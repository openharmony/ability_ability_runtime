/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sts_runtime.h"

#include <atomic>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <regex>
#include <sys/epoll.h>
#include <unistd.h>
#include <uv.h>

#include "accesstoken_kit.h"
#include "config_policy_utils.h"
#include "connect_server_manager.h"
#include "constants.h"
#include "extract_resource_manager.h"
#include "extractor.h"
#include "file_ex.h"
#include "file_mapper.h"
#include "file_path_utils.h"
#include "hdc_register.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "module_checker_delegate.h"
#include "ohos_sts_environment_impl.h"
#include "parameters.h"
#include "source_map.h"
#include "source_map_operator.h"
#include "sts_environment.h"
#include "syscap_ts.h"
#include "system_ability_definition.h"

#ifdef SUPPORT_SCREEN
#include "ace_forward_compatibility.h"
#include "declarative_module_preloader.h"
#include "hot_reloader.h"
#endif //SUPPORT_SCREEN

using namespace OHOS::AbilityBase;
using Extractor = OHOS::AbilityBase::Extractor;

namespace OHOS {
namespace AbilityRuntime {
namespace {

#ifdef APP_USE_ARM64
const std::string SANDBOX_LIB_PATH = "/system/lib64";
const std::string STS_RT_PATH = SANDBOX_LIB_PATH;
const std::string STS_SYSLIB_PATH = "/system/lib64:/system/lib64/platformsdk:/"
                                    "system/lib64/module:/system/lib64/ndk";
const std::string STS_CHIPSDK_PATH = "/system/lib64/chipset-pub-sdk";
#else
const std::string SANDBOX_LIB_PATH = "/system/lib";
const std::string STS_RT_PATH = SANDBOX_LIB_PATH;
const std::string STS_SYSLIB_PATH =
    "/system/lib:/system/lib/platformsdk:/system/lib/module:/system/lib/ndk";
const std::string STS_CHIPSDK_PATH = "/system/lib/chipset-pub-sdk";
#endif
constexpr char BUNDLE_INSTALL_PATH[] = "/data/storage/el1/bundle/";
constexpr char MERGE_ABC_PATH[] = "/ets/modules_static.abc";
constexpr char ENTRY_PATH_MAP_FILE[] = "/system/etc/entrypath.json";
constexpr char ENTRY_PATH_MAP_KEY[] = "entryPath";
constexpr char DEFAULT_ENTRY_ABILITY_CLASS[] = "entry/entryability/EntryAbility/EntryAbility";

class EntryPathManager {
public:
    static EntryPathManager &GetInstance()
    {
        static EntryPathManager instance;
        return instance;
    }

    bool Init()
    {
        std::ifstream inFile;
        inFile.open(ENTRY_PATH_MAP_FILE, std::ios::in);
        if (!inFile.is_open()) {
            TAG_LOGD(AAFwkTag::STSRUNTIME, "no entrypath file");
            return false;
        }
        nlohmann::json filePathsJson;
        inFile >> filePathsJson;
        if (filePathsJson.is_discarded()) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "json discarded error");
            inFile.close();
            return false;
        }

        if (filePathsJson.is_null() || filePathsJson.empty()) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "invalid json");
            inFile.close();
            return false;
        }

        if (!filePathsJson.contains(ENTRY_PATH_MAP_KEY)) {
            TAG_LOGD(AAFwkTag::STSRUNTIME, "no entrypath key");
            return false;
        }
        const auto &entryPathMap = filePathsJson[ENTRY_PATH_MAP_KEY];
        if (!entryPathMap.is_object()) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "entrypath is not object");
            return false;
        }

        for (const auto &entryPath: entryPathMap.items()) {
            std::string key = entryPath.key();
            if (!entryPath.value().is_string()) {
                TAG_LOGE(AAFwkTag::STSRUNTIME, "val is not string, key: %{public}s", key.c_str());
                continue;
            }
            std::string val = entryPath.value();
            TAG_LOGD(AAFwkTag::STSRUNTIME, "key: %{public}s, value: %{public}s", key.c_str(), val.c_str());
            entryPathMap_.emplace(key, val);
        }
        inFile.close();
        return true;
    }

    std::string GetEntryPath(const std::string &srcEntry)
    {
        auto const &iter = entryPathMap_.find(srcEntry);
        if (iter == entryPathMap_.end()) {
            TAG_LOGD(AAFwkTag::STSRUNTIME, "not found srcEntry: %{public}s", srcEntry.c_str());
            return DEFAULT_ENTRY_ABILITY_CLASS;
        }
        TAG_LOGD(AAFwkTag::STSRUNTIME, "found srcEntry: %{public}s, output: %{public}s",
                 srcEntry.c_str(), iter->second.c_str());
        return iter->second;
    }

private:
    EntryPathManager() = default;

    ~EntryPathManager() = default;

    std::map<std::string, std::string> entryPathMap_{};
};
} // namespace

AppLibPathVec STSRuntime::appLibPaths_;

std::unique_ptr<STSRuntime> STSRuntime::Create(const Options& options)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    std::unique_ptr<STSRuntime> instance;
    // TODO is not need?
    // JsRuntimeLite::InitJsRuntimeLite(options);
    if (!options.preload && options.isStageModel) {
        auto preloadedInstance = Runtime::GetPreloaded();
#ifdef SUPPORT_SCREEN
        // reload ace if compatible mode changes
        if (Ace::AceForwardCompatibility::PipelineChanged() && preloadedInstance) {
            preloadedInstance.reset();
        }
#endif
        if (preloadedInstance && preloadedInstance->GetLanguage() == Runtime::Language::STS) {
            instance.reset(static_cast<STSRuntime*>(preloadedInstance.release()));
        } else {
            instance = std::make_unique<STSRuntime>();
        }
    } else {
        instance = std::make_unique<STSRuntime>();
    }

    if (!instance->Initialize(options)) {
        return std::unique_ptr<STSRuntime>();
    }
    EntryPathManager::GetInstance().Init();

    return instance;
}

void STSRuntime::SetAppLibPath(const AppLibPathMap& appLibPaths)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    std::string appPath = "";
    for (const auto& kv : appLibPaths) {
        for (const auto& libPath : kv.second) {
            TAG_LOGD(AAFwkTag::STSRUNTIME, "SetSTSAppLibPath: %{public}s.", libPath.c_str());
            STSRuntime::appLibPaths_.emplace_back(libPath);
            appPath += appPath.empty() ? libPath : ":" + libPath;
        }
    }

    StsEnv::STSEnvironment::InitSTSChipSDKNS(STS_CHIPSDK_PATH);
    StsEnv::STSEnvironment::InitSTSAppNS(appPath);
    StsEnv::STSEnvironment::InitSTSSDKNS(STS_RT_PATH);
    StsEnv::STSEnvironment::InitSTSSysNS(STS_SYSLIB_PATH);

    // TODO uncompleted
    // auto moduleManager = NativeModuleManager::GetInstance();
    // if (moduleManager == nullptr) {
    //     TAG_LOGE(AAFwkTag::STSRUNTIME, "null moduleManager");
    //     return;
    // }

    // for (const auto &appLibPath : appLibPaths) {
    //     moduleManager->SetAppLibPath(appLibPath.first, appLibPath.second, isSystemApp);
    // }
}

bool STSRuntime::Initialize(const Options& options)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (options.lang != GetLanguage()) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "language mismatch");
        return false;
    }

#ifdef SUPPORT_SCREEN
    if (Ace::AceForwardCompatibility::PipelineChanged()) {
        preloaded_ = false;
    }
#endif

    if (!preloaded_) {
        if (!CreateStsEnv(options)) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "Create stsEnv failed");
            return false;
        }
    }

    apiTargetVersion_ = options.apiTargetVersion;
    TAG_LOGD(AAFwkTag::STSRUNTIME, "Initialize: %{public}d", apiTargetVersion_);
    if (options.isStageModel || options.isTestFramework) {
        auto vm = stsEnv_->GetEtsVM();
        auto env = stsEnv_->GetEtsEnv();
        if (vm == nullptr || env == nullptr) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "vm or env nullptr");
            return false;
        }

        if (preloaded_) {
            PostPreload(options);
        }

        // HandleScope handleScope(*this);
        // napi_value globalObj = nullptr;
        // napi_get_global(env, &globalObj);
        // CHECK_POINTER_AND_RETURN(globalObj, false);

        if (!preloaded_) {
            // TODO uncompleted
            // InitSyscapModule(env);
            // // Simple hook function 'isSystemplugin'
            // const char* moduleName = "JsRuntime";
            // BindNativeFunction(env, globalObj, "isSystemplugin", moduleName,
            //     [](napi_env env, napi_callback_info cbinfo) -> napi_value { return CreateJsUndefined(env); });

            // TODO uncompleted
            // napi_value propertyValue = nullptr;
            // napi_get_named_property(env, globalObj, "requireNapi", &propertyValue);
            // napi_ref tmpRef = nullptr;
            // napi_create_reference(env, propertyValue, 1, &tmpRef);
            // methodRequireNapiRef_.reset(reinterpret_cast<NativeReference*>(tmpRef));
            // if (!methodRequireNapiRef_) {
            //     TAG_LOGE(AAFwkTag::JSRUNTIME, "null methodRequireNapiRef_");
            //     return false;
            // }
            TAG_LOGD(AAFwkTag::STSRUNTIME, "PreloadAce start");
            PreloadAce(options);
            TAG_LOGD(AAFwkTag::STSRUNTIME, "PreloadAce end");
            // nativeEngine->RegisterPermissionCheck(PermissionCheckFunc);
        }

        if (!options.preload) {
            isBundle_ = options.isBundle;
            bundleName_ = options.bundleName;
            codePath_ = options.codePath;
            ReInitStsEnvImpl(options);
            LoadAotFile(options);
            pkgContextInfoJsonStringMap_ = options.pkgContextInfoJsonStringMap;
            packageNameList_ = options.packageNameList;
        }
    }

    if (!preloaded_) {
        InitConsoleModule();
    }

    if (!options.preload) {
        if (options.isUnique) {
            TAG_LOGD(AAFwkTag::STSRUNTIME, "Not supported TimerModule when form render");
        } else {
            InitTimerModule();
        }

        // TODO uncompleted
        // InitWorkerModule(options);
        // TODO uncompleted
        SetModuleLoadChecker(options.moduleCheckerDelegate);
        if (!stsEnv_->InitLoop(options.isStageModel)) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "Init loop failed");
            return false;
        }
    }
    return true;
}

bool STSRuntime::LoadSTSAppLibrary(const AppLibPathVec& appLibPaths)
{
    if (stsEnv_ == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "null stsEnv_");
         return false;
    }
    // TODO uncompleted
    // void* handle = nullptr;
    // // According to the OHOS rule, the format of the SO name is as follows
    // auto targetSoName = "lib" + packageName_ + ".so";

    // for (const auto& libPath : appLibPaths) {
    //     for (auto& itor : std::filesystem::directory_iterator(libPath)) {
    //         // According to the convention, the names of cj generated products must contain the following keywords
    //         if (itor.path().string().find(targetSoName) == std::string::npos) {
    //             continue;
    //         }
    //         handle = env->loadSTSLibrary(itor.path().c_str());
    //         if (handle == nullptr) {
    //             char* errMsg = dlerror();
    //             TAG_LOGE(AAFwkTag::STSRUNTIME,
    //                 "load %{public}s failed, reason: %{public}s", itor.path().c_str(), errMsg ? errMsg : "null");
    //             return false;
    //         }
    //     }
    // }
    appLibLoaded_ = true;
    return true;
}

void STSRuntime::StartDebugMode(const DebugOption dOption)
{
    // if (debugModel_) {
    //     TAG_LOGI(AAFwkTag::CJRUNTIME, "already debug mode");
    //     return;
    // }

    // bool isStartWithDebug = dOption.isStartWithDebug;
    // bool isDebugApp = dOption.isDebugApp;
    // const std::string bundleName = bundleName_;
    // std::string inputProcessName = bundleName_ != dOption.processName ? dOption.processName : "";

    // TAG_LOGI(AAFwkTag::CJRUNTIME, "StartDebugMode %{public}s", bundleName_.c_str());

    // HdcRegister::Get().StartHdcRegister(bundleName_, inputProcessName, isDebugApp,
    //     [bundleName, isStartWithDebug, isDebugApp](int socketFd, std::string option) {
    //         TAG_LOGI(AAFwkTag::CJRUNTIME, "hdcRegister callback call, socket fd: %{public}d, option: %{public}s.",
    //             socketFd, option.c_str());
    //         if (option.find(DEBUGGER) == std::string::npos) {
    //             if (!isDebugApp) {
    //                 ConnectServerManager::Get().StopConnectServer(false);
    //             }
    //             ConnectServerManager::Get().SendDebuggerInfo(isStartWithDebug, isDebugApp);
    //             ConnectServerManager::Get().StartConnectServer(bundleName, socketFd, false);
    //         } else {
    //             TAG_LOGE(AAFwkTag::CJRUNTIME, "debugger service unexpected option: %{public}s", option.c_str());
    //         }
    //     });
    // if (isDebugApp) {
    //     ConnectServerManager::Get().StartConnectServer(bundleName_, -1, true);
    // }
    // ConnectServerManager::Get().AddInstance(instanceId_, instanceId_);

    // debugModel_ = StartDebugger();
}

bool STSRuntime::StartDebugger()
{
    if (stsEnv_ == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "null stsEnv_");
        return false;
    }
    return stsEnv_->StartDebugger();
}

void STSRuntime::UnLoadSTSAppLibrary()
{
    TAG_LOGI(AAFwkTag::STSRUNTIME, "UnLoadSTSAppLibrary not support yet");
}

void STSRuntime::RegisterUncaughtExceptionHandler(void* uncaughtExceptionInfo)
{
    //     auto cjEnv = OHOS::CJEnv::LoadInstance();
    //     if (cjEnv == nullptr) {
    //         TAG_LOGE(AAFwkTag::CJRUNTIME, "null cjEnv");
    //         return;
    //     }
    //     cjEnv->registerCJUncaughtExceptionHandler(uncaughtExceptionInfo);
}

STSRuntime::~STSRuntime()
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    Deinitialize();
}

void STSRuntime::PostTask(const std::function<void()>& task, const std::string& name, int64_t delayTime)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (stsEnv_ != nullptr) {
        stsEnv_->PostTask(task, name, delayTime);
    }
}

void STSRuntime::PostSyncTask(const std::function<void()>& task, const std::string& name)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (stsEnv_ != nullptr) {
        stsEnv_->PostSyncTask(task, name);
    }
}

void STSRuntime::RemoveTask(const std::string& name)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (stsEnv_ != nullptr) {
        stsEnv_->RemoveTask(name);
    }
}

void STSRuntime::Deinitialize()
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    for (auto it = modules_.begin(); it != modules_.end(); it = modules_.erase(it)) {
        delete it->second;
        it->second = nullptr;
    }
    // methodRequireNapiRef_.reset();
    if (stsEnv_ != nullptr) {
        stsEnv_->DeInitLoop();
    }
}

bool STSRuntime::CreateStsEnv(const Options& options)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    stsEnv_ = std::make_shared<StsEnv::STSEnvironment>(std::make_unique<OHOSStsEnvironmentImpl>(options.eventRunner));
    if (stsEnv_ == nullptr || !stsEnv_->StartRuntime()) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Init StsEnv failed");
        return false;
    }

    // TODO uncompleted
    // if (!LoadSTSAppLibrary(STSRuntime::appLibPaths_)) {
    //     TAG_LOGE(AAFwkTag::STSRUNTIME, "load app library fail");
    //     return false;
    // }
    return true;
}

void STSRuntime::PreloadAce(const Options& options)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    // TODO uncompleted
    // auto nativeEngine = GetNativeEnginePointer();
    // CHECK_POINTER(nativeEngine);
#ifdef SUPPORT_SCREEN
    if (options.loadAce) {
        // ArkTsCard start
        if (options.isUnique) {
            // OHOS::Ace::DeclarativeModulePreloader::PreloadCard(
            //     *nativeEngine, options.bundleName, options.pkgContextInfoJsonStringMap);
        } else {
            // OHOS::Ace::DeclarativeModulePreloader::Preload(*nativeEngine);
        }
        // ArkTsCard end
    }
#endif
}

void STSRuntime::ReInitStsEnvImpl(const Options& options)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (stsEnv_ == nullptr) {
        return;
    }
    stsEnv_->ReInitStsEnvImpl(std::make_unique<OHOSStsEnvironmentImpl>(options.eventRunner));
}

void STSRuntime::LoadAotFile(const Options& options)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    auto vm = stsEnv_->GetEtsVM();
    if (vm == nullptr) {
        return;
    }

    if (options.hapPath.empty()) {
        return;
    }
    bool newCreate = false;
    std::string loadPath = ExtractorUtil::GetLoadFilePath(options.hapPath);
    std::shared_ptr<Extractor> extractor = ExtractorUtil::GetExtractor(loadPath, newCreate, true);
    if (extractor != nullptr && newCreate) {
        // TODO uncompleted
        // panda::JSNApi::LoadAotFile(vm, options.moduleName);
    }
}

void STSRuntime::InitConsoleModule()
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    // TODO uncompleted
    // if (stsEnv_ == nullptr) {
    //     return;
    // }
    // stsEnv_->InitConsoleModule();
}

void STSRuntime::InitTimerModule()
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    // TODO uncompleted, have requirement support
    // if (stsEnv_ == nullptr) {
    //     return;
    // }
    // stsEnv_->InitTimerModule();
}

void STSRuntime::ReInitUVLoop()
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (stsEnv_ == nullptr) {
        return;
    }
    stsEnv_->ReInitUVLoop();
}

void STSRuntime::PostPreload(const Options& options)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    // TODO uncompleted
    // auto vm = GetEcmaVm();
    // CHECK_POINTER(vm);
    // auto env = GetNapiEnv();
    // CHECK_POINTER(env);
    // panda::RuntimeOption postOption;
    // postOption.SetBundleName(options.bundleName);
    // if (!options.arkNativeFilePath.empty()) {
    //     std::string sandBoxAnFilePath = SANDBOX_ARK_CACHE_PATH + options.arkNativeFilePath;
    //     postOption.SetAnDir(sandBoxAnFilePath);
    // }
    // if (options.isMultiThread) {
    //     TAG_LOGD(AAFwkTag::JSRUNTIME, "Multi-Thread Mode: %{public}d", options.isMultiThread);
           // TODO not supported
    //     panda::JSNApi::SetMultiThreadCheck();
    // }
    // if (options.isErrorInfoEnhance) {
    //     TAG_LOGD(AAFwkTag::JSRUNTIME, "Start Error-Info-Enhance Mode: %{public}d.", options.isErrorInfoEnhance);
    //     panda::JSNApi::SetErrorInfoEnhance();
    // }
    // bool profileEnabled = OHOS::system::GetBoolParameter("ark.profile", false);
    // postOption.SetEnableProfile(profileEnabled);
    // TAG_LOGD(AAFwkTag::JSRUNTIME, "ASMM JIT Verify PostFork, jitEnabled: %{public}d", options.jitEnabled);
    // postOption.SetEnableJIT(options.jitEnabled);
    // postOption.SetAOTCompileStatusMap(options.aotCompileStatusMap);
    // {
    //     HITRACE_METER_NAME(HITRACE_TAG_APP, "panda::JSNApi::PostFork");
    //     panda::JSNApi::PostFork(vm, postOption);
    // }
    // reinterpret_cast<NativeEngine*>(env)->ReinitUVLoop();
    ReInitUVLoop();
    // uv_loop_s* loop = nullptr;
    // napi_get_uv_event_loop(env, &loop);
    // panda::JSNApi::SetLoop(vm, loop);
}

ani_env* STSRuntime::GetAniEnv()
{
    if (stsEnv_ == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "null stsEnv_");
        return nullptr;
    }
    return stsEnv_->GetAniEnv();
}

std::unique_ptr<STSNativeReference> STSRuntime::LoadModule(const std::string& moduleName,
    const std::string& modulePath, const std::string& hapPath, bool esmodule, bool useCommonChunk,
    const std::string& srcEntrance)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "Load module(%{public}s, %{private}s, %{private}s, %{public}s)",
        moduleName.c_str(), modulePath.c_str(), hapPath.c_str(), esmodule ? "true" : "false");
    auto vm = stsEnv_->GetEtsVM();
    //CHECK_POINTER_AND_RETURN(vm, std::unique_ptr<STSNativeReference>());
    // // use for debugger, js engine need to know load module to handle debug event
    // panda::JSNApi::NotifyLoadModule(vm);

    //env 2.0??
    //  auto env = GetNapiEnv();

    // CHECK_POINTER_AND_RETURN(env, std::unique_ptr<NativeReference>());
    // isOhmUrl_ = panda::JSNApi::IsOhmUrl(srcEntrance);

   // HandleScope handleScope(*this);

    std::string path = moduleName;
    auto pos = path.find("::");
    if (pos != std::string::npos) {
        path.erase(pos, path.size() - pos);
        moduleName_ = path;
    }
    TAG_LOGD(AAFwkTag::STSRUNTIME, "wangbing moduleName_(%{public}s, path %{private}s",
        moduleName_.c_str(),path.c_str());

    std::string fileName;
    if (!hapPath.empty()) {
        fileName.append(codePath_).append(Constants::FILE_SEPARATOR).append(modulePath);
        std::regex pattern(std::string(Constants::FILE_DOT) + std::string(Constants::FILE_SEPARATOR));
        fileName = std::regex_replace(fileName, pattern, "");
    } else {
        if (!MakeFilePath(codePath_, modulePath, fileName)) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "make module file path: %{private}s failed", modulePath.c_str());
            return nullptr;
        }
    }
    std::unique_ptr<STSNativeReference> stsNativeReference = LoadStsModule(moduleName, fileName, hapPath, srcEntrance);
    return stsNativeReference;
}

std::unique_ptr<STSNativeReference> STSRuntime::LoadStsModule(const std::string& moduleName, const std::string& path, const std::string& hapPath,
    const std::string& srcEntrance)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "Load sts module(%{public}s, %{private}s, %{private}s, %{public}s)",
        moduleName.c_str(), path.c_str(), hapPath.c_str(), srcEntrance.c_str());
    auto stsNativeReference = std::make_unique<STSNativeReference>();
    ani_env* aniEnv = GetAniEnv();
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "GetAniEnv failed");
        return std::make_unique<STSNativeReference>();
    }
    // TODO 未完成
    // if (!RunScript(aniEnv, moduleName, path, hapPath, srcEntrance)) {
    //     return std::make_unique<STSNativeReference>();
    // }

    ani_class stringCls = nullptr;
    if (aniEnv->FindClass("Lstd/core/String;", &stringCls) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "FindClass Lstd/core/String Failed");
        return std::make_unique<STSNativeReference>();
    }

    std::string modulePath = BUNDLE_INSTALL_PATH + moduleName_ + MERGE_ABC_PATH;
    ani_string ani_str;
    if (aniEnv->String_NewUTF8(modulePath.c_str(), modulePath.size(), &ani_str) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "String_NewUTF8 modulePath Failed");
        return std::make_unique<STSNativeReference>();
    }

    ani_ref undefined_ref;
    if (aniEnv->GetUndefined(&undefined_ref) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "GetUndefined failed");
        return std::make_unique<STSNativeReference>();
    }
    ani_array_ref refArray;
    if (aniEnv->Array_New_Ref(stringCls, 1, undefined_ref, &refArray) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Array_New_Ref Failed");
        return std::make_unique<STSNativeReference>();
    }
    if (aniEnv->Array_Set_Ref(refArray, 0, ani_str) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Array_Set_Ref Failed");
        return std::make_unique<STSNativeReference>();
    }

    ani_class cls = nullptr;
    if (aniEnv->FindClass("Lstd/core/AbcRuntimeLinker;", &cls) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "FindClass AbcRuntimeLinker failed");
        return std::make_unique<STSNativeReference>();
    }
    ani_method method = nullptr;
    if (aniEnv->Class_FindMethod(cls, "<ctor>", "Lstd/core/RuntimeLinker;[Lstd/core/String;:V", &method) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Class_FindMethod ctor failed");
        return std::make_unique<STSNativeReference>();
    }
    ani_object object = nullptr;
    if (aniEnv->Object_New(cls, method, &object, undefined_ref, refArray) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Object_New AbcRuntimeLinker failed");
        return std::make_unique<STSNativeReference>();
    }
    ani_method loadClassMethod = nullptr;
    if (aniEnv->Class_FindMethod(cls, "loadClass", nullptr, &loadClassMethod) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Class_FindMethod loadClass failed");
        return std::make_unique<STSNativeReference>();
    }
    std::string entryPath = EntryPathManager::GetInstance().GetEntryPath(srcEntrance);
    // std::string entryPath = "entry/entryability/EntryAbility/EntryAbility";
    // std::string entryPath = "OpenHarmonyTestRunner/OpenHarmonyTestRunner";
    ani_string entryClassStr;
    aniEnv->String_NewUTF8(entryPath.c_str(), entryPath.length(), &entryClassStr);
    ani_class entryClass = nullptr;
    ani_ref entryClassRef = nullptr;
    ani_boolean isInit = false;
    TAG_LOGI(AAFwkTag::STSRUNTIME, "load class: %{public}s", entryPath.c_str());
    if (aniEnv->Object_CallMethod_Ref(object, loadClassMethod, &entryClassRef, entryClassStr, isInit) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Object_CallMethod_Ref loadClassMethod failed");
        return std::make_unique<STSNativeReference>();
    } else {
        entryClass = static_cast<ani_class>(entryClassRef);
    }

    ani_method entryMethod = nullptr;
    if (aniEnv->Class_FindMethod(entryClass, "<ctor>", ":V", &entryMethod) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Class_FindMethod ctor failed");
        return std::make_unique<STSNativeReference>();
    }

    ani_object entryObject = nullptr;
    if (aniEnv->Object_New(entryClass, entryMethod, &entryObject) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Object_New AbcRuntimeLinker failed");
        return std::make_unique<STSNativeReference>();
    }

    ani_ref entryObjectRef = nullptr;
    if (aniEnv->GlobalReference_Create(entryObject, &entryObjectRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "GlobalReference_Create failed");
        return std::make_unique<STSNativeReference>();
    }
    stsNativeReference->aniCls = entryClass;
    stsNativeReference->aniObj = entryObject;
    stsNativeReference->aniRef = entryObjectRef;
    return stsNativeReference;
}

bool STSRuntime::RunScript(ani_env* aniEnv, const std::string& moduleName, const std::string& abcPath, const std::string& hapPath,
    const std::string& srcEntrance)
{
    bool newCreate = false;
    std::string loadPath = ExtractorUtil::GetLoadFilePath(hapPath);
    TAG_LOGE(AAFwkTag::STSRUNTIME, "hapPath[%{public}s], loadPath:%{public}s", hapPath.c_str(), loadPath.c_str());
//     std::shared_ptr<Extractor> extractor = ExtractorUtil::GetExtractor(loadPath, newCreate, true);
//     if (!extractor) {
//         TAG_LOGE(AAFwkTag::STSRUNTIME, "hapPath[%{private}s]", hapPath.c_str());
//         return false;
//     }
//     if (newCreate) {
//         // panda::JSNApi::LoadAotFile(vm, moduleName_);
//         // auto resourceManager = AbilityBase::ExtractResourceManager::GetExtractResourceManager().GetGlobalObject();
//         // if (resourceManager) {
//         //     resourceManager->AddResource(loadPath.c_str());
//         // }
//     }
//     auto func = [&](std::string modulePath, const std::string abcPath) {
//      //  bool useSafeMempry = apiTargetVersion_ == 0 || apiTargetVersion_ > API8;
//         if (!extractor->IsHapCompress(modulePath)) { //&& useSafeMempry) {
//             auto safeData = extractor->GetSafeData(modulePath);
//             if (!safeData) {
//                 TAG_LOGE(AAFwkTag::STSRUNTIME, "null safeData");
//              //   return false;
//             }
//          //   LoadScript(abcPath, safeData->GetDataPtr(), safeData->GetDataLen(), isBundle_, srcEntrance);
//         } else {
//             std::unique_ptr<uint8_t[]> data;
//             size_t dataLen = 0;
//             if (!extractor->ExtractToBufByName(modulePath, data, dataLen)) {
//                 TAG_LOGE(AAFwkTag::STSRUNTIME, "get abc file failed");
//               //  return false;
//             }
//             std::vector<uint8_t> buffer;
//             buffer.assign(data.get(), data.get() + dataLen);

//          //   LoadScript(abcPath, &buffer, isBundle_);
//         }
//     };

//     std::string path = abcPath;
//     if (!isBundle_) {
//         TAG_LOGE(AAFwkTag::JSRUNTIME, "wangbing isBundle_");
//         if (moduleName_.empty()) {
//             TAG_LOGE(AAFwkTag::JSRUNTIME, "moduleName empty");
//             return false;
//         }
//         path = BUNDLE_INSTALL_PATH + moduleName_ + MERGE_ABC_PATH;
//       //  panda::JSNApi::SetAssetPath(vm, path);
//        // panda::JSNApi::SetModuleName(vm, moduleName_);
//     }

//    // func(path, abcPath);
    return true;
}

// bool STSRuntime::LoadScript(const std::string& path, std::vector<uint8_t>* buffer, bool isBundle)
// {
//     TAG_LOGD(AAFwkTag::STSRUNTIME, "path: %{private}s", path.c_str());
//     //CHECK_POINTER_AND_RETURN(jsEnv_, false);
//     return stsEnv_->LoadScript(path, buffer, isBundle);
// }

// bool STSRuntime::LoadScript(const std::string& path, uint8_t* buffer, size_t len, bool isBundle,
//     const std::string& srcEntrance)
// {
//     TAG_LOGD(AAFwkTag::STSRUNTIME, "path: %{private}s", path.c_str());
//    // CHECK_POINTER_AND_RETURN(jsEnv_, false);
//     // if (isOhmUrl_ && !moduleName_.empty()) {
//     //     auto vm = GetEcmaVm();
//     //  //   CHECK_POINTER_AND_RETURN(vm, false);
//     //     std::string srcFilename = "";
//     //     srcFilename = BUNDLE_INSTALL_PATH + moduleName_ + MERGE_ABC_PATH;
//     //     return panda::JSNApi::ExecuteSecureWithOhmUrl(vm, buffer, len, srcFilename, srcEntrance);
//     // }
//     return stsEnv_->LoadScript(path, buffer, len, isBundle);
// }
} // namespace AbilityRuntime
} // namespace OHOS