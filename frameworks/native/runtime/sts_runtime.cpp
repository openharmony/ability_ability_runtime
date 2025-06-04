/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "bundle_constants.h"
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
#include "js_runtime.h"
#include "js_utils.h"
#include "module_checker_delegate.h"
#include "ohos_sts_environment_impl.h"
#include "parameters.h"
#include "source_map.h"
#include "source_map_operator.h"
#include "static_core/runtime/tooling/inspector/debugger_arkapi.h"
#include "sts_environment.h"
#include "syscap_ts.h"
#include "system_ability_definition.h"
#include "ets_ani_expo.h"

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
constexpr char SANDBOX_ARK_CACHE_PATH[] = "/data/storage/ark-cache/";
constexpr char MERGE_ABC_PATH[] = "/ets/modules_static.abc";
constexpr char ENTRY_PATH_MAP_FILE[] = "/system/framework/entrypath.json";
constexpr char ENTRY_PATH_MAP_KEY[] = "entryPath";
constexpr char DEFAULT_ENTRY_ABILITY_CLASS[] = "entry/src/main/ets/entryability/EntryAbility/EntryAbility";
constexpr const char* STRING_CLASS_NAME = "Lstd/core/String;";
constexpr const char* ABC_RUNTIME_LINKER_CLASS_NAME = "Lstd/core/AbcRuntimeLinker;";
const int NUMBER_ZERO = 0;
const int NUMBER_TWO = 2;

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
            if (StartsWithDotSlash(srcEntry)) {
                TAG_LOGD(AAFwkTag::STSRUNTIME, "not found srcEntry: %{public}s", srcEntry.c_str());
                return DEFAULT_ENTRY_ABILITY_CLASS;
            }
            TAG_LOGD(AAFwkTag::STSRUNTIME, "srcEntry as class: %{public}s", srcEntry.c_str());
            return HandleOhmUrlSrcEntry(srcEntry);
        }
        TAG_LOGD(AAFwkTag::STSRUNTIME, "found srcEntry: %{public}s, output: %{public}s",
                 srcEntry.c_str(), iter->second.c_str());
        return iter->second;
    }

private:
    EntryPathManager() = default;

    ~EntryPathManager() = default;

    static bool StartsWithDotSlash(const std::string &str)
    {
        if (str.length() < NUMBER_TWO) {
            return false;
        }
        std::string prefix = str.substr(NUMBER_ZERO, NUMBER_TWO);
        return prefix == "./";
    }

    static std::string HandleOhmUrlSrcEntry(const std::string &srcEntry)
    {
        size_t lastSlashPos = srcEntry.rfind('/');
        if (lastSlashPos == std::string::npos) {
            std::string fileName = srcEntry;
            // If there is no slash, the entire string is processed directly.
            HandleOhmUrlFileName(fileName);
            return fileName;
        }
        std::string base = srcEntry.substr(0, lastSlashPos + 1);
        std::string fileName = srcEntry.substr(lastSlashPos + 1);
        HandleOhmUrlFileName(fileName);
        return base + fileName;
    }

    static void HandleOhmUrlFileName(std::string &fileName)
    {
        size_t colonPos = fileName.rfind(':');
        if (colonPos != std::string::npos) {
            // <fileName>:<className>  =>  <fileName>/<className>
            fileName.replace(colonPos, 1, "/");
        } else {
            // <fileName>  =>  <fileName>/<fileName>
            fileName = fileName + "/" + fileName;
        }
    }

    std::map<std::string, std::string> entryPathMap_{};
};
} // namespace

AppLibPathVec STSRuntime::appLibPaths_;

std::unique_ptr<STSRuntime> STSRuntime::PreFork(const Options& options)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "PreFork begin");
    std::unique_ptr<STSRuntime> instance = std::make_unique<STSRuntime>();
    if (!instance->Initialize(options)) {
        return std::unique_ptr<STSRuntime>();
    }
    EntryPathManager::GetInstance().Init();
    return instance;
}

void STSRuntime::PostFork(const Options &options, std::vector<ani_option>& aniOptions, JsRuntime* jsRuntime)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "PostFork begin");
    isBundle_ = options.isBundle;
    bundleName_ = options.bundleName;
    codePath_ = options.codePath;
    ReInitStsEnvImpl(options);
    pkgContextInfoJsonStringMap_ = options.pkgContextInfoJsonStringMap;
    packageNameList_ = options.packageNameList;
    ReInitUVLoop();

    // interop
    const std::string optionPrefix = "--ext:";
    std::string interop = optionPrefix + "interop";
    ani_option interopOption = {interop.data(), (void*)jsRuntime->GetNapiEnv()};
    aniOptions.push_back(interopOption);

    // aot
    std::string aotFileString = "";
    if (!options.arkNativeFilePath.empty()) {
        std::string aotFilePath = SANDBOX_ARK_CACHE_PATH + options.arkNativeFilePath + options.moduleName + ".an";
        aotFileString = "--ext:--aot-file=" + aotFilePath;
        aniOptions.push_back(ani_option{aotFileString.c_str(), nullptr});
        TAG_LOGI(AAFwkTag::STSRUNTIME, "aotFileString: %{public}s", aotFileString.c_str());
        aniOptions.push_back(ani_option{"--ext:--enable-an", nullptr});
    }

    ani_env* aniEnv = GetAniEnv();
    ark::ets::ETSAni::Postfork(aniEnv, aniOptions);
}

std::unique_ptr<STSRuntime> STSRuntime::Create(const Options& options, JsRuntime* jsRuntime)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "create ets runtime");
    std::unique_ptr<STSRuntime> instance;
    auto preloadedInstance = Runtime::GetPreloaded(options.lang);
#ifdef SUPPORT_SCREEN
    // reload ace if compatible mode changes
    if (Ace::AceForwardCompatibility::PipelineChanged() && preloadedInstance) {
        preloadedInstance.reset();
    }
#endif
    if (preloadedInstance && preloadedInstance->GetLanguage() == Runtime::Language::STS) {
        instance.reset(static_cast<STSRuntime*>(preloadedInstance.release()));
    } else {
        instance = PreFork(options);
    }

    std::vector<ani_option> aniOptions;
    instance->PostFork(options, aniOptions, jsRuntime);
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
}

bool STSRuntime::Initialize(const Options& options)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (options.lang != GetLanguage()) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "language mismatch");
        return false;
    }

    if (!CreateStsEnv(options)) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Create stsEnv failed");
        return false;
    }

    apiTargetVersion_ = options.apiTargetVersion;
    TAG_LOGD(AAFwkTag::STSRUNTIME, "Initialize: %{public}d", apiTargetVersion_);

    if (!stsEnv_->InitLoop(options.isStageModel)) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Init loop failed");
        return false;
    }

    return true;
}

bool STSRuntime::LoadSTSAppLibrary(const AppLibPathVec& appLibPaths)
{
    if (stsEnv_ == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "null stsEnv_");
         return false;
    }

    appLibLoaded_ = true;
    return true;
}

void STSRuntime::StartDebugMode(const DebugOption dOption)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::STSRUNTIME, "localDebug %{public}d", dOption.isDebugFromLocal);
    if (!dOption.isDebugFromLocal && !dOption.isDeveloperMode) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "developer Mode false");
        return;
    }
    // Set instance id to tid after the first instance.
    instanceId_ = static_cast<uint32_t>(getproctid());

    bool isStartWithDebug = dOption.isStartWithDebug;
    bool isDebugApp = dOption.isDebugApp;
    std::string appProvisionType = dOption.appProvisionType;
    TAG_LOGD(AAFwkTag::STSRUNTIME, "Ark VM is starting debug mode [%{public}s]", isStartWithDebug ? "break" : "normal");
    const std::string bundleName = bundleName_;
    uint32_t instanceId = instanceId_;
    std::string inputProcessName = bundleName_ != dOption.processName ? dOption.processName : "";
    HdcRegister::DebugRegisterMode debugMode = HdcRegister::DebugRegisterMode::HDC_DEBUG_REG;
    auto weak = stsEnv_;
    HdcRegister::Get().StartHdcRegister(bundleName_, inputProcessName, isDebugApp, debugMode,
        [bundleName, isStartWithDebug, instanceId, weak, isDebugApp, appProvisionType]
        (int socketFd, std::string option) {
        TAG_LOGI(AAFwkTag::STSRUNTIME, "HdcRegister msg, fd= %{public}d, option= %{public}s", socketFd, option.c_str());
        // system is debuggable when const.secure is false and const.debuggable is true
        bool isSystemDebuggable = system::GetBoolParameter("const.secure", true) == false &&
            system::GetBoolParameter("const.debuggable", false) == true;
        // Don't start any server if (system not in debuggable mode) and app is release version
        // Starting ConnectServer in release app on debuggable system is only for debug mode, not for profiling mode.
        if ((!isSystemDebuggable) && appProvisionType == AppExecFwk::Constants::APP_PROVISION_TYPE_RELEASE) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "not support release app");
            return;
        }
        if (option.find(DEBUGGER) == std::string::npos) {
            // if has old connect server, stop it
            ConnectServerManager::Get().SendInstanceMessageAll(nullptr);
            ConnectServerManager::Get().StartConnectServer(bundleName, socketFd, false);
        } else {
            if (appProvisionType == AppExecFwk::Constants::APP_PROVISION_TYPE_RELEASE) {
                TAG_LOGE(AAFwkTag::STSRUNTIME, "not support release app");
                return;
            }
            if (weak == nullptr) {
                TAG_LOGE(AAFwkTag::STSRUNTIME, "null weak");
                return;
            }
            int32_t identifierId = weak->ParseHdcRegisterOption(option);
            if (identifierId == -1) {
                TAG_LOGE(AAFwkTag::JSENV, "Abnormal parsing of tid results");
                return;
            }
            weak->debugMode_ = ark::ArkDebugNativeAPI::StartDebuggerForSocketPair(identifierId, socketFd);
        }
    });
    DebuggerConnectionHandler(isDebugApp, isStartWithDebug);
}

void STSRuntime::DebuggerConnectionHandler(bool isDebugApp, bool isStartWithDebug)
{
    ConnectServerManager::Get().StoreInstanceMessage(getproctid(), instanceId_, "Debugger");
    if (stsEnv_ == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "null stsEnv");
        return;
    }
    ark::ArkDebugNativeAPI::NotifyDebugMode(getproctid(), instanceId_, isStartWithDebug);
}

void STSRuntime::UnLoadSTSAppLibrary()
{
    TAG_LOGI(AAFwkTag::STSRUNTIME, "UnLoadSTSAppLibrary not support yet");
}

void STSRuntime::RegisterUncaughtExceptionHandler(void* uncaughtExceptionInfo)
{
    if (stsEnv_ == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "null stsEnv_");
        return;
    }

    if (uncaughtExceptionInfo == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "null uncaughtExceptionInfo");
        return;
    }

    auto handle = static_cast<StsEnv::STSUncaughtExceptionInfo*>(uncaughtExceptionInfo);
    if (handle != nullptr) {
        stsEnv_->RegisterUncaughtExceptionHandler(*handle);
    }
}

STSRuntime::~STSRuntime()
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    Deinitialize();
    StopDebugMode();
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

    if (stsEnv_ != nullptr) {
        stsEnv_->DeInitLoop();
    }
}

bool STSRuntime::CreateStsEnv(const Options& options)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    stsEnv_ = std::make_shared<StsEnv::STSEnvironment>(std::make_unique<OHOSStsEnvironmentImpl>(options.eventRunner));
    std::vector<ani_option> aniOptions;

    std::string interpreerMode = "--ext:--interpreter-type=cpp";
    std::string debugEnalbeMode = "--ext:--debugger-enable=true";
    std::string debugLibraryPathMode = "--ext:--debugger-library-path=/system/lib64/libarkinspector.so";
    std::string breadonstartMode = "--ext:--debugger-break-on-start";
    if (options.isStartWithDebug) {
        ani_option interpreterModeOption = {interpreerMode.data(), nullptr};
        aniOptions.push_back(interpreterModeOption);
        ani_option debugEnalbeModeOption = {debugEnalbeMode.data(), nullptr};
        aniOptions.push_back(debugEnalbeModeOption);
        ani_option debugLibraryPathModeOption = {debugLibraryPathMode.data(), nullptr};
        aniOptions.push_back(debugLibraryPathModeOption);
        ani_option breadonstartModeOption = {breadonstartMode.data(), nullptr};
        aniOptions.push_back(breadonstartModeOption);
    }
    
    if (stsEnv_ == nullptr || !stsEnv_->StartRuntime(aniOptions)) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Init StsEnv failed");
        return false;
    }

    return true;
}

void STSRuntime::ReInitStsEnvImpl(const Options& options)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (stsEnv_ == nullptr) {
        return;
    }
    stsEnv_->ReInitStsEnvImpl(std::make_unique<OHOSStsEnvironmentImpl>(options.eventRunner));
}

void STSRuntime::ReInitUVLoop()
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (stsEnv_ == nullptr) {
        return;
    }
    stsEnv_->ReInitUVLoop();
}

ani_env* STSRuntime::GetAniEnv()
{
    if (stsEnv_ == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "null stsEnv_");
        return nullptr;
    }
    return stsEnv_->GetAniEnv();
}

void STSRuntime::PreloadModule(const std::string& moduleName, const std::string& hapPath,
    bool isEsMode, bool useCommonTrunk)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "moduleName: %{public}s", moduleName.c_str());
    ani_env* aniEnv = GetAniEnv();
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "GetAniEnv failed");
        return;
    }
    ani_class stringCls = nullptr;
    if (aniEnv->FindClass(STRING_CLASS_NAME, &stringCls) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "FindClass Lstd/core/String Failed");
        return;
    }
    std::string modulePath = BUNDLE_INSTALL_PATH + moduleName + MERGE_ABC_PATH;
    ani_string ani_str;
    if (aniEnv->String_NewUTF8(modulePath.c_str(), modulePath.size(), &ani_str) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "String_NewUTF8 modulePath Failed");
        return;
    }
    ani_ref undefined_ref;
    if (aniEnv->GetUndefined(&undefined_ref) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "GetUndefined failed");
        return;
    }
    ani_array_ref refArray;
    if (aniEnv->Array_New_Ref(stringCls, 1, undefined_ref, &refArray) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Array_New_Ref Failed");
        return;
    }
    if (aniEnv->Array_Set_Ref(refArray, 0, ani_str) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Array_Set_Ref Failed");
        return;
    }
    ani_class cls = nullptr;
    if (aniEnv->FindClass(ABC_RUNTIME_LINKER_CLASS_NAME, &cls) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "FindClass AbcRuntimeLinker failed");
        return;
    }
    ani_method method = nullptr;
    if (aniEnv->Class_FindMethod(cls, "<ctor>", "Lstd/core/RuntimeLinker;[Lstd/core/String;:V", &method) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Class_FindMethod ctor failed");
        return;
    }
    ani_object object = nullptr;
    if (aniEnv->Object_New(cls, method, &object, undefined_ref, refArray) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Object_New AbcRuntimeLinker failed");
    }
}

std::unique_ptr<STSNativeReference> STSRuntime::LoadModule(const std::string& moduleName,
    const std::string& modulePath, const std::string& hapPath, bool esmodule, bool useCommonChunk,
    const std::string& srcEntrance)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "Load module(%{public}s, %{public}s, %{public}s, %{public}s)",
        moduleName.c_str(), modulePath.c_str(), hapPath.c_str(), esmodule ? "true" : "false");

    std::string path = moduleName;
    auto pos = path.find("::");
    if (pos != std::string::npos) {
        path.erase(pos, path.size() - pos);
        moduleName_ = path;
    }
    TAG_LOGD(AAFwkTag::STSRUNTIME, "moduleName_(%{public}s, path %{public}s",
        moduleName_.c_str(), path.c_str());

    std::string fileName;
    if (!hapPath.empty()) {
        fileName.append(codePath_).append(Constants::FILE_SEPARATOR).append(modulePath);
        std::regex pattern(std::string(Constants::FILE_DOT) + std::string(Constants::FILE_SEPARATOR));
        fileName = std::regex_replace(fileName, pattern, "");
    } else {
        if (!MakeFilePath(codePath_, modulePath, fileName)) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "make module file path: %{public}s failed", modulePath.c_str());
            return nullptr;
        }
    }
    std::unique_ptr<STSNativeReference> stsNativeReference = LoadStsModule(moduleName, fileName, hapPath, srcEntrance);
    return stsNativeReference;
}

std::unique_ptr<STSNativeReference> STSRuntime::LoadStsModule(const std::string& moduleName,
    const std::string& path, const std::string& hapPath, const std::string& srcEntrance)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "Load sts module(%{public}s, %{public}s, %{public}s, %{public}s)",
        moduleName.c_str(), path.c_str(), hapPath.c_str(), srcEntrance.c_str());
    auto stsNativeReference = std::make_unique<STSNativeReference>();
    ani_env* aniEnv = GetAniEnv();
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "GetAniEnv failed");
        return std::make_unique<STSNativeReference>();
    }

    ani_class stringCls = nullptr;
    if (aniEnv->FindClass(STRING_CLASS_NAME, &stringCls) != ANI_OK) {
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
    if (aniEnv->FindClass(ABC_RUNTIME_LINKER_CLASS_NAME, &cls) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "FindClass AbcRuntimeLinker failed");
        return std::make_unique<STSNativeReference>();
    }
    ani_method method = nullptr;
    if (aniEnv->Class_FindMethod(cls, "<ctor>", "Lstd/core/RuntimeLinker;[Lstd/core/String;:V", &method) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Class_FindMethod ctor failed");
        return std::make_unique<STSNativeReference>();
    }
    ani_object object = nullptr;
    aniEnv->ResetError();
    if (aniEnv->Object_New(cls, method, &object, undefined_ref, refArray) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Object_New AbcRuntimeLinker failed");
        HandleUncaughtError();
        return std::make_unique<STSNativeReference>();
    }
    ani_method loadClassMethod = nullptr;
    if (aniEnv->Class_FindMethod(cls, "loadClass", nullptr, &loadClassMethod) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Class_FindMethod loadClass failed");
        return std::make_unique<STSNativeReference>();
    }
    std::string entryPath = EntryPathManager::GetInstance().GetEntryPath(srcEntrance);
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

bool STSRuntime::RunScript(ani_env* aniEnv, const std::string& moduleName, const std::string& abcPath,
    const std::string& hapPath, const std::string& srcEntrance)
{
    bool newCreate = false;
    std::string loadPath = ExtractorUtil::GetLoadFilePath(hapPath);
    TAG_LOGE(AAFwkTag::STSRUNTIME, "hapPath[%{public}s], loadPath:%{public}s", hapPath.c_str(), loadPath.c_str());
    // need vm support Aot.
    return true;
}

void STSRuntime::HandleUncaughtError()
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (stsEnv_ == nullptr) {
        return;
    }
    stsEnv_->HandleUncaughtError();
}

void STSRuntime::StopDebugMode()
{
    CHECK_POINTER(stsEnv_);
    if (stsEnv_->debugMode_) {
        ConnectServerManager::Get().RemoveInstance(instanceId_);
        ark::ArkDebugNativeAPI::StopDebugger();
    }
}

void STSRuntime::FinishPreload()
{
    ani_env* env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Failed: ANI env nullptr");
        return;
    }
    ark::ets::ETSAni::Prefork(env);
}

void STSRuntime::PreloadClass(const char *className)
{
    ani_env* env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "GetAniEnv failed");
        return;
    }

    ani_class cls = nullptr;
    if (env->FindClass(className, &cls) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Find preload class failed");
        return;
    }
}
} // namespace AbilityRuntime
} // namespace OHOS