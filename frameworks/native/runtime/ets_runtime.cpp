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

#include "ets_runtime.h"

#include <cstddef>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <regex>
#include <unistd.h>

#include "constants.h"
#include "ets_interface.h"
#include "file_path_utils.h"
#include "hilog_tag_wrapper.h"
#include "hybrid_js_module_reader.h"

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
const std::string ETS_RT_PATH = SANDBOX_LIB_PATH;
const std::string ETS_SYSLIB_PATH =
    "/system/lib64:/system/lib64/platformsdk:/system/lib64/module:/system/lib64/ndk";
#else
const std::string SANDBOX_LIB_PATH = "/system/lib";
const std::string ETS_RT_PATH = SANDBOX_LIB_PATH;
const std::string ETS_SYSLIB_PATH =
    "/system/lib:/system/lib/platformsdk:/system/lib/module:/system/lib/ndk";
#endif
constexpr char BUNDLE_INSTALL_PATH[] = "/data/storage/el1/bundle/";
constexpr char SANDBOX_ARK_CACHE_PATH[] = "/data/storage/ark-cache/";
constexpr char MERGE_ABC_PATH[] = "/ets/modules_static.abc";

const char *ETS_ENV_LIBNAME = "libets_environment.z.so";
const char *ETS_ENV_REGISTER_FUNCS = "OHOS_ETS_ENV_RegisterFuncs";
ETSEnvFuncs *g_etsEnvFuncs = nullptr;

bool RegisterETSEnvFuncs()
{
    if (g_etsEnvFuncs != nullptr) {
        return true;
    }
    auto handle = dlopen(ETS_ENV_LIBNAME, RTLD_LAZY);
    if (!handle) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "dlopen failed %{public}s, %{public}s", ETS_ENV_LIBNAME, dlerror());
        return false;
    }
    auto symbol = dlsym(handle, ETS_ENV_REGISTER_FUNCS);
    if (!symbol) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "dlsym failed %{public}s, %{public}s", ETS_ENV_REGISTER_FUNCS, dlerror());
        dlclose(handle);
        return false;
    }
    auto func = reinterpret_cast<ETSEnvFuncs* (*)()>(symbol);
    g_etsEnvFuncs = func();
    return true;
}
} // namespace

std::unique_ptr<ETSRuntime> ETSRuntime::PreFork(const Options &options, std::unique_ptr<JsRuntime> &jsRuntime)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "PreFork begin");
    std::unique_ptr<ETSRuntime> instance = std::make_unique<ETSRuntime>();

    if (!instance->Initialize(options, jsRuntime)) {
        return std::unique_ptr<ETSRuntime>();
    }
    return instance;
}

void ETSRuntime::PostFork(const Options &options, std::unique_ptr<JsRuntime> &jsRuntime)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "PostFork begin");
    codePath_ = options.codePath;

    if (g_etsEnvFuncs == nullptr ||
        g_etsEnvFuncs->PostFork == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null g_etsEnvFuncs or PostFork");
        return;
    }

    if (jsRuntime != nullptr) {
        jsRuntime_ = std::move(jsRuntime);
    }
    if (jsRuntime_ != nullptr) {
        auto vm = static_cast<JsRuntime *>(jsRuntime_.get())->GetEcmaVm();
        panda::JSNApi::SetHostResolveBufferTrackerForHybridApp(
            vm, HybridJsModuleReader(options.bundleName, options.hapPath, options.isUnique));
    }

    std::string aotFilePath = "";
    if (!options.arkNativeFilePath.empty()) {
        aotFilePath = SANDBOX_ARK_CACHE_PATH + options.arkNativeFilePath + options.moduleName + ".an";
    }
    napi_env napiEnv = static_cast<AbilityRuntime::JsRuntime *>(jsRuntime_.get())->GetNapiEnv();
    g_etsEnvFuncs->PostFork(reinterpret_cast<void *>(napiEnv), aotFilePath);
}
 
std::unique_ptr<ETSRuntime> ETSRuntime::Create(const Options &options, std::unique_ptr<JsRuntime> &jsRuntime)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "Create called");
    if (!RegisterETSEnvFuncs()) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "RegisterETSEnvFuncs failed");
        return std::unique_ptr<ETSRuntime>();
    }

    if (g_etsEnvFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null g_etsEnvFuncs");
        return std::unique_ptr<ETSRuntime>();
    }

    if (jsRuntime == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null jsRuntime");
        return std::unique_ptr<ETSRuntime>();
    }
    std::unique_ptr<ETSRuntime> instance;
    auto preloadedInstance = Runtime::GetPreloaded(Language::ETS);
#ifdef SUPPORT_SCREEN
    // reload ace if compatible mode changes
    if (Ace::AceForwardCompatibility::PipelineChanged() && preloadedInstance) {
        preloadedInstance.reset();
    }
#endif
    if (preloadedInstance && preloadedInstance->GetLanguage() == Runtime::Language::ETS) {
        instance.reset(static_cast<ETSRuntime *>(preloadedInstance.release()));
    } else {
        instance = PreFork(options, jsRuntime);
    }

    if (instance != nullptr && !options.preload) {
        instance->PostFork(options, jsRuntime);
    }
    return instance;
}

void ETSRuntime::SetAppLibPath(const AppLibPathMap &appLibPaths)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "SetAppLibPath called");
    if (!RegisterETSEnvFuncs()) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "RegisterETSEnvFuncs failed");
        return;
    }

    if (g_etsEnvFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null g_etsEnvFuncs");
        return;
    }

    if (g_etsEnvFuncs->InitETSSDKNS == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null InitETSSDKNS");
        return;
    }
    g_etsEnvFuncs->InitETSSDKNS(ETS_RT_PATH);

    if (g_etsEnvFuncs->InitETSSysNS == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null InitETSSysNS");
        return;
    }
    g_etsEnvFuncs->InitETSSysNS(ETS_SYSLIB_PATH);
}

bool ETSRuntime::Initialize(const Options &options, std::unique_ptr<JsRuntime> &jsRuntime)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "Initialize called");
    if (options.lang != GetLanguage()) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "language mismatch");
        return false;
    }

    if (jsRuntime != nullptr) {
        jsRuntime_ = std::move(jsRuntime);
    }
    if (!CreateEtsEnv(options)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "CreateEtsEnv failed");
        return false;
    }

    apiTargetVersion_ = options.apiTargetVersion;
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "Initialize: %{public}d", apiTargetVersion_);
    return true;
}

void ETSRuntime::FinishPreload()
{
    if (jsRuntime_ != nullptr) {
        jsRuntime_->FinishPreload();
    }

    if (g_etsEnvFuncs == nullptr ||
        g_etsEnvFuncs->FinishPreload == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null g_etsEnvFuncs or FinishPreload");
        return;
    }
    g_etsEnvFuncs->FinishPreload();
}

void ETSRuntime::RegisterUncaughtExceptionHandler(const EtsEnv::ETSUncaughtExceptionInfo &uncaughtExceptionInfo)
{
    if (g_etsEnvFuncs == nullptr ||
        g_etsEnvFuncs->RegisterUncaughtExceptionHandler == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null g_etsEnvFuncs or RegisterUncaughtExceptionHandler");
        return;
    }
    g_etsEnvFuncs->RegisterUncaughtExceptionHandler(uncaughtExceptionInfo);
}

ETSRuntime::~ETSRuntime()
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "~ETSRuntime called");
    Deinitialize();
}

void ETSRuntime::Deinitialize()
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "Deinitialize called");
}

bool ETSRuntime::CreateEtsEnv(const Options &options)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "CreateEtsEnv called");
    if (g_etsEnvFuncs == nullptr ||
        g_etsEnvFuncs->Initialize == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null g_etsEnvFuncs or Initialize");
        return false;
    }

    if (!g_etsEnvFuncs->Initialize()) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Initialize failed");
        return false;
    }
    return true;
}

ani_env *ETSRuntime::GetAniEnv()
{
    if (g_etsEnvFuncs == nullptr ||
        g_etsEnvFuncs->GetAniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null g_etsEnvFuncs or GetAniEnv");
        return nullptr;
    }
    return g_etsEnvFuncs->GetAniEnv();
}

void ETSRuntime::PreloadModule(const std::string &moduleName, const std::string &hapPath,
    bool isEsMode, bool useCommonTrunk)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "moduleName: %{public}s", moduleName.c_str());
    if (g_etsEnvFuncs == nullptr ||
        g_etsEnvFuncs->PreloadModule == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null g_etsEnvFuncs or PreloadModule");
        return;
    }

    std::string modulePath = BUNDLE_INSTALL_PATH + moduleName + MERGE_ABC_PATH;
    if (!g_etsEnvFuncs->PreloadModule(modulePath)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "PreloadModule failed");
    }
    return;
}

std::unique_ptr<AppExecFwk::ETSNativeReference> ETSRuntime::LoadModule(const std::string &moduleName,
    const std::string &modulePath, const std::string &hapPath, bool esmodule, bool useCommonChunk,
    const std::string &srcEntrance)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "LoadModule(%{public}s, %{public}s, %{public}s, %{public}s)",
        moduleName.c_str(), modulePath.c_str(), hapPath.c_str(), srcEntrance.c_str());

    std::string path = moduleName;
    auto pos = path.find("::");
    if (pos != std::string::npos) {
        path.erase(pos, path.size() - pos);
        moduleName_ = path;
    }
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "moduleName_(%{public}s, path %{public}s",
        moduleName_.c_str(), path.c_str());

    std::string fileName;
    if (!hapPath.empty()) {
        fileName.append(codePath_).append(Constants::FILE_SEPARATOR).append(modulePath);
        std::regex pattern(std::string(Constants::FILE_DOT) + std::string(Constants::FILE_SEPARATOR));
        fileName = std::regex_replace(fileName, pattern, "");
    } else {
        if (!MakeFilePath(codePath_, modulePath, fileName)) {
            TAG_LOGE(AAFwkTag::ETSRUNTIME, "make module file path: %{public}s failed", modulePath.c_str());
            return nullptr;
        }
    }
    std::unique_ptr<AppExecFwk::ETSNativeReference> etsNativeReference = LoadEtsModule(moduleName, fileName,
        hapPath, srcEntrance);
    return etsNativeReference;
}

std::unique_ptr<AppExecFwk::ETSNativeReference> ETSRuntime::LoadEtsModule(const std::string &moduleName,
    const std::string &fileName, const std::string &hapPath, const std::string &srcEntrance)
{
    if (g_etsEnvFuncs == nullptr ||
        g_etsEnvFuncs->LoadModule == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null g_etsEnvFuncs or LoadModule");
        return std::unique_ptr<AppExecFwk::ETSNativeReference>();
    }

    std::string modulePath = BUNDLE_INSTALL_PATH + moduleName_ + MERGE_ABC_PATH;
    std::string entryPath = HandleOhmUrlSrcEntry(srcEntrance);
    void *cls = nullptr;
    void *obj = nullptr;
    void *ref = nullptr;
    if (!g_etsEnvFuncs->LoadModule(modulePath, entryPath, cls, obj, ref)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "LoadModule failed");
        return std::unique_ptr<AppExecFwk::ETSNativeReference>();
    }
    auto etsNativeReference = std::make_unique<AppExecFwk::ETSNativeReference>();
    etsNativeReference->aniCls = reinterpret_cast<ani_class>(cls);
    etsNativeReference->aniObj = reinterpret_cast<ani_object>(obj);
    etsNativeReference->aniRef = reinterpret_cast<ani_ref>(ref);
    return etsNativeReference;
}

bool ETSRuntime::HandleUncaughtError()
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "HandleUncaughtError called");
    if (g_etsEnvFuncs == nullptr ||
        g_etsEnvFuncs->HandleUncaughtError == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null g_etsEnvFuncs or HandleUncaughtError");
        return false;
    }
    g_etsEnvFuncs->HandleUncaughtError();
    return true;
}

const std::unique_ptr<AbilityRuntime::Runtime> &ETSRuntime::GetJsRuntime() const
{
    return jsRuntime_;
}

std::unique_ptr<AbilityRuntime::Runtime> ETSRuntime::MoveJsRuntime()
{
    return std::move(jsRuntime_);
}

void ETSRuntime::PreloadSystemModule(const std::string &moduleName)
{
    if (jsRuntime_ != nullptr) {
        jsRuntime_->PreloadSystemModule(moduleName);
    }
}

std::string ETSRuntime::HandleOhmUrlSrcEntry(const std::string &srcEntry)
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

void ETSRuntime::HandleOhmUrlFileName(std::string &fileName)
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
} // namespace AbilityRuntime
} // namespace OHOS