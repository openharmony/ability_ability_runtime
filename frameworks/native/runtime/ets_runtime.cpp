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
#include "parameters.h"
#include "source_map.h"
#include "source_map_operator.h"
#include "ets_environment.h"
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
constexpr char ENTRY_PATH_MAP_FILE[] = "/system/framework/entrypath.json"; // will deprecated
constexpr char ENTRY_PATH_MAP_KEY[] = "entryPath"; // will deprecated
constexpr char DEFAULT_ENTRY_ABILITY_CLASS[] = "entry/src/main/ets/entryability/EntryAbility/EntryAbility";
constexpr int32_t DOT_START_LEN = 2;

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
            TAG_LOGD(AAFwkTag::ETSRUNTIME, "no entrypath file");
            return false;
        }
        nlohmann::json filePathsJson;
        inFile >> filePathsJson;
        if (filePathsJson.is_discarded()) {
            TAG_LOGE(AAFwkTag::ETSRUNTIME, "json discarded error");
            inFile.close();
            return false;
        }

        if (filePathsJson.is_null() || filePathsJson.empty()) {
            TAG_LOGE(AAFwkTag::ETSRUNTIME, "invalid json");
            inFile.close();
            return false;
        }

        if (!filePathsJson.contains(ENTRY_PATH_MAP_KEY)) {
            TAG_LOGD(AAFwkTag::ETSRUNTIME, "no entrypath key");
            return false;
        }
        const auto &entryPathMap = filePathsJson[ENTRY_PATH_MAP_KEY];
        if (!entryPathMap.is_object()) {
            TAG_LOGE(AAFwkTag::ETSRUNTIME, "entrypath is not object");
            return false;
        }

        for (const auto &entryPath : entryPathMap.items()) {
            std::string key = entryPath.key();
            if (!entryPath.value().is_string()) {
                TAG_LOGE(AAFwkTag::ETSRUNTIME, "val is not string, key: %{public}s", key.c_str());
                continue;
            }
            std::string val = entryPath.value();
            TAG_LOGD(AAFwkTag::ETSRUNTIME, "key: %{public}s, value: %{public}s", key.c_str(), val.c_str());
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
                TAG_LOGD(AAFwkTag::ETSRUNTIME, "not found srcEntry: %{public}s", srcEntry.c_str());
                return DEFAULT_ENTRY_ABILITY_CLASS;
            }
            TAG_LOGD(AAFwkTag::ETSRUNTIME, "srcEntry as class: %{public}s", srcEntry.c_str());
            return HandleOhmUrlSrcEntry(srcEntry);
        }
        TAG_LOGD(AAFwkTag::ETSRUNTIME, "found srcEntry: %{public}s, output: %{public}s",
                 srcEntry.c_str(), iter->second.c_str());
        return iter->second;
    }

private:
    EntryPathManager() = default;

    ~EntryPathManager() = default;

    static bool StartsWithDotSlash(const std::string &str)
    {
        if (str.length() < DOT_START_LEN) {
            return false;
        }
        std::string prefix = str.substr(0, DOT_START_LEN);
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

    std::map<std::string, std::string> entryPathMap_ {};
};
} // namespace

AppLibPathVec ETSRuntime::appLibPaths_;

std::unique_ptr<ETSRuntime> ETSRuntime::Create(const Options &options, std::unique_ptr<JsRuntime> &jsRuntime)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "Create called");
    if (jsRuntime == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null jsRuntime");
        return std::unique_ptr<ETSRuntime>();
    }
    std::unique_ptr<ETSRuntime> instance;
    if (!options.preload) {
        auto preloadedInstance = Runtime::GetPreloaded();
#ifdef SUPPORT_SCREEN
        // reload ace if compatible mode changes
        if (Ace::AceForwardCompatibility::PipelineChanged() && preloadedInstance) {
            preloadedInstance.reset();
        }
#endif
        if (preloadedInstance && preloadedInstance->GetLanguage() == Runtime::Language::ETS) {
            instance.reset(static_cast<ETSRuntime *>(preloadedInstance.release()));
        } else {
            instance = std::make_unique<ETSRuntime>();
        }
    } else {
        instance = std::make_unique<ETSRuntime>();
    }

    if (!instance->Initialize(options, jsRuntime)) {
        return std::unique_ptr<ETSRuntime>();
    }
    EntryPathManager::GetInstance().Init();

    return instance;
}

void ETSRuntime::SetAppLibPath(const AppLibPathMap &appLibPaths)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "SetAppLibPath called");
    EtsEnv::ETSEnvironment::InitETSSDKNS(ETS_RT_PATH);
    EtsEnv::ETSEnvironment::InitETSSysNS(ETS_SYSLIB_PATH);
}

bool ETSRuntime::Initialize(const Options &options, std::unique_ptr<JsRuntime> &jsRuntime)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "Initialize called");
    if (options.lang != GetLanguage()) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "language mismatch");
        return false;
    }

    jsRuntime_ = std::move(jsRuntime);
    if (!CreateEtsEnv(options, jsRuntime_.get())) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Create etsEnv failed");
        return false;
    }

    apiTargetVersion_ = options.apiTargetVersion;
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "Initialize: %{public}d", apiTargetVersion_);

    return true;
}

void ETSRuntime::RegisterUncaughtExceptionHandler(const EtsEnv::ETSUncaughtExceptionInfo &uncaughtExceptionInfo)
{
    if (etsEnv_ == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null etsEnv_");
        return;
    }
    etsEnv_->RegisterUncaughtExceptionHandler(uncaughtExceptionInfo);
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

bool ETSRuntime::CreateEtsEnv(const Options &options, Runtime *jsRuntime)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "CreateEtsEnv called");
    etsEnv_ = std::make_shared<EtsEnv::ETSEnvironment>();
    std::vector<ani_option> aniOptions;
    std::string aotFileString = "";
    if (!options.arkNativeFilePath.empty()) {
        std::string aotFilePath = SANDBOX_ARK_CACHE_PATH + options.arkNativeFilePath + options.moduleName + ".an";
        aotFileString = "--ext:--aot-file=" + aotFilePath;
        aniOptions.push_back(ani_option { aotFileString.c_str(), nullptr });
        TAG_LOGI(AAFwkTag::ETSRUNTIME, "aotFileString: %{public}s", aotFileString.c_str());
        aniOptions.push_back(ani_option { "--ext:--enable-an", nullptr });
    }

    if (!etsEnv_->Initialize(static_cast<AbilityRuntime::JsRuntime *>(jsRuntime)->GetNapiEnv(), aniOptions)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Initialize failed");
        return false;
    }
    return true;
}

ani_env *ETSRuntime::GetAniEnv()
{
    if (etsEnv_ == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null etsEnv_");
        return nullptr;
    }
    return etsEnv_->GetAniEnv();
}

void ETSRuntime::PreloadModule(const std::string &moduleName, const std::string &hapPath,
    bool isEsMode, bool useCommonTrunk)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "moduleName: %{public}s", moduleName.c_str());
    if (etsEnv_ == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null etsEnv_");
        return;
    }

    std::string modulePath = BUNDLE_INSTALL_PATH + moduleName + MERGE_ABC_PATH;
    if (!etsEnv_->PreloadModule(modulePath)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "PreloadModule failed");
    }
    return;
}

std::unique_ptr<ETSNativeReference> ETSRuntime::LoadModule(const std::string &moduleName,
    const std::string &modulePath, const std::string &hapPath, bool esmodule, bool useCommonChunk,
    const std::string &srcEntrance)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "Load module(%{public}s, %{public}s, %{public}s, %{public}s)",
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
    std::unique_ptr<ETSNativeReference> etsNativeReference = LoadEtsModule(moduleName, fileName, hapPath, srcEntrance);
    return etsNativeReference;
}

std::unique_ptr<ETSNativeReference> ETSRuntime::LoadEtsModule(const std::string &moduleName,
    const std::string &fileName, const std::string &hapPath, const std::string &srcEntrance)
{
    if (etsEnv_ == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null etsEnv_");
        return std::unique_ptr<ETSNativeReference>();
    }

    std::string modulePath = BUNDLE_INSTALL_PATH + moduleName_ + MERGE_ABC_PATH;
    std::string entryPath = EntryPathManager::GetInstance().GetEntryPath(srcEntrance);
    ani_class cls = nullptr;
    ani_object obj = nullptr;
    ani_ref ref = nullptr;
    if (!etsEnv_->LoadModule(modulePath, entryPath, cls, obj, ref)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "LoadModule failed");
        return std::unique_ptr<ETSNativeReference>();
    }
    auto etsNativeReference = std::make_unique<ETSNativeReference>();
    etsNativeReference->aniCls = cls;
    etsNativeReference->aniObj = obj;
    etsNativeReference->aniRef = ref;
    return etsNativeReference;
}

bool ETSRuntime::HandleUncaughtError()
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "HandleUncaughtError called");
    if (etsEnv_ == nullptr) {
        return false;
    }
    etsEnv_->HandleUncaughtError();
    return true;
}

const std::unique_ptr<AbilityRuntime::Runtime> &ETSRuntime::GetJsRuntime() const
{
    return jsRuntime_;
}
} // namespace AbilityRuntime
} // namespace OHOS