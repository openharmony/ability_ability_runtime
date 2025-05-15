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

#include "context_impl.h"

#include <cstring>
#include <regex>

#include "bundle_container.h"
#include "bundle_info.h"
#include "hilog_tag_wrapper.h"
#include "js_data_converter.h"
#include "res_common.h"
#include "res_config.h"
#include "resource_manager_helper.h"

namespace OHOS {
namespace AbilityRuntime {
const size_t Context::CONTEXT_TYPE_ID(std::hash<const char *>{}("Context"));
const int64_t ContextImpl::CONTEXT_CREATE_BY_SYSTEM_APP(0x00000001);
constexpr const char *CONTEXT_DISTRIBUTEDFILES("distributedfiles");
constexpr const char *CONTEXT_CLOUD("cloud");
constexpr const char *CONTEXT_FILE_SEPARATOR("/");
constexpr const char *CONTEXT_FILE_OPPOSITE_SEPARATOR("\\");
constexpr const char *CONTEXT_BASE("base");
constexpr const char *CONTEXT_CACHE("cache");
constexpr const char *CONTEXT_PREFERENCES("preferences");
constexpr const char *CONTEXT_DATABASE("database");
constexpr const char *CONTEXT_TEMP("temp");
constexpr const char *CONTEXT_FILES("files");
constexpr const char *CONTEXT_HAPS("haps");
constexpr const char *CONTEXT_ASSET("asset");
constexpr const char *CONTEXT_ELS[] = {"el1", "el2", "el3", "el4", "el5"};
constexpr const char *CONTEXT_RESOURCE_BASE("/data/storage/el1/bundle");
constexpr const char *CONTEXT_RESOURCE_END("/resources/resfile");
const int32_t TYPE_RESERVE = 1;
const int32_t TYPE_OTHERS = 2;
const int32_t API11 = 11;
const int32_t API_VERSION_MOD = 100;
const int AREA1 = 1;
const int AREA2 = 2;
const int AREA3 = 3;
const int AREA4 = 4;
constexpr int DIR_DEFAULT_PERM = 0770;
std::shared_ptr<AppExecFwk::Configuration> ContextImpl::GetConfiguration()
{
    return configuration_;
}

void ContextImpl::SetConfiguration(const std::shared_ptr<AppExecFwk::Configuration> &configuration)
{
    if (configuration == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "null configuration");
        return;
    }
    configuration_ = configuration;
}

std::shared_ptr<AppExecFwk::ApplicationInfo> ContextImpl::GetApplicationInfo() const
{
    return applicationInfo_;
}

void ContextImpl::SetApplicationInfo(const std::shared_ptr<AppExecFwk::ApplicationInfo> &info)
{
    if (info == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "null applicationInfo");
        return;
    }
    applicationInfo_ = info;
}

std::shared_ptr<AppExecFwk::HapModuleInfo> ContextImpl::GetHapModuleInfo() const
{
    if (hapModuleInfo_ == nullptr) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "hapModuleInfo is empty");
    }
    return hapModuleInfo_;
}

void ContextImpl::InitHapModuleInfo(const AppExecFwk::HapModuleInfo &hapModuleInfo)
{
    hapModuleInfo_ = std::make_shared<AppExecFwk::HapModuleInfo>(hapModuleInfo);
}

std::shared_ptr<Global::Resource::ResourceManager> ContextImpl::GetResourceManager() const
{
    return resourceManager_;
}

void ContextImpl::SetResourceManager(const std::shared_ptr<Global::Resource::ResourceManager> &resourceManager)
{
    resourceManager_ = resourceManager;
}

Options ContextImpl::GetOptions()
{
    return options_;
}

void ContextImpl::SetOptions(const Options &options)
{
    options_ = options;
}

std::string ContextImpl::GetBundleName() const
{
    return (applicationInfo_ != nullptr) ? applicationInfo_->bundleName : "";
}

std::string ContextImpl::GetBundleCodePath()
{
    return (applicationInfo_ != nullptr) ? applicationInfo_->codePath : "";
}

std::string ContextImpl::GetPreviewPath()
{
    auto path = AppExecFwk::BundleContainer::GetInstance().GetBundleCodeDir();
    auto pos = path.find(CONTEXT_FILE_SEPARATOR);
    if (pos == std::string::npos) {
        fileSeparator_ = CONTEXT_FILE_OPPOSITE_SEPARATOR;
    }
    return path;
}

std::string ContextImpl::GetBundleCodeDir()
{
    return GetPreviewPath();
}

std::string ContextImpl::GetCacheDir()
{
    if (GetPreviewPath().empty()) {
        return "";
    }

    auto dir = GetBaseDir() + fileSeparator_ + CONTEXT_CACHE;
    CreateMultiDir(dir);
    return dir;
}

std::string ContextImpl::GetTempDir()
{
    if (GetPreviewPath().empty()) {
        return "";
    }

    auto dir = GetBaseDir() + fileSeparator_ + CONTEXT_TEMP;
    CreateMultiDir(dir);
    return dir;
}

std::string ContextImpl::GetResourceDir()
{
    std::shared_ptr<AppExecFwk::HapModuleInfo> hapModuleInfoPtr = GetHapModuleInfo();
    if (hapModuleInfoPtr == nullptr || hapModuleInfoPtr->moduleName.empty()) {
        return "";
    }
    auto dir = std::string(CONTEXT_RESOURCE_BASE) +
        CONTEXT_FILE_SEPARATOR + hapModuleInfoPtr->moduleName + CONTEXT_RESOURCE_END;
    if (Access(dir)) {
        return dir;
    }
    return "";
}

std::string ContextImpl::GetFilesDir()
{
    if (GetPreviewPath().empty()) {
        return "";
    }

    auto dir = GetBaseDir() + fileSeparator_ + CONTEXT_FILES;
    CreateMultiDir(dir);
    return dir;
}

std::string ContextImpl::GetDatabaseDir()
{
    auto preivewDir = GetPreviewPath();
    if (preivewDir.empty()) {
        return "";
    }

    std::shared_ptr<AppExecFwk::HapModuleInfo> hapModuleInfoPtr = GetHapModuleInfo();
    if (hapModuleInfoPtr == nullptr || hapModuleInfoPtr->moduleName.empty()) {
        return "";
    }
    auto dir = preivewDir + fileSeparator_ + currArea_ + fileSeparator_ + CONTEXT_DATABASE +
        fileSeparator_ + hapModuleInfoPtr->moduleName;
    CreateMultiDir(dir);
    return dir;
}

std::string ContextImpl::GetPreferencesDir()
{
    if (GetPreviewPath().empty()) {
        return "";
    }

    auto dir = GetBaseDir() + fileSeparator_ + CONTEXT_PREFERENCES;
    CreateMultiDir(dir);
    return dir;
}

std::string ContextImpl::GetDistributedFilesDir()
{
    auto preivewDir = GetPreviewPath();
    if (preivewDir.empty()) {
        return "";
    }

    auto dir = preivewDir + fileSeparator_ + currArea_ + fileSeparator_ + CONTEXT_DISTRIBUTEDFILES;
    CreateMultiDir(dir);
    return dir;
}

std::string ContextImpl::GetCloudFileDir()
{
    auto preivewDir = GetPreviewPath();
    if (preivewDir.empty()) {
        return "";
    }

    auto dir = GetBaseDir() + fileSeparator_ + CONTEXT_CLOUD;
    CreateMultiDir(dir);
    return dir;
}

void ContextImpl::SwitchArea(int mode)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "mode:%{public}d", mode);
    if (mode < 0 || mode >= (int)(sizeof(CONTEXT_ELS) / sizeof(CONTEXT_ELS[0]))) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "mode invalid");
        return;
    }
    currArea_ = CONTEXT_ELS[mode];
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "currArea:%{public}s", currArea_.c_str());
}
int ContextImpl::GetArea()
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "begin");
    int mode = -1;
    for (int i = 0; i < (int)(sizeof(CONTEXT_ELS) / sizeof(CONTEXT_ELS[0])); i++) {
        if (currArea_ == CONTEXT_ELS[i]) {
            mode = i;
            break;
        }
    }
    if (mode == -1) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "not find mode");
        return EL_DEFAULT;
    }
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "end");
    return mode;
}

std::string ContextImpl::GetBaseDir()
{
    auto previewPath = GetPreviewPath();
    if (previewPath.empty()) {
        return "";
    }
    std::shared_ptr<AppExecFwk::HapModuleInfo> hapModuleInfoPtr = GetHapModuleInfo();
    if (hapModuleInfoPtr == nullptr || hapModuleInfoPtr->moduleName.empty()) {
        return "";
    }
    return previewPath + fileSeparator_ + currArea_ + fileSeparator_ + CONTEXT_BASE + fileSeparator_ +
        CONTEXT_HAPS + fileSeparator_ + hapModuleInfoPtr->moduleName;
}

void ContextImpl::GetBundleInfo(
    const std::string &bundleName, const std::string &moduleName, AppExecFwk::BundleInfo &bundleInfo)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "begin");
    if (bundleName.empty() || moduleName.empty()) {
        return;
    }
    AppExecFwk::BundleContainer::GetInstance().GetBundleInfo(bundleName, moduleName, bundleInfo);
}

void ContextImpl::UpdateResConfig(std::shared_ptr<Global::Resource::ResourceManager> &resourceManager)
{
    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    if (resConfig == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "null resConfig");
        return;
    }

    if (GetHapModuleInfo() != nullptr && GetApplicationInfo() != nullptr) {
        std::vector<AppExecFwk::Metadata> metadata = GetHapModuleInfo()->metadata;
        bool load = std::any_of(metadata.begin(), metadata.end(), [](const auto &metadataItem) {
            return metadataItem.name == "ContextResourceConfigLoadFromParentTemp" && metadataItem.value == "true";
        });
        if (load && GetApplicationInfo()->apiTargetVersion % API_VERSION_MOD >= API11) {
            std::shared_ptr<Global::Resource::ResourceManager> currentResMgr = GetResourceManager();
            if (currentResMgr != nullptr) {
                TAG_LOGD(AAFwkTag::ABILITY_SIM, "apiVersion: %{public}d, load parent config",
                    GetApplicationInfo()->apiTargetVersion);
                currentResMgr->GetResConfig(*resConfig);
            }
        }
    }
    ResourceManagerHelper::GetInstance().GetResConfig(*resConfig, true);
    resourceManager->UpdateResConfig(*resConfig);
}

void ContextImpl::UpdateResConfig(std::shared_ptr<Global::Resource::ResourceManager> src,
    std::shared_ptr<Global::Resource::ResourceManager> &resourceManager)
{
    if (src == nullptr) {
        UpdateResConfig(resourceManager);
        return;
    }
    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    if (resConfig == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "null resConfig");
        return;
    }
    src->GetResConfig(*resConfig);
    resourceManager->UpdateResConfig(*resConfig);
}

std::shared_ptr<Global::Resource::ResourceManager> ContextImpl::InitOthersResourceManagerInner(
    const AppExecFwk::BundleInfo &bundleInfo, bool currentBundle, const std::string &moduleName)
{
    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    std::string hapPath;
    std::vector<std::string> overlayPaths;
    int32_t appType;
    if (bundleInfo.applicationInfo.codePath == std::to_string(TYPE_RESERVE)) {
        appType = TYPE_RESERVE;
    } else if (bundleInfo.applicationInfo.codePath == std::to_string(TYPE_OTHERS)) {
        appType = TYPE_OTHERS;
    } else {
        appType = 0;
    }
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager(
        bundleInfo.name, moduleName, hapPath, overlayPaths, *resConfig, appType));
    return resourceManager;
}

std::shared_ptr<Global::Resource::ResourceManager> ContextImpl::InitResourceManagerInner(
    const AppExecFwk::BundleInfo &bundleInfo, bool currentBundle, const std::string &moduleName,
    std::shared_ptr<Context> inputContext)
{
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager =
        InitOthersResourceManagerInner(bundleInfo, currentBundle, moduleName);
    if (resourceManager == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "null resourceManager");
        return resourceManager;
    }
    if (!moduleName.empty() || !bundleInfo.applicationInfo.multiProjects) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "hapModuleInfos count: %{public}zu", bundleInfo.hapModuleInfos.size());
        for (auto hapModuleInfo : bundleInfo.hapModuleInfos) {
            if (!moduleName.empty() && hapModuleInfo.moduleName != moduleName) {
                continue;
            }
            std::string loadPath = hapModuleInfo.hapPath.empty() ? hapModuleInfo.resourcePath : hapModuleInfo.hapPath;
            if (loadPath.empty()) {
                TAG_LOGD(AAFwkTag::ABILITY_SIM, "loadPath is empty");
                continue;
            }
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "loadPath: %{public}s", loadPath.c_str());
            if (!resourceManager->AddResource(loadPath.c_str())) {
                TAG_LOGE(AAFwkTag::ABILITY_SIM, "Add resource failed");
            }
            ResourceManagerHelper::GetInstance().AddSystemResource(resourceManager);
        }
    }
    return resourceManager;
}

void ContextImpl::InitResourceManager(const AppExecFwk::BundleInfo &bundleInfo,
    const std::shared_ptr<ContextImpl> &appContext, bool currentBundle, const std::string &moduleName,
    std::shared_ptr<Context> inputContext)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "begin, bundleName:%{public}s, moduleName:%{public}s", bundleInfo.name.c_str(),
        moduleName.c_str());

    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "null appContext");
        return;
    }
    if (bundleInfo.applicationInfo.codePath == std::to_string(TYPE_RESERVE) ||
        bundleInfo.applicationInfo.codePath == std::to_string(TYPE_OTHERS)) {
        std::shared_ptr<Global::Resource::ResourceManager> resourceManager =
            InitOthersResourceManagerInner(bundleInfo, currentBundle, moduleName);
        if (resourceManager == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "null resourceManager");
            return;
        }
        appContext->SetResourceManager(resourceManager);
        return;
    }

    std::shared_ptr<Global::Resource::ResourceManager> resourceManager =
        InitResourceManagerInner(bundleInfo, currentBundle, moduleName, inputContext);
    if (resourceManager == nullptr) {
        return;
    }
    std::shared_ptr<Global::Resource::ResourceManager> src = nullptr;
    if (inputContext) {
        src = inputContext->GetResourceManager();
    }
    UpdateResConfig(src, resourceManager);
    appContext->SetResourceManager(resourceManager);
}

std::shared_ptr<Context> ContextImpl::CreateModuleContext(const std::string &moduleName)
{
    return CreateModuleContext(GetBundleName(), moduleName, nullptr);
}

std::shared_ptr<Context> ContextImpl::CreateModuleContext(const std::string &bundleName, const std::string &moduleName)
{
    return CreateModuleContext(bundleName, moduleName, nullptr);
}

std::string ContextImpl::GetBundleNameWithContext(std::shared_ptr<Context> inputContext) const
{
    if (inputContext != nullptr) {
        return inputContext->GetBundleName();
    }
    return GetBundleName();
}

std::shared_ptr<Context> ContextImpl::CreateModuleContext(
    const std::string &moduleName, std::shared_ptr<Context> inputContext)
{
    return CreateModuleContext(GetBundleNameWithContext(inputContext), moduleName, inputContext);
}

std::shared_ptr<Context> ContextImpl::CreateModuleContext(
    const std::string &bundleName, const std::string &moduleName, std::shared_ptr<Context> inputContext)
{
    if (bundleName.empty() || moduleName.empty()) {
        return nullptr;
    }

    TAG_LOGD(AAFwkTag::ABILITY_SIM, "bundleName: %{public}s", bundleName.c_str());
    AppExecFwk::BundleInfo bundleInfo;
    GetBundleInfo(bundleName, moduleName, bundleInfo);
    if (bundleInfo.name.empty() || bundleInfo.applicationInfo.name.empty()) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "GetBundleInfo error");
        ErrCode ret = AppExecFwk::BundleContainer::GetInstance().GetDependentBundleInfo(
            bundleName, moduleName, bundleInfo, AppExecFwk::GetDependentBundleInfoFlag::GET_ALL_DEPENDENT_BUNDLE_INFO);
        if (ret != ERR_OK) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "GetDependentBundleInfo failed:%{public}d", ret);
            return nullptr;
        }
    }

    auto appContext = std::make_shared<ContextImpl>();
    if (bundleInfo.applicationInfo.codePath != std::to_string(TYPE_RESERVE) &&
        bundleInfo.applicationInfo.codePath != std::to_string(TYPE_OTHERS)) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "modulename: %{public}s, bundleName: %{public}s", moduleName.c_str(),
            bundleName.c_str());
        auto info = std::find_if(bundleInfo.hapModuleInfos.begin(), bundleInfo.hapModuleInfos.end(),
            [&moduleName](
                const AppExecFwk::HapModuleInfo &hapModuleInfo) { return hapModuleInfo.moduleName == moduleName; });
        if (info == bundleInfo.hapModuleInfos.end()) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "moduleName error");
            return nullptr;
        }
        appContext->InitHapModuleInfo(*info);
    }

    appContext->SetConfiguration(configuration_);
    bool self = false;
    if (inputContext != nullptr) {
        self = (bundleName == inputContext->GetBundleName());
    } else {
        self = bundleName == GetBundleName();
    }
    InitResourceManager(bundleInfo, appContext, self, moduleName, inputContext);
    appContext->SetApplicationInfo(std::make_shared<AppExecFwk::ApplicationInfo>(bundleInfo.applicationInfo));
    return appContext;
}

void ContextImpl::FsReqCleanup(uv_fs_t *req)
{
    uv_fs_req_cleanup(req);
    if (req) {
        delete req;
        req = nullptr;
    }
}

bool ContextImpl::Access(const std::string &path)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "Access: dir: %{public}s", path.c_str());
    std::unique_ptr<uv_fs_t, decltype(ContextImpl::FsReqCleanup) *> access_req = { new uv_fs_t,
        ContextImpl::FsReqCleanup };
    if (!access_req) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "request heap memory failed");
        return false;
    }

    return (uv_fs_access(nullptr, access_req.get(), path.c_str(), 0, nullptr) == 0);
}

void ContextImpl::Mkdir(const std::string &path)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "Mkdir: dir: %{public}s", path.c_str());
    std::unique_ptr<uv_fs_t, decltype(ContextImpl::FsReqCleanup) *> mkdir_req = { new uv_fs_t,
        ContextImpl::FsReqCleanup };
    if (!mkdir_req) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "request heap memory failed");
        return;
    }

    int ret = uv_fs_mkdir(nullptr, mkdir_req.get(), path.c_str(), DIR_DEFAULT_PERM, nullptr);
    if (ret < 0) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create directory failed");
    }
}

bool ContextImpl::CreateMultiDir(const std::string &path)
{
    if (path.empty()) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "empty path");
        return false;
    }

    if (Access(path)) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "path existed");
        return true;
    }

    std::string tempStr = path;
    tempStr += CONTEXT_FILE_SEPARATOR;

    std::string::size_type pos = 0;
    std::string::size_type prePos = 0;
    std::string strFolderPath;

    while ((pos = tempStr.find(CONTEXT_FILE_SEPARATOR, pos)) != std::string::npos) {
        strFolderPath = tempStr.substr(0, pos);
        if (Access(strFolderPath)) {
            pos = pos + 1;
            prePos = pos;
            continue;
        }

        Mkdir(strFolderPath);
        pos = pos + 1;
        prePos = pos;
    }

    return Access(tempStr);
}
} // namespace AbilityRuntime
} // namespace OHOS
