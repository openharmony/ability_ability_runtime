/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "bundle_container.h"

#include <nlohmann/json.hpp>

#include "hilog_tag_wrapper.h"
#include "json_serializer.h"
#include "module_profile.h"

namespace OHOS {
namespace AppExecFwk {
constexpr const char *FILE_SEPARATOR = "/";
BundleContainer& BundleContainer::GetInstance()
{
    static BundleContainer instance;
    return instance;
}

void BundleContainer::LoadBundleInfos(const std::vector<uint8_t> &buffer, const std::string &resourcePath)
{
    bundleInfo_ = std::make_shared<InnerBundleInfo>();
    if (!bundleInfo_) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "null bundleInfo_");
        return;
    }

    bundleInfo_->SetIsNewVersion(true);
    ModuleProfile moduleProfile;
    moduleProfile.TransformTo(buffer, *bundleInfo_);
    resourcePath_ = resourcePath;
    auto appInfo = std::make_shared<ApplicationInfo>();
    bundleInfo_->GetApplicationInfo(0, Constants::UNSPECIFIED_USERID, *appInfo);
    if (appInfo != nullptr) {
        std::string bundleName = appInfo->bundleName;
        std::string moduleName = appInfo->moduleInfos[0].moduleName;
        auto key = bundleName + std::string(FILE_SEPARATOR) + moduleName;
        bundleInfos_.emplace(key, bundleInfo_);
        resourcePaths_.emplace(key, resourcePath_);
    }
}

void BundleContainer::LoadDependencyHspInfo(
    const std::string &bundleName, const std::vector<AbilityRuntime::DependencyHspInfo> &dependencyHspInfos)
{
    for (const auto &info : dependencyHspInfos) {
        auto innerBundleInfo = std::make_shared<InnerBundleInfo>();
        if (!innerBundleInfo) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "null innerBundleInfo");
            return;
        }
        innerBundleInfo->SetIsNewVersion(true);
        ModuleProfile moduleProfile;
        moduleProfile.TransformTo(info.moduleJsonBuffer, *innerBundleInfo);
        auto key = bundleName + std::string(FILE_SEPARATOR) + info.moduleName;
        bundleInfos_.emplace(key, innerBundleInfo);
        resourcePaths_.emplace(key, info.resourcePath);
    }
}

std::shared_ptr<ApplicationInfo> BundleContainer::GetApplicationInfo() const
{
    if (bundleInfo_ != nullptr) {
        auto appInfo = std::make_shared<ApplicationInfo>();
        bundleInfo_->GetApplicationInfo(0, Constants::UNSPECIFIED_USERID, *appInfo);
        return appInfo;
    }
    return nullptr;
}

std::shared_ptr<HapModuleInfo> BundleContainer::GetHapModuleInfo(const std::string &modulePackage) const
{
    if (bundleInfo_ != nullptr) {
        auto uid = Constants::UNSPECIFIED_USERID;
        TAG_LOGI(AAFwkTag::ABILITY_SIM,
            "modulePackage:%{public}s", modulePackage.c_str());
        std::optional<HapModuleInfo> hapMouduleInfo = bundleInfo_->FindHapModuleInfo(modulePackage, uid);
        if (hapMouduleInfo) {
            auto hapInfo = std::make_shared<HapModuleInfo>();
            *hapInfo = *hapMouduleInfo;
            return hapInfo;
        }
    }
    return nullptr;
}

std::shared_ptr<AbilityInfo> BundleContainer::GetAbilityInfo(
    const std::string &moduleName, const std::string &abilityName) const
{
    if (bundleInfo_ != nullptr) {
        auto uid = Constants::UNSPECIFIED_USERID;
        std::optional<AbilityInfo> ablilityInfo = bundleInfo_->FindAbilityInfo(moduleName, abilityName, uid);
        if (ablilityInfo) {
            auto aInfo = std::make_shared<AbilityInfo>();
            *aInfo = *ablilityInfo;
            return aInfo;
        }
    }
    return nullptr;
}

void BundleContainer::GetBundleInfo(
    const std::string &bundleName, const std::string &moduleName, BundleInfo &bundleInfo)
{
    auto innerBundleInfo = GetInnerBundleInfo(bundleName, moduleName);
    if (innerBundleInfo != nullptr) {
        innerBundleInfo->GetBundleInfoV9(
            (static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) +
                static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)),
            bundleInfo);
        UpdateResourcePath(bundleName, moduleName, bundleInfo);
    }
}

ErrCode BundleContainer::GetDependentBundleInfo(const std::string &bundleName, const std::string &moduleName,
    BundleInfo &sharedBundleInfo, GetDependentBundleInfoFlag flag)
{
    auto innerBundleInfo = GetInnerBundleInfo(bundleName, moduleName);
    if (innerBundleInfo == nullptr) {
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    int32_t bundleInfoFlags = static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
                              static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    switch (flag) {
        case GetDependentBundleInfoFlag::GET_ALL_DEPENDENT_BUNDLE_INFO: {
            if (innerBundleInfo->GetAppServiceHspInfo(sharedBundleInfo) == ERR_OK) {
                UpdateResourcePath(bundleName, moduleName, sharedBundleInfo);
                return ERR_OK;
            }
            innerBundleInfo->GetSharedBundleInfo(bundleInfoFlags, sharedBundleInfo);
            UpdateResourcePath(bundleName, moduleName, sharedBundleInfo);
            return ERR_OK;
        }
        default:
            return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
}

void BundleContainer::SetBundleCodeDir(const std::string &bundleCodeDir)
{
    bundleCodeDir_ = bundleCodeDir;
}

std::string BundleContainer::GetBundleCodeDir() const
{
    return bundleCodeDir_;
}

std::shared_ptr<InnerBundleInfo> BundleContainer::GetInnerBundleInfo(
    const std::string &bundleName, const std::string &moduleName)
{
    auto key = bundleName + std::string(FILE_SEPARATOR) + moduleName;
    auto it = bundleInfos_.find(key);
    if (it == bundleInfos_.end()) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "find hsp innerBundleInfo fail");
        return nullptr;
    }
    return it->second;
}

void BundleContainer::UpdateResourcePath(
    const std::string &bundleName, const std::string &moduleName, BundleInfo &bundleInfo)
{
    auto key = bundleName + std::string(FILE_SEPARATOR) + moduleName;
    auto it = resourcePaths_.find(key);
    if (it == resourcePaths_.end()) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "find hsp resourcePath fail");
        return;
    }
    for (auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        hapModuleInfo.resourcePath = it->second;
    }
}
} // namespace AppExecFwk
} // namespace OHOS
