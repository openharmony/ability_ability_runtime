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

#include "mock_bundle_mgr_helper.h"

namespace OHOS {
namespace AppExecFwk {

BundleMgrHelper::BundleMgrHelper() {}

BundleMgrHelper::~BundleMgrHelper() {}

ErrCode BundleMgrHelper::GetSandboxBundleInfo(
    const std::string& bundleName, int32_t appIndex, int32_t userId, BundleInfo& info)
{
    return ERR_OK;
}

bool BundleMgrHelper::GetBundleInfo(
    const std::string& bundleName, const BundleFlag flags, BundleInfo& bundleInfo, int32_t userId)
{
    AbilityInfo abilityInfo;
    bundleInfo.applicationInfo.accessTokenId = 1;
    abilityInfo.bundleName = "bundleNameTest";
    abilityInfo.name = "nameTest";
    abilityInfo.moduleName = "moduleName";
    bundleInfo.abilityInfos.emplace_back(abilityInfo);
    if ("hapModuleInfosModuleNameIsEmpty" == bundleName) {
        abilityInfo.bundleName = bundleName;
        abilityInfo.moduleName = "";
        HapModuleInfo hapModuleInfo;
        hapModuleInfo.abilityInfos.emplace_back(abilityInfo);
        bundleInfo.hapModuleInfos.emplace_back(hapModuleInfo);
    }
    if ("hapAbilityInfoVisible" == bundleName) {
        abilityInfo.bundleName = bundleName;
        abilityInfo.moduleName = "moduleNameTest";
        abilityInfo.visible = true;
        HapModuleInfo hapModuleInfo;
        hapModuleInfo.abilityInfos.emplace_back(abilityInfo);
        bundleInfo.hapModuleInfos.emplace_back(hapModuleInfo);
    }
    return true;
}

bool BundleMgrHelper::GetApplicationInfo(
    const std::string& appName, int32_t flags, int32_t userId, ApplicationInfo& appInfo)
{
    return true;
}

std::string BundleMgrHelper::GetAppIdByBundleName(const std::string& bundleName, const int32_t userId)
{
    auto appId = bundleName + "_appId";
    return appId;
}

ErrCode BundleMgrHelper::GetCloneBundleInfo(
    const std::string& bundleName, int32_t flags, int32_t appCloneIndex, BundleInfo& bundleInfo, int32_t userId)
{
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS