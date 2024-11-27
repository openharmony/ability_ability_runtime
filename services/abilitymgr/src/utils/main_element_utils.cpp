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

#include "main_element_utils.h"

#include "ability_manager_service.h"
#include "ability_util.h"

namespace OHOS {
namespace AAFwk {
namespace {
/**
* IsMainElementTypeOk, check if it is a valid main element type.
*
* @param hapModuleInfo The hap module info.
* @param mainElement The returned main element.
* @param userId User id.
* @return Whether it is a valid main element type.
*/
bool IsMainElementTypeOk(const AppExecFwk::HapModuleInfo &hapModuleInfo, const std::string &mainElement,
    int32_t userId)
{
    if (userId == 0) {
        for (const auto &abilityInfo: hapModuleInfo.abilityInfos) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "compare ability: %{public}s", abilityInfo.name.c_str());
            if (abilityInfo.name == mainElement) {
                return abilityInfo.type != AppExecFwk::AbilityType::PAGE;
            }
        }
        return true;
    }
    for (const auto &extensionInfo: hapModuleInfo.extensionInfos) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "compare extension: %{public}s", extensionInfo.name.c_str());
        if (extensionInfo.name == mainElement) {
            return extensionInfo.type == AppExecFwk::ExtensionAbilityType::SERVICE;
        }
    }
    return false;
}
} // namespace

void MainElementUtils::UpdateMainElement(const std::string &bundleName, const std::string &moduleName,
    const std::string &mainElement, bool updateEnable, int32_t userId)
{
    auto abilityMs = DelayedSingleton<AbilityManagerService>::GetInstance();
    CHECK_POINTER(abilityMs);
    auto ret = abilityMs->UpdateKeepAliveEnableState(bundleName, moduleName, mainElement, updateEnable, userId);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR,
            "update keepAlive fail,bundle:%{public}s,mainElement:%{public}s,enable:%{public}d,userId:%{public}d",
            bundleName.c_str(), mainElement.c_str(), updateEnable, userId);
    }
}

bool MainElementUtils::CheckMainElement(const AppExecFwk::HapModuleInfo &hapModuleInfo,
    const std::string &processName, std::string &mainElement, bool &isDataAbility,
    std::string &uriStr, int32_t userId)
{
    if (!hapModuleInfo.isModuleJson) {
        // old application model
        mainElement = hapModuleInfo.mainAbility;
        if (mainElement.empty()) {
            return false;
        }

        // old application model, use ability 'process'
        bool isAbilityKeepAlive = false;
        for (auto abilityInfo : hapModuleInfo.abilityInfos) {
            if (abilityInfo.process != processName || abilityInfo.name != mainElement) {
                continue;
            }
            isAbilityKeepAlive = true;
        }
        if (!isAbilityKeepAlive) {
            return false;
        }

        isDataAbility = DelayedSingleton<AbilityManagerService>::GetInstance()->GetDataAbilityUri(
            hapModuleInfo.abilityInfos, mainElement, uriStr);
        if (isDataAbility) {
            return false;
        }
    } else {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "new mode: %{public}s", hapModuleInfo.bundleName.c_str());
        // new application model
        mainElement = hapModuleInfo.mainElementName;
        if (mainElement.empty()) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "mainElement empty");
            return false;
        }

        // new application model, user model 'process'
        if (hapModuleInfo.process != processName) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "processName err: %{public}s", processName.c_str());
            return false;
        }
    }
    return IsMainElementTypeOk(hapModuleInfo, mainElement, userId);
}

bool MainElementUtils::CheckMainUIAbility(const AppExecFwk::BundleInfo &bundleInfo, std::string& mainElementName)
{
    for (const auto& hapModuleInfo : bundleInfo.hapModuleInfos) {
        if (hapModuleInfo.moduleType != AppExecFwk::ModuleType::ENTRY) {
            continue;
        }

        mainElementName = hapModuleInfo.mainElementName;
        if (mainElementName.empty()) {
            return false;
        }
        for (const auto &abilityInfo: hapModuleInfo.abilityInfos) {
            if (abilityInfo.type != AppExecFwk::AbilityType::PAGE) {
                continue;
            }
            if (abilityInfo.name == mainElementName) {
                return true;
            }
        }
        break;
    }
    return false;
}

bool MainElementUtils::CheckStatusBarAbility(const AppExecFwk::BundleInfo &bundleInfo)
{
    for (const auto& hapModuleInfo : bundleInfo.hapModuleInfos) {
        for (const auto &extensionInfo: hapModuleInfo.extensionInfos) {
            if (extensionInfo.type == AppExecFwk::ExtensionAbilityType::STATUS_BAR_VIEW) {
                return true;
            }
        }
    }
    return false;
}

void MainElementUtils::GetMainUIAbilityAccessTokenId(const AppExecFwk::BundleInfo &bundleInfo,
    const std::string &mainElementName, uint32_t &accessTokenId)
{
    accessTokenId = bundleInfo.applicationInfo.accessTokenId;
}
}  // namespace AAFwk
}  // namespace OHOS
