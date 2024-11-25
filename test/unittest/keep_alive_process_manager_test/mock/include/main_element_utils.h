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

#ifndef OHOS_ABILITY_RUNTIME_MAIN_ELEMENT_UTILS_H
#define OHOS_ABILITY_RUNTIME_MAIN_ELEMENT_UTILS_H

#include "bundle_info.h"

namespace OHOS {
namespace AAFwk {
/**
 * @class MainElementUtils
 * provides main element utilities.
 */
class MainElementUtils final {
public:
    /**
     * UpdateMainElement, update main element.
     *
     * @param bundleName The bundle name.
     * @param moduleName The modle name.
     * @param mainElement The returned main element.
     * @param updateEnable Flag indicated whether update is enabled.
     * @param userId User id.
     */
    static void UpdateMainElement(const std::string &bundleName, const std::string &moduleName,
        const std::string &mainElement, bool updateEnable, int32_t userId);

    /**
     * CheckMainUIAbility, check if bundle has main UIAbility.
     *
     * @param bundleInfo The bundle info.
     * @param mainElementName The returned main element name.
     * @return Whether or not the bundle has the main element.
     */
    static bool CheckMainUIAbility(const AppExecFwk::BundleInfo &bundleInfo, std::string& mainElementName);

    /**
     * CheckStatusBarAbility, check if bundle has status bar ability.
     *
     * @param bundleInfo The bundle info.
     * @return Whether or not the bundle has a status bar ability.
     */
    static bool CheckStatusBarAbility(const AppExecFwk::BundleInfo &bundleInfo);

    /**
     * GetMainUIAbilityAccessTokenId, get the access token id of the main uiability.
     *
     * @param bundleInfo The bundle info.
     * @param mainElementName The main element name.
     * @param accessTokenId The returned access token id.
     */
    static void GetMainUIAbilityAccessTokenId(const AppExecFwk::BundleInfo &bundleInfo,
        const std::string &mainElementName, uint32_t &accessTokenId);

public:
    static bool checkMainUIAbilityResult;
    static bool checkStatusBarAbilityResult;
    static uint32_t accessTokenId_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_MAIN_ELEMENT_UTILS_H
