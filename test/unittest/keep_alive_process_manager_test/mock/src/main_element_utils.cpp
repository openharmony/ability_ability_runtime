/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
bool MainElementUtils::checkMainUIAbilityResult = false;
bool MainElementUtils::checkStatusBarAbilityResult = false;
bool MainElementUtils::checkAppServiceExtensionResult = false;
int32_t MainElementUtils::usedUpdateMainElementTimes = 0;
int32_t MainElementUtils::usedCheckMainUIAbilityTime = 0;

void MainElementUtils::UpdateMainElement(const std::string &bundleName, const std::string &moduleName,
    const std::string &mainElement, bool updateEnable, int32_t userId)
{
    usedUpdateMainElementTimes++;
}

bool MainElementUtils::CheckMainUIAbility(const AppExecFwk::BundleInfo &bundleInfo, std::string& mainElementName)
{
    usedCheckMainUIAbilityTime++;
    return checkMainUIAbilityResult;
}

bool MainElementUtils::CheckStatusBarAbility(const AppExecFwk::BundleInfo &bundleInfo)
{
    return checkStatusBarAbilityResult;
}

bool MainElementUtils::CheckAppServiceExtension(const AppExecFwk::BundleInfo &bundleInfo, std::string& mainElementName)
{
    return checkAppServiceExtensionResult;
}
}  // namespace AAFwk
}  // namespace OHOS
