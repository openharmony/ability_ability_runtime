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

#include "ability_manager_service.h"

#include "ability_manager_errors.h"

namespace OHOS {
namespace AAFwk {
bool AbilityManagerService::isInStatusBarResult = false;
bool AbilityManagerService::isSupportStatusBarResult = true;
bool AbilityManagerService::isSceneBoardReadyResult = true;
int32_t AbilityManagerService::userId_ = 0;
int32_t AbilityManagerService::startAbilityResult = ERR_OK;
int32_t AbilityManagerService::usedSupportStatusBarTimes = 0;
int32_t AbilityManagerService::usedStartAbilityTimes = 0;
int32_t AbilityManagerService::usedIsInStatusBar = 0;
int32_t AbilityManagerService::startExtensionAbilityResult = ERR_OK;
int32_t AbilityManagerService::usedStartExtensionAbilityTimes = 0;

AbilityManagerService::AbilityManagerService() {}

AbilityManagerService::~AbilityManagerService() {}

bool AbilityManagerService::IsInStatusBar(uint32_t accessTokenId, int32_t uid, bool isMultiInstance)
{
    usedIsInStatusBar++;
    return isInStatusBarResult;
}

bool AbilityManagerService::IsSupportStatusBar(int32_t uid)
{
    usedSupportStatusBarTimes++;
    return isSupportStatusBarResult;
}

bool AbilityManagerService::IsSceneBoardReady(int32_t userId)
{
    if (!userId_) {
        isSceneBoardReadyResult = true;
        return isSceneBoardReadyResult;
    }
    isSceneBoardReadyResult = false;
    return isSceneBoardReadyResult;
}

int32_t AbilityManagerService::StartAbility(const Want &want, const StartOptions &startOptions,
    const sptr<IRemoteObject> &callerToken, int32_t userId, int requestCode)
{
    if (!userId_ && !usedStartAbilityTimes) {
        return ERR_OK;
    }
    usedStartAbilityTimes++;
    return startAbilityResult;
}

int32_t AbilityManagerService::StartExtensionAbility(const Want &want, const sptr<IRemoteObject> &callerToken,
    int32_t userId, AppExecFwk::ExtensionAbilityType extensionType)
{
    usedStartExtensionAbilityTimes++;
    return startExtensionAbilityResult;
}
}  // namespace AAFwk
}  // namespace OHOS
