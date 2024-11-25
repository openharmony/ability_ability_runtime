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

#include "ability_manager_service.h"

#include "ability_manager_errors.h"

namespace OHOS {
namespace AAFwk {
bool AbilityManagerService::isInStatusBarResult = false;
int32_t AbilityManagerService::userId_ = 0;
int32_t AbilityManagerService::startAbilityResult = ERR_OK;

AbilityManagerService::AbilityManagerService() {}

AbilityManagerService::~AbilityManagerService() {}

bool AbilityManagerService::IsInStatusBar(uint32_t accessTokenId)
{
    return isInStatusBarResult;
}

int32_t AbilityManagerService::GetUserId() const
{
    return userId_;
}

int32_t AbilityManagerService::StartAbility(const Want &want, const StartOptions &startOptions,
    const sptr<IRemoteObject> &callerToken, int32_t userId, int requestCode)
{
    return startAbilityResult;
}
}  // namespace AAFwk
}  // namespace OHOS
