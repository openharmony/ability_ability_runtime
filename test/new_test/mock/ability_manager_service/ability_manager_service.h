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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_SERVICE_H
#define MOCK_OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_SERVICE_H

#include <cstdint>
#include <memory>

#include "ability_manager_errors.h"
#include "app_scheduler.h"
#include "mission_list_manager_interface.h"
#include "oh_mock_utils.h"
#include "parameters.h"
#include "refbase.h"
#include "singleton.h"
#include "task_handler_wrap.h"
#include "user_callback.h"

namespace OHOS {
namespace AAFwk {
namespace {
constexpr int32_t U1_USER_ID = 1;
}
class AbilityManagerService : public std::enable_shared_from_this<AbilityManagerService> {
    DECLARE_DELAYED_SINGLETON(AbilityManagerService)
public:
    OH_MOCK_METHOD(std::shared_ptr<TaskHandlerWrap>, AbilityManagerService, GetTaskHandler);
    OH_MOCK_METHOD(std::shared_ptr<MissionListWrap>, AbilityManagerService, GetMissionListWrap);

    void RemoveLauncherDeathRecipient(int32_t userId) {}
    void StartFreezingScreen() {}
    void StopFreezingScreen() {}
    void UserStarted(int32_t userId) {}

    OH_MOCK_METHOD(int, AbilityManagerService, SwitchToUser, int32_t, int32_t,
        sptr<AAFwk::IUserCallback>, bool isAppRecovery = false);
    void ClearUserData(int32_t userId) {}
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // MOCK_OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_SERVICE_H
