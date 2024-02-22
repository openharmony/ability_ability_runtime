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

#ifndef OHOS_ABILITY_RUNTIME_APP_EXIT_REASON_HELPER
#define OHOS_ABILITY_RUNTIME_APP_EXIT_REASON_HELPER

#include <memory>
#include <mutex>

#include "bundle_info.h"
#include "exit_reason.h"
#include "mission_list_manager.h"
#include "scene_board/ui_ability_lifecycle_manager.h"

namespace OHOS {
namespace AAFwk {
class AppExitReasonHelper {
public:
    AppExitReasonHelper(std::shared_ptr<UIAbilityLifecycleManager> &uiAbilityLifecycleManager,
        std::unordered_map<int, std::shared_ptr<MissionListManager>> &missionListManagers,
        ffrt::mutex &managersMutex);

    void SetCurrentMissionListManager(const std::shared_ptr<MissionListManager> currentMissionListManager);
    int32_t RecordAppExitReason(const ExitReason &exitReason);
    int32_t RecordProcessExitReason(const int32_t pid, const ExitReason &exitReason);
    int32_t RecordProcessExitReason(const int32_t pid, const ExitReason &exitReason, const std::string bundleName,
        const int32_t uid);

private:
    void GetActiveAbilityListByU0(const std::string bundleName, std::vector<std::string> &abilityLists,
        const int32_t pid);
    void GetActiveAbilityListByUser(const std::string bundleName, std::vector<std::string> &abilityLists,
        const int32_t targetUserId, const int32_t pid);
    std::shared_ptr<MissionListManager> GetListManagerByUserId(const int32_t userId);
    bool IsExitReasonValid(const ExitReason &exitReason);

    std::shared_ptr<UIAbilityLifecycleManager> &uiAbilityLifecycleManager_;
    std::unordered_map<int, std::shared_ptr<MissionListManager>> &missionListManagers_;
    std::shared_ptr<MissionListManager> currentMissionListManager_;
    ffrt::mutex &managersMutex_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APP_EXIT_REASON_HELPER