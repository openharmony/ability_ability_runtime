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

#include "ability_record_death_manager.h"

#include "task_handler_wrap.h"
#include "time_util.h"

namespace OHOS {
namespace AAFwk {
constexpr int32_t DEAD_APP_RECORD_CLEAR_TIME = 3000; // ms
AbilityRecordDeathManager &AbilityRecordDeathManager::GetInstance()
{
    static AbilityRecordDeathManager instance;
    return instance;
}

void AbilityRecordDeathManager::AddRecordToDeadList(std::shared_ptr<AbilityRecord> abilityRecord)
{
    if (abilityRecord == nullptr) {
        return;
    }
    std::lock_guard lock(deadAbilityRecordListMutex_);
    deadAbilityRecordList_.emplace_back(AbilityRuntime::TimeUtil::CurrentTimeMillis(), abilityRecord);
    if (deadAbilityRecordList_.size() == 1) {
        AAFwk::TaskHandlerWrap::GetFfrtHandler()->SubmitTask([]() {
                AbilityRecordDeathManager::GetInstance().RemoveTimeoutDeadAbilityRecord();
            }, DEAD_APP_RECORD_CLEAR_TIME);
    }
}

std::list<std::shared_ptr<AbilityRecord>> AbilityRecordDeathManager::QueryDeadAbilityRecord(int32_t pid, int32_t uid)
{
    std::list<std::shared_ptr<AbilityRecord>> result;
    std::lock_guard lock(deadAbilityRecordListMutex_);
    for (const auto &[deadTime, abilityRecord] : deadAbilityRecordList_) {
        if (abilityRecord && abilityRecord->GetPid() == pid && abilityRecord->GetUid() == uid) {
            result.emplace_back(abilityRecord);
        }
    }
    return result;
}

void AbilityRecordDeathManager::RemoveTimeoutDeadAbilityRecord()
{
    std::lock_guard lock(deadAbilityRecordListMutex_);
    auto timeEnd = AbilityRuntime::TimeUtil::CurrentTimeMillis() - DEAD_APP_RECORD_CLEAR_TIME;
    auto it = deadAbilityRecordList_.begin();
    while (it != deadAbilityRecordList_.end() && it->first <= timeEnd) {
        it = deadAbilityRecordList_.erase(it);
    }

    if (!deadAbilityRecordList_.empty()) {
        AAFwk::TaskHandlerWrap::GetFfrtHandler()->SubmitTask([]() {
                AbilityRecordDeathManager::GetInstance().RemoveTimeoutDeadAbilityRecord();
            }, DEAD_APP_RECORD_CLEAR_TIME);
    }
}
}  // namespace AAFwk
}  // namespace OHOS