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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_RECORD_DEATH_MANAGER_H
#define OHOS_ABILITY_RUNTIME_ABILITY_RECORD_DEATH_MANAGER_H

#include <list>
#include <memory>
#include <mutex>

#include "ability_record.h"

namespace OHOS {
namespace AAFwk {
class AbilityRecordDeathManager {
public:
    static AbilityRecordDeathManager &GetInstance();
    AbilityRecordDeathManager(AbilityRecordDeathManager &) = delete;
    void operator=(AbilityRecordDeathManager &) = delete;

    void AddRecordToDeadList(std::shared_ptr<AbilityRecord> abilityRecord);
    std::list<std::shared_ptr<AbilityRecord>> QueryDeadAbilityRecord(int32_t pid, int32_t uid);
protected:
    AbilityRecordDeathManager() = default;

    void RemoveTimeoutDeadAbilityRecord();
private:
    std::mutex deadAbilityRecordListMutex_;
    std::list<std::pair<int64_t, std::shared_ptr<AbilityRecord>>> deadAbilityRecordList_;
};
}  // namespace AAFwk
}  // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_ABILITY_RECORD_DEATH_MANAGER_H