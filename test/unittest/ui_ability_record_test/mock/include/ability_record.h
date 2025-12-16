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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_RECORD_H
#define OHOS_ABILITY_RUNTIME_ABILITY_RECORD_H

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <gmock/gmock.h>

namespace OHOS {
namespace AppExecFwk {
struct ApplicationInfo {};
struct AbilityInfo {
    ApplicationInfo applicationInfo;
};
}
namespace AAFwk {
enum class AbilityRecordType {
    BASE_ABILITY,
    UI_ABILITY,
    MISSION_ABILITY,
};

class Want {};

struct AbilityRequest {
    int32_t requestCode = 0;
    Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo appInfo;
};

class LifecycleDeal {
public:
    MOCK_METHOD(void, ScheduleCollaborate, (Want), ());
};

class AbilityRecord : public std::enable_shared_from_this<AbilityRecord> {
public:
    AbilityRecord(const Want &want, const AppExecFwk::AbilityInfo &abilityInfo,
        const AppExecFwk::ApplicationInfo &applicationInfo, int32_t requestCode) {}
    virtual ~AbilityRecord() = default;

    virtual void Init(const AbilityRequest &abilityRequest);
    virtual AbilityRecordType GetAbilityRecordType();
protected:
    bool isPrelaunch_ = false;
    bool isHook_ = false;
    std::atomic_bool isLastWantBackgroundDriven_ = false;
    std::mutex collaborateWantLock_;
    std::shared_ptr<LifecycleDeal> lifecycleDeal_;
};
} // namespace OHOS
} // namespace AAFwk
#endif