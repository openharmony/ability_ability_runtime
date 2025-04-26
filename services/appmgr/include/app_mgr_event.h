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

#ifndef OHOS_ABILITY_RUNTIME_APP_MGR_EVENT_H
#define OHOS_ABILITY_RUNTIME_APP_MGR_EVENT_H

#include "ability_info.h"
#include "app_running_record.h"
#ifdef SUPPORT_CHILD_PROCESS
#include "child_process_record.h"
#endif // SUPPORT_CHILD_PROCESS
#include "common_event_data.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"
#include "event_report.h"

namespace OHOS {
namespace AppExecFwk {
enum class ProcessStartFailedReason {
    UNKNOWN = 0,
    APPSPAWN_FAILED = 1,
    CREATE_START_MSG_FAILED = 2,
    GET_SPAWN_CLIENT_FAILED = 3,
    GENERATE_RENDER_UID_FAILED = 4,
    CHECK_CHILD_FDS_FAILED = 5,
};

class AppMgrEventSubscriber : public EventFwk::CommonEventSubscriber {
public:
    AppMgrEventSubscriber(
        const EventFwk::CommonEventSubscribeInfo &subcribeInfo, const std::function<void()> &callback);

    ~AppMgrEventSubscriber() override = default;

    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;

private:
    std::function<void()> callback_;
};

class AppMgrEventUtil {
public:
    static bool SendCreateAtomicServiceProcessEvent(const std::shared_ptr<AppRunningRecord> &callerAppRecord,
        const std::shared_ptr<AppRunningRecord> &appRecord, const std::string &moduleName,
        const std::string &abilityName);
    
    static bool SendProcessStartEvent(const std::shared_ptr<AppRunningRecord> &callerAppRecord,
        const std::shared_ptr<AppRunningRecord> &appRecord, AAFwk::EventInfo &eventInfo);

    static bool SendProcessStartFailedEvent(std::shared_ptr<AppRunningRecord> callerAppRecord,
        std::shared_ptr<AppRunningRecord> appRecord, AAFwk::EventInfo &eventInfo);

#ifdef SUPPORT_CHILD_PROCESS
    static bool SendChildProcessStartFailedEvent(std::shared_ptr<ChildProcessRecord> childRecord,
        ProcessStartFailedReason reason, int32_t subReason);
#endif // SUPPORT_CHILD_PROCESS

    static bool SendRenderProcessStartFailedEvent(std::shared_ptr<RenderRecord> renderRecord,
        ProcessStartFailedReason reason, int32_t subReason);
    
    static void SendReStartProcessEvent(AAFwk::EventInfo &eventInfo, int32_t appUid, int64_t restartTime);

private:
    static int32_t GetCallerPid(const std::shared_ptr<AppRunningRecord> &callerAppRecord);

    static void UpdateStartupType(const std::shared_ptr<AbilityInfo> &abilityInfo, int32_t &abilityType,
        int32_t &extensionType);

    static void UpdateCallerInfo(AAFwk::EventInfo &eventInfo, std::shared_ptr<AppRunningRecord> callerAppRecord,
        std::shared_ptr<AppRunningRecord> appRecord);
};
}
}
#endif  // OHOS_ABILITY_RUNTIME_APP_MGR_EVENT_H