/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "appfreeze_event_report.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "fault_data.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// appfreeze event params
constexpr char EVENT_UID[] = "UID";
constexpr char EVENT_PID[] = "PID";
constexpr char EVENT_TID[] = "TID";
constexpr char EVENT_INPUT_ID[] = "INPUT_ID";
constexpr char EVENT_MESSAGE[] = "MSG";
constexpr char EVENT_PACKAGE_NAME[] = "PACKAGE_NAME";
constexpr char EVENT_PROCESS_NAME[] = "PROCESS_NAME";
constexpr char EVENT_STACK[] = "STACK";
constexpr char EVENT_BINDER_INFO[] = "BINDER_INFO";
constexpr char EVENT_APP_RUNNING_UNIQUE_ID[] = "APP_RUNNING_UNIQUE_ID";
constexpr char EVENT_FREEZE_MEMORY[] = "FREEZE_MEMORY";
constexpr char EVENT_FREEZE_INFO_PATH[] = "FREEZE_INFO_PATH";
constexpr char EVENT_TRACE_ID[] = "HITRACE_ID";
constexpr char EVENT_FOREGROUND[] = "FOREGROUND";
constexpr char EVENT_ENABLE_MAINTHREAD_SAMPLE[] = "ENABLE_MAINTHREAD_SAMPLE";
}

int AppfreezeEventReport::SendAppfreezeEvent(const std::string &eventName, HiSysEventType type,
    const AppfreezeEventInfo &eventInfo)
{
    HITRACE_METER_FMT(HITRACE_TAG_APP, "SendAppfreezeEvent eventName:%{public}s", eventName.c_str());
    int ret = -1;
    if (eventName == AppFreezeType::APP_INPUT_BLOCK) {
        return LogAppInputBlockEvent(eventName, type, eventInfo);
    }
    if (eventName == AppFreezeType::THREAD_BLOCK_6S) {
        return LogThreadBlockEvent(eventName, type, eventInfo);
    }
    return LogGeneralEvent(eventName, type, eventInfo);
}

int AppfreezeEventReport::LogAppInputBlockEvent(const std::string &name, HiSysEventType type,
    const AppfreezeEventInfo &eventInfo)
{
    int ret = -1;
    ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::AAFWK,
        name,
        type,
        EVENT_UID, eventInfo.uid,
        EVENT_PID, eventInfo.pid,
        EVENT_PACKAGE_NAME, eventInfo.bundleName,
        EVENT_PROCESS_NAME, eventInfo.processName,
        EVENT_MESSAGE, eventInfo.errorMessage,
        EVENT_STACK, eventInfo.errorStack,
        EVENT_BINDER_INFO, eventInfo.binderInfo,
        EVENT_APP_RUNNING_UNIQUE_ID, eventInfo.appRunningUniqueId,
        EVENT_INPUT_ID, eventInfo.eventId,
        EVENT_FREEZE_MEMORY, eventInfo.freezeMemory,
        EVENT_ENABLE_MAINTHREAD_SAMPLE, eventInfo.enableFreeze,
        EVENT_FOREGROUND, eventInfo.foregroundState,
        EVENT_FREEZE_INFO_PATH, eventInfo.freezeInfoFile);
    return ret;
}

int AppfreezeEventReport::LogThreadBlockEvent(const std::string &name, HiSysEventType type,
    const AppfreezeEventInfo &eventInfo)
{
    int ret = -1;
    ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::AAFWK,
        name,
        type,
        EVENT_UID, eventInfo.uid,
        EVENT_PID, eventInfo.pid,
        EVENT_TID, eventInfo.tid,
        EVENT_PACKAGE_NAME, eventInfo.bundleName,
        EVENT_PROCESS_NAME, eventInfo.processName,
        EVENT_MESSAGE, eventInfo.errorMessage,
        EVENT_STACK, eventInfo.errorStack,
        EVENT_BINDER_INFO, eventInfo.binderInfo,
        EVENT_APP_RUNNING_UNIQUE_ID, eventInfo.appRunningUniqueId,
        EVENT_FREEZE_MEMORY, eventInfo.freezeMemory,
        EVENT_TRACE_ID, eventInfo.hitraceInfo,
        EVENT_FREEZE_INFO_PATH, eventInfo.freezeInfoFile,
        EVENT_ENABLE_MAINTHREAD_SAMPLE, eventInfo.enableFreeze,
        EVENT_FOREGROUND, eventInfo.foregroundState);
    return ret;
}

int AppfreezeEventReport::LogGeneralEvent(const std::string &name, HiSysEventType type,
    const AppfreezeEventInfo &eventInfo)
{
    int ret = -1;
    ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::AAFWK,
        name,
        type,
        EVENT_UID, eventInfo.uid,
        EVENT_PID, eventInfo.pid,
        EVENT_TID, eventInfo.tid,
        EVENT_PACKAGE_NAME, eventInfo.bundleName,
        EVENT_PROCESS_NAME, eventInfo.processName,
        EVENT_MESSAGE, eventInfo.errorMessage,
        EVENT_STACK, eventInfo.errorStack,
        EVENT_BINDER_INFO, eventInfo.binderInfo,
        EVENT_APP_RUNNING_UNIQUE_ID, eventInfo.appRunningUniqueId,
        EVENT_FREEZE_MEMORY, eventInfo.freezeMemory,
        EVENT_FREEZE_INFO_PATH, eventInfo.freezeInfoFile,
        EVENT_ENABLE_MAINTHREAD_SAMPLE, eventInfo.enableFreeze,
        EVENT_FOREGROUND, eventInfo.foregroundState);
    return ret;
}
}  // namespace AppExecFwk
}  // namespace OHOS
