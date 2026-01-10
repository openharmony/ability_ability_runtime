/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "abilityappmgreventfourth_fuzzer.h"

#define private public
#include "app_mgr_event.h"
#undef private

#include <cstddef>
#include <cstdint>
#include <iostream>
#include "securec.h"
#include "configuration.h"
#include "application_info.h"
#include "fd_guard.h"
using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t U32_LEFT1 = 24;
constexpr size_t U32_LEFT2 = 16;
constexpr size_t U32_LEFT3 = 8;
constexpr size_t FD1 = 100;
constexpr size_t FD2 = 101;
constexpr size_t FD3 = 102;
}

uint32_t GetU32Data(const char* ptr)
{
    return (ptr[0] << U32_LEFT1) | (ptr[1] << U32_LEFT2) | (ptr[2] << U32_LEFT3) | ptr[3];
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    std::shared_ptr<ApplicationInfo> appInfo = std::make_shared<ApplicationInfo>();
    int32_t recordId = static_cast<int32_t>(GetU32Data(data));
    std::string processName(data, size);
    
    std::shared_ptr<AppRunningRecord> callerAppRecord = std::make_shared<AppRunningRecord>(
        appInfo, recordId, processName);
    std::shared_ptr<AppRunningRecord> appRecord = std::make_shared<AppRunningRecord>(
        appInfo, recordId + 1, processName + "_test");
    int32_t intParam = static_cast<int32_t>(GetU32Data(data));
    int64_t longParam = static_cast<int64_t>(GetU32Data(data));
    EventInfo eventInfo;
    int32_t seed1 = 2;
    int32_t seed2 = 10;
    eventInfo.isPreload = (intParam % seed1) == 0;
    eventInfo.preloadMode = intParam % seed2;
    int32_t appUid = intParam;
    int64_t restartTime = longParam;
    AppMgrEventUtil::SendReStartProcessEvent(eventInfo, appUid, restartTime);

    AppMgrEventUtil::GetCallerPid(nullptr);
    callerAppRecord->SetUid(intParam);
    AppMgrEventUtil::GetCallerPid(callerAppRecord);
    std::shared_ptr<AbilityInfo> abilityInfo = std::make_shared<AbilityInfo>();
    int32_t abilityType = 0;
    int32_t extensionType = 0;
    AppMgrEventUtil::UpdateStartupType(nullptr, abilityType, extensionType);
    abilityInfo->type = static_cast<AbilityType>(intParam % 10);
    int32_t seed3 = 20;
    abilityInfo->extensionAbilityType = static_cast<ExtensionAbilityType>(intParam % seed3);
    AppMgrEventUtil::UpdateStartupType(abilityInfo, abilityType, extensionType);

    AppMgrEventUtil::UpdateCallerInfo(eventInfo, nullptr, appRecord);
    AppMgrEventUtil::UpdateCallerInfo(eventInfo, callerAppRecord, appRecord);

    pid_t hostPid = static_cast<pid_t>(intParam);
    std::string renderParam(data, size);
    FdGuard ipcFd(FD1);
    FdGuard sharedFd(FD2);
    FdGuard crashFd(FD3);
    
    std::shared_ptr<RenderRecord> renderRecord = RenderRecord::CreateRenderRecord(
        hostPid, renderParam, std::move(ipcFd), std::move(sharedFd), std::move(crashFd), appRecord);

    ProcessStartFailedReason reason = static_cast<ProcessStartFailedReason>(intParam % 10);
    int32_t seed = 100;
    int32_t subReason = intParam % seed;
    AppMgrEventUtil::SendRenderProcessStartFailedEvent(nullptr, reason, subReason);
    AppMgrEventUtil::SendRenderProcessStartFailedEvent(renderRecord, reason, subReason);

    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    auto subscriber = std::make_shared<AppMgrEventSubscriber>(subscribeInfo, nullptr);
    EventFwk::CommonEventData eventData;
    subscriber->OnReceiveEvent(eventData);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        std::cout << "invalid data" << std::endl;
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = (char*)malloc(size + 1);
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        std::cout << "copy failed." << std::endl;
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}