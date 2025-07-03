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
#include "abilityappmgreventfirst_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "app_mgr_event.h"
#undef private

#include "configuration.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    auto appInfo = std::make_shared<ApplicationInfo>();
    appInfo->bundleName = "testBundleName";
    appInfo->name = "testBundleName";
    int32_t recordId = 1;
    std::string processName = "testProcess";
    std::shared_ptr<AppRunningRecord> callerAppRecord;
    std::shared_ptr<AppRunningRecord> appRecord;
    std::shared_ptr<RenderRecord> renderRecord;
    AAFwk::EventInfo eventInfo;
    std::string stringParam;
    EventFwk::CommonEventData eventData;
    int32_t subReason;
    FuzzedDataProvider fdp(data, size);
    stringParam = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    subReason = fdp.ConsumeIntegral<int32_t>();

    appRecord = nullptr;
    AppMgrEventUtil::SendProcessStartFailedEvent(callerAppRecord, appRecord, eventInfo);
    auto appRecord1 = std::make_shared<AppRunningRecord>(appInfo, recordId, processName);
    AppMgrEventUtil::SendProcessStartFailedEvent(callerAppRecord, appRecord1, eventInfo);

    ProcessStartFailedReason reason = ProcessStartFailedReason::APPSPAWN_FAILED;
    AppMgrEventUtil::SendRenderProcessStartFailedEvent(renderRecord, reason, subReason);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}