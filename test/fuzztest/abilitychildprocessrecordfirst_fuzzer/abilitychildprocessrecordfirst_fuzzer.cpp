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
#include "abilitychildprocessrecordfirst_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "app_running_record.h"
#include "child_process_record.h"
#undef private

#include "child_process_request.h"
#include "configuration.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;
namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    int32_t hostPid;
    ChildProcessRequest request;
    std::shared_ptr<AppRunningRecord> hostRecord;
    std::string stringParam;
    sptr<IRemoteObject> mainProcessCb;
    int32_t childProcessCount;
    bool isStartWithDebug;
    int32_t recordId;
    FuzzedDataProvider fdp(data, size);
    hostPid = fdp.ConsumeIntegral<int32_t>();
    ChildProcessRecord::CreateChildProcessRecord(hostPid, request, hostRecord);
    stringParam = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    childProcessCount = fdp.ConsumeIntegral<int32_t>();
    isStartWithDebug = fdp.ConsumeBool();
    ChildProcessRecord::CreateNativeChildProcessRecord(hostPid, stringParam, hostRecord, mainProcessCb,
        childProcessCount, isStartWithDebug, "");
    std::shared_ptr<ApplicationInfo> appInfo = std::make_shared<ApplicationInfo>();
    recordId = fdp.ConsumeIntegral<int32_t>();
    auto appRecord = std::make_shared<AppRunningRecord>(appInfo, recordId, stringParam);
    auto childRecord = std::make_shared<ChildProcessRecord>(hostPid, request, appRecord);
    childRecord->IsNativeSpawnStarted();
    childRecord->GetProcessType();
    childRecord->GetEntryFunc();
    childRecord->GetScheduler();
    childRecord->SetEntryParams(stringParam);
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