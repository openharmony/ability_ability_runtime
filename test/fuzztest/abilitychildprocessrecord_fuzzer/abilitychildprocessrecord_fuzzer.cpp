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
#include "abilitychildprocessrecord_fuzzer.h"

#define private public
#include "app_running_record.h"
#include "child_process_record.h"
#undef private
#include "child_process_request.h"
#include <cstddef>
#include <cstdint>
#include <iostream>
#include "securec.h"
#include "configuration.h"
using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;
namespace OHOS {
namespace {
constexpr size_t U32_AT_SIZE = 4;
constexpr int INPUT_ZERO = 0;
constexpr int INPUT_ONE = 1;
constexpr int INPUT_THREE = 3;
constexpr uint8_t ENABLE = 2;
constexpr size_t OFFSET_ZERO = 24;
constexpr size_t OFFSET_ONE = 16;
constexpr size_t OFFSET_TWO = 8;
}


uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[INPUT_ZERO] << OFFSET_ZERO) | (ptr[INPUT_ONE] << OFFSET_ONE) | (ptr[ENABLE] << OFFSET_TWO) |
        ptr[INPUT_THREE];
}


bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    int32_t hostPid = static_cast<int32_t>(GetU32Data(data));
    ChildProcessRequest request;
    std::shared_ptr<AppRunningRecord> hostRecord;
    ChildProcessRecord::CreateChildProcessRecord(hostPid, request, hostRecord);
    std::string stringParam(data, size);
    sptr<IRemoteObject> mainProcessCb;
    int32_t childProcessCount = static_cast<int32_t>(GetU32Data(data));
    bool isStartWithDebug = *data % ENABLE;
    ChildProcessRecord::CreateNativeChildProcessRecord(hostPid, stringParam, hostRecord, mainProcessCb,
        childProcessCount, isStartWithDebug);
    std::shared_ptr<ApplicationInfo> appInfo = std::make_shared<ApplicationInfo>();
    int32_t RECORD_ID = static_cast<int32_t>(GetU32Data(data));
    auto appRecord = std::make_shared<AppRunningRecord>(appInfo, RECORD_ID, stringParam);
    auto childRecord = std::make_shared<ChildProcessRecord>(hostPid, request, appRecord);
    childRecord->SetPid(hostPid);
    childRecord->GetPid();
    childRecord->GetHostPid();
    int32_t uid = static_cast<int32_t>(GetU32Data(data));
    childRecord->SetUid(uid);
    childRecord->GetUid();
    childRecord->GetProcessName();
    childRecord->GetSrcEntry();
    childRecord->GetHostRecord();
    sptr<IChildScheduler> scheduler;
    childRecord->SetScheduler(scheduler);
    sptr<AppDeathRecipient> recipient;
    childRecord->SetDeathRecipient(recipient);
    childRecord->RegisterDeathRecipient();
    childRecord-> RemoveDeathRecipient();
    childRecord-> ScheduleExitProcessSafely();
    childRecord->isStartWithDebug();
    childRecord-> GetChildProcessType();
    childRecord->GetMainProcessCallback();
    childRecord->ClearMainProcessCallback();
    std::string entryParams(data, size);
    childRecord->GetEntryParams();
    childRecord->MakeProcessName(hostRecord);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        std::cout << "invalid data" << std::endl;
        return 0;
    }

    /* Validate the length of size */
    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = (char*)malloc(size + 1);
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
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

