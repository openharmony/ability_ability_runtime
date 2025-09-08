/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "abilityinterfacesappmgrchildschedulerstub_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "child_scheduler_stub.h"
#include "child_scheduler_interface.h"
#undef private

#include "securec.h"
#include "parcel.h"
#include "ability_record.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}
const std::u16string CHILD_SCHEDULER_TOKEN = u"ohos.appexecfwk.ChildScheduler";

class ChildSchedulerStubFUZZ : public ChildSchedulerStub {
public:
    explicit ChildSchedulerStubFUZZ() {};
    virtual ~ ChildSchedulerStubFUZZ() {};
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override{ return 0; };
    bool ScheduleLoadChild() override{ return true; };
    bool ScheduleExitProcessSafely() override{ return true; };
    bool ScheduleRunNativeProc(const sptr<IRemoteObject> &mainProcessCb) override{ return true; };
    void OnLoadAbilityFinished(uint64_t callbackId, int32_t pid) override {};
};

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<ChildSchedulerStub> stub = std::make_shared<ChildSchedulerStubFUZZ>();
    uint32_t code;
    MessageParcel parcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    parcel.WriteInterfaceToken(CHILD_SCHEDULER_TOKEN);
    parcel.WriteString(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    parcel.WriteInt32(fdp.ConsumeIntegral<int32_t>());
    parcel.RewindRead(0);
    code = static_cast<uint32_t>(IChildScheduler::Message::SCHEDULE_LOAD_JS);
    stub->OnRemoteRequest(code, parcel, reply, option);
    code = static_cast<uint32_t>(IChildScheduler::Message::SCHEDULE_EXIT_PROCESS_SAFELY);
    stub->OnRemoteRequest(code, parcel, reply, option);
    code = static_cast<uint32_t>(IChildScheduler::Message::SCHEDULE_RUN_NATIVE_PROC);
    stub->OnRemoteRequest(code, parcel, reply, option);
    stub->HandleScheduleLoadChild(parcel, reply);
    stub->HandleScheduleExitProcessSafely(parcel, reply);
    stub->HandleScheduleRunNativeProc(parcel, reply);
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