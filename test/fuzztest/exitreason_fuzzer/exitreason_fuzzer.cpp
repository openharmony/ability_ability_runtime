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

#include "exitreason_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "ability_record.h"
#define private public
#include "exit_reason.h"
#define private public

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t STRING_MAX_LENGTH = 128;
} // namespace

bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    std::string exitMsg;
    int32_t subReason;
    Reason reason;
    FuzzedDataProvider fdp(data, size);
    exitMsg = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    subReason = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    reason = static_cast<Reason>(fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE));
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    std::shared_ptr<ExitReason> exitReasonFirst = std::make_shared<ExitReason>(reason, exitMsg);
    std::shared_ptr<ExitReason> exitReasonSecond = std::make_shared<ExitReason>(reason, subReason, exitMsg);
    std::shared_ptr<ExitReason> exitReason = std::make_shared<ExitReason>();
    exitReason->ReadFromParcel(parcel);
    exitReason->Marshalling(parcel);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
   
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}