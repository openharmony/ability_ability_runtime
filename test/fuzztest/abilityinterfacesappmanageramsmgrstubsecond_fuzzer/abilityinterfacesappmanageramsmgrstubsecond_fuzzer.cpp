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

#include "abilityinterfacesappmanageramsmgrstubsecond_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "ams_mgr_stub.h"
#include "ams_mgr_scheduler.h"
#undef private

#include "securec.h"
#include "parcel.h"
#include "ability_record.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr int INPUT_ZERO = 0;
constexpr int INPUT_ONE = 1;
constexpr int INPUT_TWO = 2;
constexpr int INPUT_THREE = 3;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t OFFSET_ZERO = 24;
constexpr size_t OFFSET_ONE = 16;
constexpr size_t OFFSET_TWO = 8;
constexpr uint8_t ENABLE = 2;
constexpr size_t STRING_MAX_LENGTH = 128;
}

const std::u16string AMSMGR_INTERFACE_TOKEN = u"ohos.appexecfwk.IAmsMgr";
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[INPUT_ZERO] << OFFSET_ZERO) | (ptr[INPUT_ONE] << OFFSET_ONE) | (ptr[INPUT_TWO] << OFFSET_TWO) |
        ptr[INPUT_THREE];
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<AppMgrServiceInner> MgrServiceInner;
    std::shared_ptr<AAFwk::TaskHandlerWrap> Handler;
    std::shared_ptr<AmsMgrScheduler> amsmgr = std::make_shared<AmsMgrScheduler>(MgrServiceInner, Handler);
    MessageParcel parcel;
    MessageParcel reply;
    FuzzedDataProvider fdp(data, size);
    parcel.WriteInterfaceToken(AMSMGR_INTERFACE_TOKEN);
    parcel.WriteString(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    parcel.WriteInt32(fdp.ConsumeIntegral<int32_t>());
    parcel.RewindRead(0);
    amsmgr->HandleKillApplication(parcel, reply);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
