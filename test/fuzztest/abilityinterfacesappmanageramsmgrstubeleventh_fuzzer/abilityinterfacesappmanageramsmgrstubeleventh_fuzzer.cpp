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

#include "abilityinterfacesappmanageramsmgrstubeleventh_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "ams_mgr_stub.h"
#include "ams_mgr_scheduler.h"
#undef private

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}
const std::u16string AMSMGR_INTERFACE_TOKEN = u"ohos.appexecfwk.IAmsMgr";
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
    amsmgr->HandleUpdateAbilityState(parcel, reply);
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
