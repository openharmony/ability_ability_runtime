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

#include "abilityinterfacesappmgrappdebuglistenerstub_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "app_debug_listener_stub.h"
#include "app_debug_listener_interface.h"
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
const std::u16string AMSMGR_INTERFACE_TOKEN = u"ohos.appexecfwk.IAmsMgr";
class AppDebugListenerStubFUZZ : public AppDebugListenerStub {
public:
    explicit AppDebugListenerStubFUZZ() {};
    virtual ~ AppDebugListenerStubFUZZ() {};
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override{ return 0; };
    void OnAppDebugStarted(const std::vector<AppDebugInfo> &debugInfos) override{};
    void OnAppDebugStoped(const std::vector<AppDebugInfo> &debugInfos) override{};
};

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<AppDebugListenerStub> stub = std::make_shared<AppDebugListenerStubFUZZ>();
    uint32_t code1;
    uint32_t code2;
    MessageParcel parcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    parcel.WriteInterfaceToken(AMSMGR_INTERFACE_TOKEN);
    parcel.WriteString(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    parcel.WriteInt32(fdp.ConsumeIntegral<int32_t>());
    parcel.RewindRead(0);
    code1 = static_cast<uint32_t>(IAppDebugListener::Message::ON_APP_DEBUG_STARTED);
    stub->OnRemoteRequest(code1, parcel, reply, option);
    code2 = static_cast<uint32_t>(IAppDebugListener::Message::ON_APP_DEBUG_STOPED);
    stub->OnRemoteRequest(code2, parcel, reply, option);
    stub->HandleOnAppDebugStarted(parcel, reply);
    stub->HandleOnAppDebugStoped(parcel, reply);
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