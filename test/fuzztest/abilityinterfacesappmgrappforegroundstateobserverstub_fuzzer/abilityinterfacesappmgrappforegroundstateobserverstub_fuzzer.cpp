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

#include "abilityinterfacesappmgrappforegroundstateobserverstub_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "app_foreground_state_observer_stub.h"
#include "app_foreground_state_observer_interface.h"
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
const std::u16string IA_APP_FOREGROUND_STATE_OBSERVER_TOKEN = u"ohos.appexecfwk.IAppForegroundStateObserver";

class AppForegroundStateObserverStubFUZZ : public AppForegroundStateObserverStub {
public:
    explicit AppForegroundStateObserverStubFUZZ() {};
    virtual ~ AppForegroundStateObserverStubFUZZ() {};
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override{ return 0; };
    void OnAppStateChanged(const AppStateData &appStateData) override{};
};

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<AppForegroundStateObserverStub> stub = std::make_shared<AppForegroundStateObserverStubFUZZ>();
    uint32_t code;
    MessageParcel parcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    parcel.WriteInterfaceToken(IA_APP_FOREGROUND_STATE_OBSERVER_TOKEN);
    parcel.WriteString(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    parcel.WriteInt32(fdp.ConsumeIntegral<int32_t>());
    parcel.RewindRead(0);
    code = static_cast<uint32_t>(IAppForegroundStateObserver::Message::ON_APP_STATE_CHANGED);
    stub->OnRemoteRequest(code, parcel, reply, option);
    stub->HandleOnAppStateChanged(parcel, reply);
    using RemoteDiedHandler = std::function<void(const wptr<IRemoteObject> &)>;
    RemoteDiedHandler handler;
    std::shared_ptr<AppForegroundStateObserverRecipient> infos =
        std::make_shared<AppForegroundStateObserverRecipient>(handler);
    wptr<IRemoteObject> remote;
    infos->OnRemoteDied(remote);
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