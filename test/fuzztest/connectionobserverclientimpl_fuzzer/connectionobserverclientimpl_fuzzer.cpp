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

#include "connectionobserverclientimpl_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "connection_observer_client_impl.h"
#include "service_proxy_adapter.h"
#undef protected
#undef private

#include "ability_record.h"
#include "continuous_task_callback_info.h"
#include "connection_observer.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace {
class MyConnectionObserver : public ConnectionObserver {
public:
    MyConnectionObserver() = default;
    virtual ~MyConnectionObserver() = default;
    void OnExtensionConnected(const ConnectionData& data) override
    {}
    void OnExtensionDisconnected(const ConnectionData& data) override
    {}
    void OnDlpAbilityOpened(const DlpStateData& data) override
    {}
    void OnDlpAbilityClosed(const DlpStateData& data) override
    {}
    void OnServiceDied() override
    {}
};
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    std::shared_ptr<ConnectionObserver> observer = std::make_shared<MyConnectionObserver>();
    // fuzz for connectionObserverClientImpl
    auto connectionObserverClientImpl = std::make_shared<ConnectionObserverClientImpl>();
    connectionObserverClientImpl->UnregisterObserver(observer);

    Parcel parcel;
    parcel.WriteString(fdp->ConsumeRandomLengthString());
    sptr<AbilityRuntime::ConnectionData> connData = AbilityRuntime::ConnectionData::Unmarshalling(parcel);
    AbilityRuntime::ConnectionData connectionData = *connData;

    connectionObserverClientImpl->HandleExtensionConnected(connectionData);
    connectionObserverClientImpl->HandleExtensionDisconnected(connectionData);
#ifdef WITH_DLP
    AbilityRuntime::DlpStateData dlpStateData;
    connectionObserverClientImpl->HandleDlpAbilityOpened(dlpStateData);
    connectionObserverClientImpl->HandleDlpAbilityClosed(dlpStateData);
#endif // WITH_DLP
    sptr<IRemoteObject> remoteObj;
    auto serviceProxyAdapter = std::make_shared<ServiceProxyAdapter>(remoteObj);
    connectionObserverClientImpl->UnregisterFromServiceLocked(serviceProxyAdapter);
    connectionObserverClientImpl->RemoveObserversLocked(observer);
    wptr<IRemoteObject> remote;
    connectionObserverClientImpl->HandleRemoteDied(remote);
    connectionObserverClientImpl->ResetProxy(remote);
    connectionObserverClientImpl->ResetStatus();
    connectionObserverClientImpl->NotifyServiceDiedToObservers();
    connectionObserverClientImpl->GetObservers();
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}

