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

#ifndef OHOS_ABILITY_ABILITY_START_WITH_WAIT_OBSERVER_STUB_H
#define OHOS_ABILITY_ABILITY_START_WITH_WAIT_OBSERVER_STUB_H

#include <map>
#include <mutex>

#include "ability_start_with_wait_observer_data.h"
#include "ability_start_with_wait_observer_interface.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AAFwk {

class AbilityStartWithWaitObserverStub : public IRemoteStub<IAbilityStartWithWaitObserver> {
public:
    AbilityStartWithWaitObserverStub() = default;
    virtual ~AbilityStartWithWaitObserverStub() = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    int32_t OnNotifyAATerminateWithWait(MessageParcel& data, MessageParcel& reply);

private:
    DISALLOW_COPY_AND_MOVE(AbilityStartWithWaitObserverStub);
};

class AbilityStartWithWaitObserverRecipient : public IRemoteObject::DeathRecipient {
public:
    using RemoteDiedHandler = std::function<void(const wptr<IRemoteObject> &)>;
    explicit AbilityStartWithWaitObserverRecipient(RemoteDiedHandler handler);
    virtual ~AbilityStartWithWaitObserverRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

private:
    RemoteDiedHandler handler_;
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_ABILITY_START_WITH_WAIT_OBSERVER_STUB_H