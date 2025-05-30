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

#ifndef OHOS_ABILITY_RUNTIME_FIRST_FRAME_STATE_OBSERVER_STUB_H
#define OHOS_ABILITY_RUNTIME_FIRST_FRAME_STATE_OBSERVER_STUB_H
#ifdef SUPPORT_GRAPHICS

#include <map>
#include <mutex>

#include "ability_first_frame_state_observer_interface.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AppExecFwk {
class AbilityFirstFrameStateObserverStub : public IRemoteStub<IAbilityFirstFrameStateObserver> {
public:
    AbilityFirstFrameStateObserverStub();
    virtual ~AbilityFirstFrameStateObserverStub();

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int32_t HandleOnAbilityFirstFrameStateChanged(MessageParcel &data, MessageParcel &reply);

    static std::mutex callbackMutex_;

    DISALLOW_COPY_AND_MOVE(AbilityFirstFrameStateObserverStub);
};

/**
 * @class AbilityFirstFrameStateObserverRecipient
 * AbilityFirstFrameStateObserverRecipient notices IRemoteBroker died.
 */
class AbilityFirstFrameStateObserverRecipient : public IRemoteObject::DeathRecipient {
public:
    using RemoteDiedHandler = std::function<void(const wptr<IRemoteObject> &)>;
    explicit AbilityFirstFrameStateObserverRecipient(RemoteDiedHandler handler);
    virtual ~AbilityFirstFrameStateObserverRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

private:
    RemoteDiedHandler handler_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // SUPPORT_GRAPHICS
#endif // OHOS_ABILITY_RUNTIME_ABILITY_FOREGROUND_STATE_OBSERVER_STUB_H
