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

#ifndef OHOS_ABILITY_RUNTIME_HIDDEN_START_OBSERVER_PROXY_H
#define OHOS_ABILITY_RUNTIME_HIDDEN_START_OBSERVER_PROXY_H

#include "iremote_proxy.h"
#include "ihidden_start_observer.h"

namespace OHOS {
namespace AAFwk {
class HiddenStartObserverProxy : public IRemoteProxy<IHiddenStartObserver> {
public:
    explicit HiddenStartObserverProxy(const sptr<IRemoteObject> &impl);
    virtual ~HiddenStartObserverProxy() = default;

    /**
     * IsHiddenStart, return if the given app is started hidden.
     *
     * @param pid Pid of the given app's process.
     * @return if the given app is started hidden
     */
    virtual bool IsHiddenStart(int32_t pid) override;

private:
    /**
     * WriteInterfaceToken.
     *
     * @param data The message parcel data.
     * @return Flag whether write is successful.
     */
    bool WriteInterfaceToken(MessageParcel &data);
    static inline BrokerDelegator<HiddenStartObserverProxy> delegator_;
    int32_t SendTransactCmd(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_HIDDEN_START_OBSERVER_PROXY_H