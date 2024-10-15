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

#ifndef OHOS_ABILITY_RUNTIME_APP_EXCEPTION_CALLBACK_PROXY_H
#define OHOS_ABILITY_RUNTIME_APP_EXCEPTION_CALLBACK_PROXY_H

#include "iapp_exception_callback.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AppExecFwk {
class AppExceptionCallbackProxy : public IRemoteProxy<IAppExceptionCallback> {
public:
    explicit AppExceptionCallbackProxy(const sptr<IRemoteObject> &impl);
    virtual ~AppExceptionCallbackProxy() = default;

    /**
     * Notify abilityManager lifecycle exception.
     *
     * @param type lifecycle failed type
     * @param token associated ability
     */
    virtual void OnLifecycleException(LifecycleException type, sptr<IRemoteObject> token);
private:
    bool WriteInterfaceToken(MessageParcel &data);
    static inline BrokerDelegator<AppExceptionCallbackProxy> delegator_;
    int32_t SendTransactCmd(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APP_EXCEPTION_CALLBACK_PROXY_H
