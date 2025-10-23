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

#ifndef OHOS_ABILITYRUNTIME_FOREGROUND_APP_CONNECTION_PROXY_H
#define OHOS_ABILITYRUNTIME_FOREGROUND_APP_CONNECTION_PROXY_H

#include "iforeground_app_connection.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * interface for connection observer.
 */
class ForegroundAppConnectionProxy : public IRemoteProxy<IForegroundAppConnection> {
public:
    explicit ForegroundAppConnectionProxy(sptr<IRemoteObject> impl)
        : IRemoteProxy<IForegroundAppConnection>(impl) {}

    virtual ~ForegroundAppConnectionProxy() = default;

    virtual void OnForegroundAppConnected(const ForegroundAppConnectionData &connectionData) override;

    virtual void OnForegroundAppDisconnected(const ForegroundAppConnectionData &connectionData) override;

    virtual void OnForegroundAppCallerStarted(int32_t callerPid, int32_t callerUid,
        const std::string &bundleName) override;

private:
    static inline BrokerDelegator<ForegroundAppConnectionProxy> delegator_;
    int SendTransactCmd(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITYRUNTIME_FOREGROUND_APP_CONNECTION_PROXY_H
