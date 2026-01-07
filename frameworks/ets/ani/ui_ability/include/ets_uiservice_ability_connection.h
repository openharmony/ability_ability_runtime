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

#ifndef OHOS_ABILITY_RUNTIME_ETS_UISERVICE_ABILITY_CONNECTION_H
#define OHOS_ABILITY_RUNTIME_ETS_UISERVICE_ABILITY_CONNECTION_H

#include "ets_ability_context.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsUIServiceExtAbilityConnection;
namespace EtsUIServiceConnection {
void RemoveUIServiceAbilityConnection(int64_t connectId);
int64_t InsertUIServiceAbilityConnection(sptr<EtsUIServiceExtAbilityConnection> connection, const AAFwk::Want& want);
void FindUIServiceAbilityConnection(const int64_t& connectId, AAFwk::Want& want,
    sptr<EtsUIServiceExtAbilityConnection>& connection);
void FindUIServiceAbilityConnection(ani_env *env, const AAFwk::Want &want, ani_object callback,
    sptr<EtsUIServiceExtAbilityConnection> &connection);
}  // namespace EtsUIServiceConnection

class EtsUIAbilityServiceHostStubImpl;
class EtsUIServiceExtAbilityConnection : public ETSAbilityConnection {
public:
    EtsUIServiceExtAbilityConnection(ani_vm *etsVm);
    ~EtsUIServiceExtAbilityConnection();
    virtual void HandleOnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override;
    virtual void HandleOnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;
    sptr<EtsUIAbilityServiceHostStubImpl> GetServiceHostStub() { return serviceHostStub_; }
    void SetProxyObject(ani_object proxy);
    ani_ref GetProxyObject();
    void SetAniAsyncCallback_(ani_object myCallback);
    void ResolveDuplicatedPendingCallbacks(ani_env *env, ani_object proxyObj);
    void AddDuplicatedPendingCallback(ani_object myCallback);
    void RejectDuplicatedPendingCallbacks(ani_env *env, int32_t error);
    int32_t OnSendData(AAFwk::WantParams &data);
    void HandleOnSendData(const AAFwk::WantParams &data);
    static bool IsEtsCallbackObjectEquals(ani_env *env, ani_ref callback, ani_object value);
private:
    void ReleaseReference(ani_env *env, ani_ref etsObjRef);
    void CallObjectMethod(ani_env *env, const char *methodName, const char *signature, ...);
    sptr<EtsUIAbilityServiceHostStubImpl> serviceHostStub_;
    ani_ref serviceProxyObject_ = nullptr;
    ani_ref aniAsyncCallback_ = nullptr;
    std::vector<ani_ref> duplicatedPendingCallbacks_;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_UISERVICE_ABILITY_CONNECTION_H

