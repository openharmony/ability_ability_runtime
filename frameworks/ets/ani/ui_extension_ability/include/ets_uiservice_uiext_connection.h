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
#ifndef OHOS_ABILITY_RUNTIME_ETS_UISERVICE_UIEXT_CONNECTION_H
#define OHOS_ABILITY_RUNTIME_ETS_UISERVICE_UIEXT_CONNECTION_H

#include "ets_ui_extension_context.h"
#include "ets_ui_extension_servicehost_stub_impl.h"
#include "ui_service_host_stub.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsUIServiceUIExtConnection;
namespace ETSUIServiceConnection {
void AddUIServiceExtensionConnection(AAFwk::Want &want, sptr<EtsUIServiceUIExtConnection> &connection);
void RemoveUIServiceExtensionConnection(const int64_t &connectId);
void FindUIServiceExtensionConnection(const int64_t &connectId, AAFwk::Want& want,
    sptr<EtsUIServiceUIExtConnection> &connection);
void FindUIServiceExtensionConnection(ani_env *env, const AAFwk::Want &want, ani_object callback,
    sptr<EtsUIServiceUIExtConnection> &connection);
}

class EtsUIServiceUIExtConnection : public EtsUIExtensionConnection {
public:
    EtsUIServiceUIExtConnection(ani_vm *etsVm);
    ~EtsUIServiceUIExtConnection();
    virtual void HandleOnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override;
    virtual void HandleOnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;
    sptr<EtsUIExtensionServiceHostStubImpl> GetServiceHostStub() { return serviceHostStub_; }
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
    sptr<EtsUIExtensionServiceHostStubImpl> serviceHostStub_;
    ani_ref serviceProxyObject_;
    ani_ref aniAsyncCallback_;
    std::vector<ani_ref> duplicatedPendingCallbacks_;
};

} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_UISERVICE_UIEXT_CONNECTION_H
