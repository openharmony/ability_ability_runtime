/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_AGENT_RUNTIME_JS_AGENT_EXTENSION_CONNECTION_H
#define OHOS_AGENT_RUNTIME_JS_AGENT_EXTENSION_CONNECTION_H

#include "agnet_extension_host_stub_impl.h"
#include "js_ability_context.h"
#include "want.h"

namespace OHOS {
namespace AgentRuntime {
using namespace OHOS::AbilityRuntime;
class JSAgentExtensionConnection;
class AgentExtensionHostStubImpl;

namespace AgentExtensionConnection {
void RemoveAgentExtensionConnection(int64_t connectId);
int64_t InsertAgentExtensionConnection(sptr<JSAgentExtensionConnection> connection, const AAFwk::Want &want);
void FindAgentExtensionConnection(const int64_t& connectId, AAFwk::Want& want,
    sptr<JSAgentExtensionConnection>& connection);
void FindAgentExtensionConnection(napi_env env, AAFwk::Want& want, napi_value callback,
    sptr<JSAgentExtensionConnection>& connection);
}

class JSAgentExtensionConnection : public AbilityRuntime::JSAbilityConnection {
public:
    JSAgentExtensionConnection(napi_env env);
    ~JSAgentExtensionConnection();
    virtual void HandleOnAbilityConnectDone(
        const OHOS::AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override;
    virtual void HandleOnAbilityDisconnectDone(const OHOS::AppExecFwk::ElementName &element, int resultCode) override;
    sptr<AgentExtensionHostStubImpl> GetServiceHostStub() { return serviceHostStub_; }
    void SetProxyObject(napi_value proxy);
    napi_value GetProxyObject();
    void SetNapiAsyncTask(std::shared_ptr<NapiAsyncTask>& task);
    void AddDuplicatedPendingTask(std::unique_ptr<NapiAsyncTask>& task);
    void ResolveDuplicatedPendingTask(napi_env env, napi_value proxy);
    void RejectDuplicatedPendingTask(napi_env env, napi_value error);
    int32_t OnSendData(std::string &data);
    void HandleOnSendData(const std::string &data);
    void CallJsOnDisconnect();
    static bool IsJsCallbackObjectEquals(napi_env env, std::unique_ptr<NativeReference>& callback, napi_value value);

private:
    sptr<AgentExtensionHostStubImpl> serviceHostStub_;
    std::shared_ptr<NapiAsyncTask> napiAsyncTask_;
    std::unique_ptr<NativeReference> serviceProxyObject_;
    std::vector<std::unique_ptr<NapiAsyncTask>> duplicatedPendingTaskList_;
};

} // namespace AgentRuntime
} // namespace OHOS
#endif //OHOS_AGENT_RUNTIME_JS_AGENT_EXTENSION_CONNECTION_H

