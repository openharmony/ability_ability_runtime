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

#ifndef OHOS_AGENT_RUNTIME_JSAGENT_EXTENSION_PROXY_H
#define OHOS_AGENT_RUNTIME_JSAGENT_EXTENSION_PROXY_H

#include <memory>

#include "agent_extension_proxy.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace AgentRuntime {
using namespace AbilityRuntime;

class JsAgentExtensionProxy {
public:
    static napi_value CreateJsAgentExtensionProxy(napi_env env, const sptr<IRemoteObject>& impl,
        int64_t connectionId, const sptr<IRemoteObject>& hostProxy);
    static void Finalizer(napi_env env, void* data, void* hint);

    JsAgentExtensionProxy(const sptr<IRemoteObject>& impl, const sptr<IRemoteObject>& hostProxy);
    virtual ~JsAgentExtensionProxy();

    void SetConnectionId(int64_t id) { connectionId_ = id; }
    int64_t GetConnectionId() { return connectionId_; }
private:
    static napi_value SendData(napi_env env, napi_callback_info info);
    napi_value OnSendData(napi_env env, NapiCallbackInfo& info);

protected:
    sptr<IAgentExtension> proxy_ = nullptr;
    int64_t connectionId_ = 0;
    sptr<IRemoteObject> hostProxy_ = nullptr;
};

} // namespace AgentRuntime
} // namespace OHOS
#endif //OHOS_AGENT_RUNTIME_JSAGENT_EXTENSION_PROXY_H