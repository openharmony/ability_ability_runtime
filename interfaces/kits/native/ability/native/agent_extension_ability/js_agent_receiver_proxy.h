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

#ifndef OHOS_AGENT_RUNTIME_JS_AGENT_RECEIVER_PROXY_H
#define OHOS_AGENT_RUNTIME_JS_AGENT_RECEIVER_PROXY_H

#include <memory>

#include "agent_receiver_proxy.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace AgentRuntime {
using namespace AbilityRuntime;

/**
 * @class JsAgentReceiverProxy
 * JavaScript proxy class for Agent Receiver.
 * Binds to JS class AgentReceiverProxy, used on host side
 * to send calls from host to agent extension (receiver).
 */
class JsAgentReceiverProxy {
public:
    /**
     * Create a JavaScript receiver proxy object.
     *
     * @param env The N-API environment.
     * @param impl The remote object implementation.
     * @param connectionId The connection ID.
     * @param connectorProxy The connector proxy object for callbacks.
     * @return Returns the N-API value of the created proxy object.
     */
    static napi_value CreateJsAgentReceiverProxy(napi_env env,
        const sptr<IRemoteObject> &impl,
        int64_t connectionId,
        const sptr<IRemoteObject> &connectorProxy);

    /**
     * Finalizer for the receiver proxy object.
     *
     * @param env The N-API environment.
     * @param data The pointer to the JsAgentReceiverProxy instance.
     * @param hint The hint data.
     */
    static void Finalizer(napi_env env, void *data, void *hint);

    /**
     * Constructor.
     *
     * @param impl The remote object implementation.
     * @param connectorProxy The connector proxy object.
     */
    JsAgentReceiverProxy(const sptr<IRemoteObject> &impl, const sptr<IRemoteObject> &connectorProxy);

    /**
     * Destructor.
     */
    virtual ~JsAgentReceiverProxy();

    /**
     * Set the connection ID.
     *
     * @param id The connection ID.
     */
    void SetConnectionId(int64_t id) { connectionId_ = id; }

    /**
     * Get the connection ID.
     *
     * @return Returns the connection ID.
     */
    int64_t GetConnectionId() { return connectionId_; }

private:
    /**
     * N-API callback for sendData method.
     *
     * @param env The N-API environment.
     * @param info The N-API callback info.
     * @return Returns the N-API value (undefined).
     */
    static napi_value SendData(napi_env env, napi_callback_info info);

    /**
     * N-API callback for authorize method.
     *
     * @param env The N-API environment.
     * @param info The N-API callback info.
     * @return Returns the N-API value (undefined).
     */
    static napi_value Authorize(napi_env env, napi_callback_info info);

    /**
     * Implementation of sendData method.
     *
     * @param env The N-API environment.
     * @param info The N-API callback info.
     * @return Returns the N-API value (undefined).
     */
    napi_value OnSendData(napi_env env, NapiCallbackInfo &info);

    /**
     * Implementation of authorize method.
     *
     * @param env The N-API environment.
     * @param info The N-API callback info.
     * @return Returns the N-API value (undefined).
     */
    napi_value OnAuthorize(napi_env env, NapiCallbackInfo &info);

protected:
    /**
     * The native proxy for IPC communication with agent extension.
     */
    sptr<IAgentReceiver> proxy_ = nullptr;

    /**
     * The connection ID for this proxy.
     */
    int64_t connectionId_ = 0;

    /**
     * The connector proxy object for agent extension to call back.
     */
    sptr<IRemoteObject> connectorProxy_ = nullptr;
};

} // namespace AgentRuntime
} // namespace OHOS

#endif // OHOS_AGENT_RUNTIME_JS_AGENT_RECEIVER_PROXY_H
