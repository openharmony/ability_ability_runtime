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

#ifndef OHOS_AGENT_RUNTIME_AGENT_CONNECTOR_PROXY_H
#define OHOS_AGENT_RUNTIME_AGENT_CONNECTOR_PROXY_H

#include <iremote_broker.h>
#include <iremote_object.h>
#include <iremote_proxy.h>

#include "iagent_connector.h"

namespace OHOS {
namespace AgentRuntime {

/**
 * @class AgentConnectorProxy
 * Proxy class for making IPC calls to host application from agent extension.
 * Corresponds to the client end of IAgentConnector.
 */
class AgentConnectorProxy : public IRemoteProxy<IAgentConnector> {
public:
    /**
     * Constructor.
     *
     * @param impl The remote object implementation.
     */
    explicit AgentConnectorProxy(const sptr<IRemoteObject> &impl);
    virtual ~AgentConnectorProxy();

    /**
     * Send data to host application.
     *
     * @param data The string data to send.
     * @return Returns 0 on success, error code otherwise.
     */
    virtual int32_t SendData(const std::string &data) override;

    /**
     * Send authorization to host application.
     *
     * @param data The authorization string to send.
     * @return Returns 0 on success, error code otherwise.
     */
    virtual int32_t Authorize(const std::string &data) override;

private:
    static inline BrokerDelegator<AgentConnectorProxy> delegator_;
};

} // namespace AgentRuntime
} // namespace OHOS

#endif // OHOS_AGENT_RUNTIME_AGENT_CONNECTOR_PROXY_H
