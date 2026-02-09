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

#ifndef OHOS_AGENT_RUNTIME_AGENT_CONNECTOR_STUB_H
#define OHOS_AGENT_RUNTIME_AGENT_CONNECTOR_STUB_H

#include <iremote_object.h>
#include <iremote_stub.h>

#include "iagent_connector.h"
#include "ipc_types.h"
#include "message_parcel.h"

namespace OHOS {
namespace AgentRuntime {

/**
 * @class AgentConnectorStub
 * Base stub class for agent connector IPC.
 * Corresponds to the server end of IAgentConnector.
 * Handles incoming IPC calls from host application to agent extension.
 */
class AgentConnectorStub : public IRemoteStub<IAgentConnector> {
public:
    AgentConnectorStub();
    virtual ~AgentConnectorStub();

    /**
     * Handle incoming remote request.
     *
     * @param code The command code.
     * @param data The request data parcel.
     * @param reply The reply parcel.
     * @param option The message option.
     * @return Returns ERR_OK on success, error code otherwise.
     */
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;

    /**
     * Handle SendData request from host application.
     *
     * @param data The request data parcel containing the data string.
     * @param reply The reply parcel.
     * @return Returns ERR_OK on success, error code otherwise.
     */
    int32_t OnSendData(MessageParcel &data, MessageParcel &reply);

    /**
     * Handle Authorize request from host application.
     *
     * @param data The request data parcel containing the authorization string.
     * @param reply The reply parcel.
     * @return Returns ERR_OK on success, error code otherwise.
     */
    int32_t OnAuthorize(MessageParcel &data, MessageParcel &reply);
};

} // namespace AgentRuntime
} // namespace OHOS

#endif // OHOS_AGENT_RUNTIME_AGENT_CONNECTOR_STUB_H
