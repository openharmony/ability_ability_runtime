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

#include "agent_connector_stub.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AgentRuntime {

AgentConnectorStub::AgentConnectorStub()
{
}

AgentConnectorStub::~AgentConnectorStub()
{
}

int AgentConnectorStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "OnRemoteRequest, code: %{public}u", code);

    std::u16string descriptor = AgentConnectorStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Descriptor mismatch");
        return ERR_INVALID_STATE;
    }

    switch (code) {
        case IAgentConnector::SEND_DATA:
            return OnSendData(data, reply);
        case IAgentConnector::AUTHORIZE:
            return OnAuthorize(data, reply);
        default:
            TAG_LOGW(AAFwkTag::SER_ROUTER, "Unknown code: %{public}u", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t AgentConnectorStub::OnSendData(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "OnSendData called");

    std::string dataStr = data.ReadString();

    TAG_LOGD(AAFwkTag::SER_ROUTER, "OnSendData, data length: %{public}zu", dataStr.length());

    int32_t result = SendData(dataStr);
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Failed to write result to reply parcel");
        return IPC_STUB_ERR;
    }

    return NO_ERROR;
}

int32_t AgentConnectorStub::OnAuthorize(MessageParcel &data, MessageParcel &reply)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "OnAuthorize called");

    std::string authStr = data.ReadString();

    TAG_LOGD(AAFwkTag::SER_ROUTER, "OnAuthorize, auth length: %{public}zu", authStr.length());

    int32_t result = Authorize(authStr);
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Failed to write result to reply parcel");
        return IPC_STUB_ERR;
    }

    return NO_ERROR;
}

} // namespace AgentRuntime
} // namespace OHOS
