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

#include "agent_extension_host_stub.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AgentRuntime {

AgentExtensionHostStub::AgentExtensionHostStub()
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "called");
    requestFuncMap_[SEND_DATA] = &AgentExtensionHostStub::OnSendData;
}

AgentExtensionHostStub::~AgentExtensionHostStub()
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "called");
    requestFuncMap_.clear();
}

int AgentExtensionHostStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption& option)
{
    std::u16string descriptor = AgentExtensionHostStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        return ERR_INVALID_STATE;
    }
    auto itFunc = requestFuncMap_.find(code);
    if (itFunc != requestFuncMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return (this->*requestFunc)(data, reply);
        }
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AgentExtensionHostStub::OnSendData(MessageParcel& data, MessageParcel& reply)
{
    std::string dataParam = data.ReadString();
    int32_t result = SendData(dataParam);
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write result failed");
        return IPC_STUB_ERR;
    }
    return NO_ERROR;
}
}
}
