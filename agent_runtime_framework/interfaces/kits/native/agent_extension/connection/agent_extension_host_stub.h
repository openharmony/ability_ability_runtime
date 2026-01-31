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
#ifndef OHOS_AGENT_RUNTIME_AGENT_EXTENSION_HOST_PROXY_H
#define OHOS_AGENT_RUNTIME_AGENT_EXTENSION_HOST_PROXY_H

#include <map>

#include <iremote_object.h>
#include <iremote_stub.h>
#include "ipc_types.h"
#include "message_parcel.h"
#include "agent_extension_host_interface.h"

namespace OHOS {
namespace AgentRuntime {

class AgentExtensionHostStub : public IRemoteStub<IAgentExtensionHost> {
public:
    AgentExtensionHostStub();
    virtual ~AgentExtensionHostStub();

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

    int32_t OnSendData(MessageParcel& data, MessageParcel& reply);

protected:
    using RequestFuncType = int32_t (AgentExtensionHostStub::*)(MessageParcel& data, MessageParcel& reply);
    std::map<uint32_t, RequestFuncType> requestFuncMap_;
};

} // namespace AgentRuntime
} // namespace OHOS
#endif //OHOS_AGENT_RUNTIME_AGENT_EXTENSION_HOST_PROXY_H