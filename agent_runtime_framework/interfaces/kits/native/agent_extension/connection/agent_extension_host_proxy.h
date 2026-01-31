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

#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "agent_extension_host_interface.h"

namespace OHOS {
namespace AgentRuntime {

class AgentExtensionHostProxy : public IRemoteProxy<IAgentExtensionHost> {
public:
    explicit AgentExtensionHostProxy(const sptr<IRemoteObject>& impl);
    virtual ~AgentExtensionHostProxy();

    virtual int32_t SendData(std::string &data) override;

private:
    static inline BrokerDelegator<AgentExtensionHostProxy> delegator_;
};
} // namespace AgentRuntime
} // namespace OHOS
#endif //OHOS_AGENT_RUNTIME_AGENT_EXTENSION_HOST_PROXY_H