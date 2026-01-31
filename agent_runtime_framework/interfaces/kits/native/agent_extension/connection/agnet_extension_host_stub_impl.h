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

#ifndef OHOS_AGENT_RUNTIME_AGENT_EXTENSION_HOST_STUB_IMPL_H
#define OHOS_AGENT_RUNTIME_AGENT_EXTENSION_HOST_STUB_IMPL_H

#include "js_agent_extension_connection.h"
#include "agent_extension_host_stub.h"

namespace OHOS {
namespace AgentRuntime {

class AgentExtensionHostStubImpl : public AgentExtensionHostStub {
public:
    AgentExtensionHostStubImpl(wptr<JSAgentExtensionConnection> conn);
    ~AgentExtensionHostStubImpl() = default;
    virtual int32_t SendData(std::string &data) override;

protected:
    wptr<JSAgentExtensionConnection> conn_;
};

} // namespace AgentRuntime
} // namespace OHOS
#endif //OHOS_AGENT_RUNTIME_AGENT_EXTENSION_HOST_STUB_IMPL_H
