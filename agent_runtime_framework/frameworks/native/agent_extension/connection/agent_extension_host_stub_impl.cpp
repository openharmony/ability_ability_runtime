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

#include "ability_business_error.h"
#include "agnet_extension_host_stub_impl.h"
#include "js_agent_extension_connection.h"

namespace OHOS {
namespace AgentRuntime {

AgentExtensionHostStubImpl::AgentExtensionHostStubImpl(wptr<JSAgentExtensionConnection> conn)
    :conn_(conn)
{
}

int32_t AgentExtensionHostStubImpl::SendData(std::string &data)
{
    sptr<JSAgentExtensionConnection> conn = conn_.promote();
    if (conn != nullptr) {
        return conn->OnSendData(data);
    }

    return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
}

}
}
