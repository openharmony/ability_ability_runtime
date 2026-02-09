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

#include "js_agent_connector_stub_impl.h"

#include "js_agent_connection.h"
#include "js_error_utils.h"

namespace OHOS {
namespace AgentRuntime {

JsAgentConnectorStubImpl::JsAgentConnectorStubImpl(wptr<JSAgentConnection> conn)
    : conn_(conn)
{
}

int32_t JsAgentConnectorStubImpl::SendData(const std::string &data)
{
    sptr<JSAgentConnection> conn = conn_.promote();
    if (conn != nullptr) {
        return conn->OnSendData(data);
    }

    return static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
}

int32_t JsAgentConnectorStubImpl::Authorize(const std::string &data)
{
    sptr<JSAgentConnection> conn = conn_.promote();
    if (conn != nullptr) {
        return conn->OnAuthorize(data);
    }

    return static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
}

} // namespace AgentRuntime
} // namespace OHOS
