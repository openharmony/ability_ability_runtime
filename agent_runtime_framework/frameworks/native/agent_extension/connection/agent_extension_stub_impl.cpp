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
#include "agent_extension_stub_impl.h"

namespace OHOS {
namespace AgentRuntime {
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;

AgentExtensionStubImpl::AgentExtensionStubImpl(std::weak_ptr<JsAgentExtension>& ext)
    :extension_(ext)
{
}

AgentExtensionStubImpl::~AgentExtensionStubImpl()
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "~");
}

int32_t AgentExtensionStubImpl::SendData(sptr<IRemoteObject> hostProxy, std::string &data)
{
    auto sptr = extension_.lock();
    if (sptr) {
        return sptr->OnSendData(hostProxy, data);
    }
    return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
}

}
}