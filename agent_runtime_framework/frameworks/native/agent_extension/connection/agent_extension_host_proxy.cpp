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

#include "agent_extension_host_proxy.h"

#include "ability_business_error.h"
#include "ability_manager_ipc_interface_code.h"
#include "ipc_types.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AgentRuntime {
using namespace AbilityRuntime;

AgentExtensionHostProxy::AgentExtensionHostProxy(const sptr<IRemoteObject>& impl)
    :IRemoteProxy<IAgentExtensionHost>(impl)
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "called");
}

AgentExtensionHostProxy::~AgentExtensionHostProxy()
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "called");
}

int32_t AgentExtensionHostProxy::SendData(std::string &data)
{
    MessageParcel parcelData;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!parcelData.WriteInterfaceToken(AgentExtensionHostProxy::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write interface token failed");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }
    if (!parcelData.WriteString(data)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write data failed");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }
    sptr<IRemoteObject> remoteObject = Remote();
    if (remoteObject == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null remoteObject");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }
    auto error = remoteObject->SendRequest(
        static_cast<uint32_t>(AgentExtensionHostProxy::SEND_DATA), parcelData, reply, option);
    if (error != ERR_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "error %{public}d", error);
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }
    return ERR_OK;
}
}
}
