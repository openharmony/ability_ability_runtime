/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "load_ability_callback_stub.h"

#include "hilog_tag_wrapper.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
int LoadAbilityCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::u16string descriptor = LoadAbilityCallbackStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        TAG_LOGE(AAFwkTag::APPMGR, "local descriptor is not equal to remote.");
        return ERR_INVALID_STATE;
    }

    if (static_cast<Message>(code) == Message::TRANSACT_ON_FINISH) {
        return HandleOnFinish(data, reply);
    }
    TAG_LOGW(AAFwkTag::APPMGR, "LoadAbilityCallbackStub::OnRemoteRequest, default case, need check");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t LoadAbilityCallbackStub::HandleOnFinish(MessageParcel &data, MessageParcel &reply)
{
    int32_t pid = data.ReadInt32();
    OnFinish(pid);
    return NO_ERROR;
}
}  // namespace AppExecFwk
}  // namespace OHOS
