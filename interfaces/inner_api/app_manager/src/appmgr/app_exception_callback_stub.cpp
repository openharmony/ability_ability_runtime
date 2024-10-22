/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "app_exception_callback_stub.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
int32_t AppExceptionCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::u16string descriptor = AppExceptionCallbackStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        TAG_LOGE(AAFwkTag::APPMGR, "local descriptor is not equal to remote");
        return ERR_INVALID_STATE;
    }

    switch (code) {
        case static_cast<uint32_t>(IAppExceptionCallback::Message::LIFECYCLE_EXCEPTION_MSG_ID):
            return HandleLifecycleException(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t AppExceptionCallbackStub::HandleLifecycleException(MessageParcel &data, MessageParcel &reply)
{
    auto type = data.ReadInt32();
    if (type < 0 || type > static_cast<int32_t>(LifecycleException::END)) {
        return ERR_INVALID_STATE;
    }
    auto lifecycleExceptType = static_cast<LifecycleException>(type);
    sptr<IRemoteObject> token;
    if (data.ReadBool()) {
        token = data.ReadRemoteObject();
    }
    OnLifecycleException(lifecycleExceptType, token);
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
