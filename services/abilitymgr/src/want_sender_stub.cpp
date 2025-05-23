/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "want_sender_stub.h"

#include "hilog_tag_wrapper.h"
#include "ipc_types.h"

namespace OHOS {
namespace AAFwk {
WantSenderStub::WantSenderStub() {}

WantSenderStub::~WantSenderStub() {}

int WantSenderStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "cmd = %d, flags= %d", code, option.GetFlags());
    std::u16string descriptor = WantSenderStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "local descriptor invalid");
        return ERR_INVALID_STATE;
    }

    if (code == (WANT_SENDER_SEND)) {
        return SendInner(data, reply);
    }
    TAG_LOGW(AAFwkTag::WANTAGENT, "default case, need check");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int WantSenderStub::SendInner(MessageParcel &data, MessageParcel &reply)
{
    SenderInfo *senderInfo = data.ReadParcelable<SenderInfo>();
    if (senderInfo == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null senderInfo");
        return ERR_INVALID_VALUE;
    }
    Send(*senderInfo);
    delete senderInfo;
    return NO_ERROR;
}
}  // namespace AAFwk
}  // namespace OHOS
