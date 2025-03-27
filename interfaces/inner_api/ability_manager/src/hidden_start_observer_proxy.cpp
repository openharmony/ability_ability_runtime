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

#include "hidden_start_observer_proxy.h"

#include "hilog_tag_wrapper.h"
#include "ipc_types.h"


namespace OHOS {
namespace AAFwk {
HiddenStartObserverProxy::HiddenStartObserverProxy(
    const sptr<IRemoteObject> &impl) : IRemoteProxy<IHiddenStartObserver>(impl)
{}

bool HiddenStartObserverProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(HiddenStartObserverProxy::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write interface token failed");
        return false;
    }
    return true;
}

bool HiddenStartObserverProxy::IsHiddenStart(int32_t pid)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!WriteInterfaceToken(data)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "WriteInterfaceToken failed");
        return false;
    }
    data.WriteInt32(pid);
    int32_t ret = SendTransactCmd(
        static_cast<uint32_t>(IHiddenStartObserver::Message::TRANSACT_ON_IS_HIDDEN_START),
        data, reply, option);
    if (ret != NO_ERROR) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "SendRequest is failed, error code: %{public}d.", ret);
        return false;
    }
    return reply.ReadBool();
}

int32_t HiddenStartObserverProxy::SendTransactCmd(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Remote is nullptr.");
        return ERR_NULL_OBJECT;
    }

    return remote->SendRequest(code, data, reply, option);
}
} // namespace AAFwk
} // namespace OHOS