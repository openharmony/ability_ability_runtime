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

#include "ability_start_with_wait_observer_stub.h"

#include "ability_manager_errors.h"
#include "hilog_tag_wrapper.h"
#include "appexecfwk_errors.h"

namespace OHOS {
namespace AAFwk {

int32_t AbilityStartWithWaitObserverStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "msgCode:%{public}d", code);
    std::u16string descriptor = AbilityStartWithWaitObserverStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid descriptor");
        return ERR_INVALID_STATE;
    }
    if (code == static_cast<uint32_t>(IAbilityStartWithWaitObserver::Message::NOTIFY_AA_TERMINATE_WAIT)) {
        return OnNotifyAATerminateWithWait(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AbilityStartWithWaitObserverStub::OnNotifyAATerminateWithWait(MessageParcel& data, MessageParcel& reply)
{
    std::unique_ptr<AbilityStartWithWaitObserverData> info(data.ReadParcelable<AbilityStartWithWaitObserverData>());
    if (!info) {
        TAG_LOGE(AAFwkTag::APPMGR, "ReadParcelable<info> failed");
        return ERR_AAFWK_PARCEL_FAIL;
    }
    int32_t result = NotifyAATerminateWait(*info);
    if (!reply.WriteInt32(result)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write result failed");
        return IPC_STUB_ERR;
    }
    return ERR_OK;
}

AbilityStartWithWaitObserverRecipient::AbilityStartWithWaitObserverRecipient(RemoteDiedHandler handler)
    : handler_(handler)
{}

void AbilityStartWithWaitObserverRecipient::OnRemoteDied(const wptr<IRemoteObject> &__attribute__((unused)) remote)
{
    TAG_LOGE(AAFwkTag::ABILITYMGR, "Remote died");
    if (handler_) {
        handler_(remote);
    }
}
} // namespace AAFwk
} // namespace OHOS