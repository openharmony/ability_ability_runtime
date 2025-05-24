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

#include "ability_start_with_wait_observer_proxy.h"

#include "hilog_tag_wrapper.h"
#include "parcel_util.h"

namespace OHOS {
namespace AAFwk {
AbilityStartWithWaitObserverProxy::AbilityStartWithWaitObserverProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IAbilityStartWithWaitObserver>(impl) {}

bool AbilityStartWithWaitObserverProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(AbilityStartWithWaitObserverProxy::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Write token failed");
        return false;
    }
    return true;
}

int32_t AbilityStartWithWaitObserverProxy::NotifyAATerminateWait(
    const AbilityStartWithWaitObserverData &abilityStartWithWaitObserverData)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!WriteInterfaceToken(data)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Write Token failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!data.WriteParcelable(&abilityStartWithWaitObserverData)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write abilityFirstFrameStateData failed");
        return ERR_FLATTEN_OBJECT;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null remote");
        return ERR_NULL_OBJECT;
    }

    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(IAbilityStartWithWaitObserver::Message::NOTIFY_AA_TERMINATE_WAIT),
        data, reply, option);
    if (ret != NO_ERROR) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "SendRequest error: %{public}d", ret);
    }
    return ret;
}
} // namespace AAFwk
} // namespace OHOS