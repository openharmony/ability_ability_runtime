/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "auto_startup_callback_proxy.h"

#include "ability_manager_errors.h"
#include "hilog_wrapper.h"
#include "ipc_types.h"
#include "message_parcel.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AAFwk;
void AutoStartupCallBackProxy::OnAutoStartupOn(const AutoStartupInfo &info)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(AutoStartupCallBackProxy::GetDescriptor())) {
        HILOG_ERROR("Write interface token failed.");
        return;
    }

    if (!data.WriteParcelable(&info)) {
        HILOG_ERROR("Write AutoStartupInfo failed.");
        return;
    }

    auto ret = SendRequest(AbilityManagerInterfaceCode::ON_AUTO_STARTUP_ON, data, reply, option);
    if (ret != NO_ERROR) {
        HILOG_ERROR("Send request error: %{public}d.", ret);
    }
}

void AutoStartupCallBackProxy::OnAutoStartupOff(const AutoStartupInfo &info)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(AutoStartupCallBackProxy::GetDescriptor())) {
        HILOG_ERROR("Write interface token failed.");
        return;
    }

    if (!data.WriteParcelable(&info)) {
        HILOG_ERROR("Write AutoStartupInfo failed.");
        return;
    }

    auto ret = SendRequest(AbilityManagerInterfaceCode::ON_AUTO_STARTUP_OFF, data, reply, option);
    if (ret != NO_ERROR) {
        HILOG_ERROR("Send request error: %{public}d.", ret);
    }
}

ErrCode AutoStartupCallBackProxy::SendRequest(
    AbilityManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOG_ERROR("Remote is nullptr.");
        return INNER_ERR;
    }

    return remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
}
} // namespace AbilityRuntime
} // namespace OHOS