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
#include "app_running_status_proxy.h"

#include "app_running_status_listener_interface.h"
#include "hilog_wrapper.h"
#include "ipc_types.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AbilityRuntime {
void AppRunningStatusProxy::NotifyAppRunningStatus(const std::string &bundle, int32_t &uid, int32_t runningStatus)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(AppRunningStatusProxy::GetDescriptor())) {
        HILOG_ERROR("Write interface token failed.");
        return;
    }
    if (!data.WriteString(bundle) || !data.WriteInt32(uid) || !data.WriteBool(runningStatus)) {
        HILOG_ERROR("Write data failed.");
        return;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOG_ERROR("Remote is nullptr.");
        return;
    }
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(IAppRunningStatusListener::MessageCode::APP_RUNNING_STATUS), data, reply, option);
    if (ret != NO_ERROR) {
        HILOG_WARN("SendRequest is failed, error code: %{public}d", ret);
        return;
    }
}
} // namespace AbilityRuntime
} // namespace OHOS