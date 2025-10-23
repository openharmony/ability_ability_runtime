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

#include "foreground_app_connection_proxy.h"

#include "hilog_tag_wrapper.h"
#include "ipc_types.h"

namespace OHOS {
namespace AbilityRuntime {
void ForegroundAppConnectionProxy::OnForegroundAppConnected(const ForegroundAppConnectionData &connectionData)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(IForegroundAppConnection::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::CONNECTION, "Write token failed");
        return;
    }

    if (!data.WriteParcelable(&connectionData)) {
        TAG_LOGE(AAFwkTag::CONNECTION, "Write ConnectionData error");
        return;
    }

    int error = SendTransactCmd(IForegroundAppConnection::ON_FOREGROUND_APP_CONNECTED, data, reply, option);
    if (error != NO_ERROR) {
        TAG_LOGE(AAFwkTag::CONNECTION, "send request error: %{public}d", error);
    }
}

void ForegroundAppConnectionProxy::OnForegroundAppDisconnected(const ForegroundAppConnectionData &connectionData)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(IForegroundAppConnection::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::CONNECTION, "Write token failed");
        return;
    }

    if (!data.WriteParcelable(&connectionData)) {
        TAG_LOGE(AAFwkTag::CONNECTION, "Write ConnectionData error");
        return;
    }

    int error = SendTransactCmd(IForegroundAppConnection::ON_FOREGROUND_APP_DISCONNECTED, data, reply, option);
    if (error != NO_ERROR) {
        TAG_LOGE(AAFwkTag::CONNECTION, "send request error: %{public}d", error);
    }
}

void ForegroundAppConnectionProxy::OnForegroundAppCallerStarted(int32_t callerPid,
    int32_t callerUid, const std::string &bundleName)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(IForegroundAppConnection::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::CONNECTION, "Write token failed");
        return;
    }

    if (!data.WriteInt32(callerPid)) {
        TAG_LOGE(AAFwkTag::CONNECTION, "Write callerPid error");
        return;
    }

    if (!data.WriteInt32(callerUid)) {
        TAG_LOGE(AAFwkTag::CONNECTION, "Write callerUid error");
        return;
    }

    if (!data.WriteString(bundleName)) {
        TAG_LOGE(AAFwkTag::CONNECTION, "Write bundleName error");
        return;
    }

    int error = SendTransactCmd(IForegroundAppConnection::ON_FOREGROUND_APP_CALLER_STARTED, data, reply, option);
    if (error != NO_ERROR) {
        TAG_LOGE(AAFwkTag::CONNECTION, "send request error: %{public}d", error);
    }
}

int32_t ForegroundAppConnectionProxy::SendTransactCmd(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TAG_LOGE(AAFwkTag::CONNECTION, "null remote");
        return ERR_NULL_OBJECT;
    }

    int32_t ret = remote->SendRequest(code, data, reply, option);
    if (ret != NO_ERROR) {
        TAG_LOGE(AAFwkTag::CONNECTION, "SendRequest failed. code: %{public}d, ret: %{public}d.", code, ret);
        return ret;
    }
    return NO_ERROR;
}
}  // namespace AAFwk
}  // namespace OHOS
