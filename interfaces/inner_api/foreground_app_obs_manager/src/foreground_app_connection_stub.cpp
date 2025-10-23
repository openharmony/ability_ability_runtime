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

#include "foreground_app_connection_stub.h"

#include "hilog_tag_wrapper.h"
#include "ipc_types.h"

namespace OHOS {
namespace AbilityRuntime {
ForegroundAppConnectionStub::ForegroundAppConnectionStub() {}

int ForegroundAppConnectionStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::u16string descriptor = ForegroundAppConnectionStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        TAG_LOGI(AAFwkTag::CONNECTION, "invalid descriptor");
        return ERR_INVALID_STATE;
    }
    if (code < IForegroundAppConnection::CMD_MAX && code >= 0) {
        switch (code) {
            case ON_FOREGROUND_APP_CONNECTED:
                return OnForegroundAppConnectedInner(data, reply);
            case ON_FOREGROUND_APP_DISCONNECTED:
                return OnForegroundAppDisconnectedInner(data, reply);
            case ON_FOREGROUND_APP_CALLER_STARTED:
                return OnForegroundAppCallerStartedInner(data, reply);
        }
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int ForegroundAppConnectionStub::OnForegroundAppConnectedInner(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<ForegroundAppConnectionData> foregroundAppConnectionData(
        data.ReadParcelable<ForegroundAppConnectionData>());
    if (!foregroundAppConnectionData) {
        TAG_LOGE(AAFwkTag::CONNECTION, "error foregroundAppConnectionData");
        return ERR_INVALID_VALUE;
    }

    OnForegroundAppConnected(*foregroundAppConnectionData);
    return NO_ERROR;
}

int ForegroundAppConnectionStub::OnForegroundAppDisconnectedInner(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<ForegroundAppConnectionData> foregroundAppConnectionData(
        data.ReadParcelable<ForegroundAppConnectionData>());
    if (!foregroundAppConnectionData) {
        TAG_LOGE(AAFwkTag::CONNECTION, "error foregroundAppConnectionData");
        return ERR_INVALID_VALUE;
    }

    OnForegroundAppDisconnected(*foregroundAppConnectionData);
    return NO_ERROR;
}

int ForegroundAppConnectionStub::OnForegroundAppCallerStartedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t callerPid = data.ReadInt32();
    int32_t callerUid = data.ReadInt32();
    std::string bundleName = data.ReadString();

    OnForegroundAppCallerStarted(callerPid, callerUid, bundleName);
    return NO_ERROR;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
