/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "ability_manager_errors.h"
#include "ability_manager_ipc_interface_code.h"
#include "extension_manager_proxy.h"
#include "extension_running_info.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "message_parcel.h"
#include "want.h"

namespace OHOS::AAFwk {
constexpr int32_t CYCLE_LIMIT = 1000;
bool ExtensionManagerProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(ExtensionManagerProxy::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::EXTMGR, "write token failed");
        return false;
    }
    return true;
}

int ExtensionManagerProxy::ConnectAbilityCommon(const Want &want, sptr<IRemoteObject> connect,
    const sptr<IRemoteObject> &callerToken, AppExecFwk::ExtensionAbilityType extensionType, int32_t userId,
    bool isQueryExtensionOnly)
{
    if (connect == nullptr) {
        TAG_LOGE(AAFwkTag::EXTMGR, "null connect");
        return CONNECTION_NOT_EXIST;
    }

    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        return INVALID_PARAMETERS_ERR;
    }
    if (!data.WriteParcelable(&want)) {
        TAG_LOGE(AAFwkTag::EXTMGR, "want write failed");
        return INVALID_PARAMETERS_ERR;
    }
    if (!data.WriteBool(true) || !data.WriteRemoteObject(connect)) {
        TAG_LOGE(AAFwkTag::EXTMGR, "flag or connect write failed");
        return INVALID_PARAMETERS_ERR;
    }
    if (callerToken) {
        if (!data.WriteBool(true) || !data.WriteRemoteObject(callerToken)) {
            TAG_LOGE(AAFwkTag::EXTMGR, "flag or callerToken write failed");
            return INVALID_PARAMETERS_ERR;
        }
    } else {
        if (!data.WriteBool(false)) {
            TAG_LOGE(AAFwkTag::EXTMGR, "flag write failed");
            return INVALID_PARAMETERS_ERR;
        }
    }
    if (!data.WriteInt32(userId)) {
        TAG_LOGE(AAFwkTag::EXTMGR, "userId write failed.");
        return INVALID_PARAMETERS_ERR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(extensionType))) {
        TAG_LOGE(AAFwkTag::EXTMGR, "extensionType write failed.");
        return INVALID_PARAMETERS_ERR;
    }
    if (!data.WriteBool(isQueryExtensionOnly)) {
        TAG_LOGE(AAFwkTag::EXTMGR, "isQueryExtensionOnly write failed");
        return INVALID_PARAMETERS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendRequest(AbilityManagerInterfaceCode::CONNECT_ABILITY_WITH_TYPE, data, reply, option);
    if (error != NO_ERROR) {
        TAG_LOGE(AAFwkTag::EXTMGR, "Send request error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

int ExtensionManagerProxy::DisconnectAbility(const sptr<IRemoteObject> &connect)
{
    if (connect == nullptr) {
        TAG_LOGE(AAFwkTag::EXTMGR, "disconnect ability failed");
        return INVALID_PARAMETERS_ERR;
    }

    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        return INVALID_PARAMETERS_ERR;
    }
    if (!data.WriteRemoteObject(connect)) {
        TAG_LOGE(AAFwkTag::EXTMGR, "connect write failed");
        return INVALID_PARAMETERS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    auto error = SendRequest(AbilityManagerInterfaceCode::DISCONNECT_ABILITY, data, reply, option);
    if (error != NO_ERROR) {
        TAG_LOGE(AAFwkTag::EXTMGR, "Send request error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

ErrCode ExtensionManagerProxy::SendRequest(AbilityManagerInterfaceCode code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    auto remote = Remote();
    if (remote == nullptr) {
        TAG_LOGE(AAFwkTag::EXTMGR, "null remote");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    return remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
}

int32_t ExtensionManagerProxy::StartExtensionAbility(const Want &want, const sptr<IRemoteObject> &callerToken,
    int32_t userId, AppExecFwk::ExtensionAbilityType extensionType)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    int error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return INVALID_PARAMETERS_ERR;
    }
    if (!data.WriteParcelable(&want)) {
        TAG_LOGE(AAFwkTag::EXTMGR, "want write fail");
        return INVALID_PARAMETERS_ERR;
    }
    if (callerToken) {
        if (!data.WriteBool(true) || !data.WriteRemoteObject(callerToken)) {
            TAG_LOGE(AAFwkTag::EXTMGR, "flag and callerToken write fail");
            return INVALID_PARAMETERS_ERR;
        }
    } else {
        if (!data.WriteBool(false)) {
            TAG_LOGE(AAFwkTag::EXTMGR, "flag write fail");
            return INVALID_PARAMETERS_ERR;
        }
    }
    if (!data.WriteInt32(userId)) {
        TAG_LOGE(AAFwkTag::EXTMGR, "userId write failed");
        return INVALID_PARAMETERS_ERR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(extensionType))) {
        TAG_LOGE(AAFwkTag::EXTMGR, "extensionType write failed");
        return INVALID_PARAMETERS_ERR;
    }
    error = SendRequest(AbilityManagerInterfaceCode::START_EXTENSION_ABILITY, data, reply, option);
    if (error != NO_ERROR) {
        TAG_LOGE(AAFwkTag::EXTMGR, "request error:%{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

int ExtensionManagerProxy::StopExtensionAbility(const Want &want, const sptr<IRemoteObject> &callerToken,
    int32_t userId, AppExecFwk::ExtensionAbilityType extensionType)
{
    int error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return INVALID_PARAMETERS_ERR;
    }
    if (!data.WriteParcelable(&want)) {
        TAG_LOGE(AAFwkTag::EXTMGR, "want write fail");
        return INVALID_PARAMETERS_ERR;
    }
    if (callerToken) {
        if (!data.WriteBool(true) || !data.WriteRemoteObject(callerToken)) {
            TAG_LOGE(AAFwkTag::EXTMGR, "flag and callerToken write fail");
            return INVALID_PARAMETERS_ERR;
        }
    } else {
        if (!data.WriteBool(false)) {
            TAG_LOGE(AAFwkTag::EXTMGR, "flag write fail");
            return INVALID_PARAMETERS_ERR;
        }
    }
    if (!data.WriteInt32(userId)) {
        TAG_LOGE(AAFwkTag::EXTMGR, "userId write fail");
        return INVALID_PARAMETERS_ERR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(extensionType))) {
        TAG_LOGE(AAFwkTag::EXTMGR, "writeInt32 fail");
        return INVALID_PARAMETERS_ERR;
    }
    error = SendRequest(AbilityManagerInterfaceCode::STOP_EXTENSION_ABILITY, data, reply, option);
    if (error != NO_ERROR) {
        TAG_LOGE(AAFwkTag::EXTMGR, "request error:%{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

template <typename T>
int ExtensionManagerProxy::GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos)
{
    int32_t infoSize = reply.ReadInt32();
    if (infoSize > CYCLE_LIMIT) {
        TAG_LOGE(AAFwkTag::EXTMGR, "infoSize large");
        return INVALID_PARAMETERS_ERR;
    }

    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (!info) {
            TAG_LOGE(AAFwkTag::EXTMGR, "readParcelableInfos fail");
            return INVALID_PARAMETERS_ERR;
        }
        parcelableInfos.emplace_back(*info);
    }
    return NO_ERROR;
}

int ExtensionManagerProxy::GetExtensionRunningInfos(int upperLimit, std::vector<ExtensionRunningInfo> &info)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        return INVALID_PARAMETERS_ERR;
    }

    if (!data.WriteInt32(upperLimit)) {
        TAG_LOGE(AAFwkTag::EXTMGR, "upperLimit write fail");
        return INVALID_PARAMETERS_ERR;
    }

    auto error = SendRequest(AbilityManagerInterfaceCode::GET_EXTENSION_RUNNING_INFO, data, reply, option);
    if (error != NO_ERROR) {
        TAG_LOGE(AAFwkTag::EXTMGR, "request error:%{public}d", error);
        return error;
    }
    error = GetParcelableInfos<ExtensionRunningInfo>(reply, info);
    if (error != NO_ERROR) {
        TAG_LOGE(AAFwkTag::EXTMGR, "getParcelableInfos fail, error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

int32_t ExtensionManagerProxy::TransferAbilityResultForExtension(const sptr<IRemoteObject> &callerToken,
    int32_t resultCode, const Want &want)
{
    if (callerToken == nullptr) {
        TAG_LOGE(AAFwkTag::EXTMGR, "null callerToken");
        return INVALID_PARAMETERS_ERR;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return INVALID_PARAMETERS_ERR;
    }
    if (!data.WriteRemoteObject(callerToken) || !data.WriteInt32(resultCode)) {
        TAG_LOGE(AAFwkTag::EXTMGR, "callerToken or resultCode write fail");
        return INVALID_PARAMETERS_ERR;
    }
    if (!data.WriteParcelable(&want)) {
        TAG_LOGE(AAFwkTag::EXTMGR, "want write fail");
        return INVALID_PARAMETERS_ERR;
    }
    auto error = SendRequest(AbilityManagerInterfaceCode::TRANSFER_ABILITY_RESULT, data, reply, option);
    if (error != NO_ERROR) {
        TAG_LOGE(AAFwkTag::EXTMGR, "request error:%{public}d", error);
        return error;
    }
    return NO_ERROR;
}
}  // namespace OHOS::AAFwk
