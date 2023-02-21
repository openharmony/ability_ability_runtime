/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "dataobs_mgr_proxy.h"

#include "errors.h"
#include "hilog_wrapper.h"
#include "dataobs_mgr_errors.h"

namespace OHOS {
namespace AAFwk {
bool DataObsManagerProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(DataObsManagerProxy::GetDescriptor())) {
        HILOG_ERROR("write interface token failed");
        return false;
    }
    return true;
}

int32_t DataObsManagerProxy::RegisterObserver(const Uri &uri, const sptr<IDataAbilityObserver> &dataObserver)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        return IPC_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&uri)) {
        HILOG_ERROR("register observer fail, uri error");
        return INVALID_PARAM;
    }
    if (dataObserver == nullptr) {
        HILOG_ERROR("register observer fail, dataObserver is nullptr");
        return INVALID_PARAM;
    }

    if (!data.WriteRemoteObject(dataObserver->AsObject())) {
        HILOG_ERROR("register observer fail, dataObserver error");
        return INVALID_PARAM;
    }

    auto error = Remote()->SendRequest(IDataObsMgr::REGISTER_OBSERVER, data, reply, option);
    if (error != 0) {
        HILOG_ERROR("register observer fail, error: %d", error);
        return error;
    }

    return static_cast<Status>(reply.ReadInt32());
}

int32_t DataObsManagerProxy::UnregisterObserver(const Uri &uri, const sptr<IDataAbilityObserver> &dataObserver)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        return IPC_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&uri)) {
        HILOG_ERROR("unregister observer fail, uri error");
        return INVALID_PARAM;
    }
    if (dataObserver == nullptr) {
        HILOG_ERROR("unregister observer fail, dataObserver is nullptr");
        return INVALID_PARAM;
    }

    if (!data.WriteRemoteObject(dataObserver->AsObject())) {
        HILOG_ERROR("unregister observer fail, dataObserver error");
        return INVALID_PARAM;
    }

    auto error = Remote()->SendRequest(IDataObsMgr::UNREGISTER_OBSERVER, data, reply, option);
    if (error != 0) {
        HILOG_ERROR("unregister observer fail, error: %d", error);
        return error;
    }
    return reply.ReadInt32();
}

int32_t DataObsManagerProxy::NotifyChange(const Uri &uri)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        return IPC_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&uri)) {
        HILOG_ERROR("notifyChange fail, uri error");
        return INVALID_PARAM;
    }

    auto error = Remote()->SendRequest(IDataObsMgr::NOTIFY_CHANGE, data, reply, option);
    if (error != 0) {
        HILOG_ERROR("notifyChange fail, error: %d", error);
        return IPC_ERROR;
    }
    return static_cast<Status>(reply.ReadInt32());
}

Status DataObsManagerProxy::RegisterObserverExt(const Uri &uri, const sptr<IDataAbilityObserver> &dataObserver, bool isDescendants)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        return IPC_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&uri)) {
        HILOG_ERROR("register observer fail, uri error");
        return INVALID_PARAM;
    }

    if (dataObserver == nullptr) {
        HILOG_ERROR("register observer fail, dataObserver is nullptr");
        return INVALID_PARAM;
    }

    if (!data.WriteRemoteObject(dataObserver->AsObject())) {
        HILOG_ERROR("register observer fail, dataObserver error");
        return INVALID_PARAM;
    }

    if (!data.WriteBool(isDescendants)) {
        HILOG_ERROR("register observer fail, isDescendants error");
        return INVALID_PARAM;
    }

    auto error = Remote()->SendRequest(IDataObsMgr::REGISTER_OBSERVER_EXT, data, reply, option);
    if (error != 0) {
        HILOG_ERROR("register observer fail, error: %d", error);
        return IPC_ERROR;
    }
    return static_cast<Status>(reply.ReadInt32());
}

Status DataObsManagerProxy::UnregisterObserverExt(const sptr<IDataAbilityObserver> &dataObserver)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        return IPC_PARCEL_ERROR;
    }

    if (dataObserver == nullptr) {
        HILOG_ERROR("unregister observer fail, dataObserver is nullptr");
        return INVALID_PARAM;
    }

    if (!data.WriteRemoteObject(dataObserver->AsObject())) {
        HILOG_ERROR("unregister observer fail, dataObserver error");
        return INVALID_PARAM;
    }

    auto error = Remote()->SendRequest(IDataObsMgr::UNREGISTER_OBSERVER_EXT, data, reply, option);
    if (error != 0) {
        HILOG_ERROR("unregister observer fail, error: %d", error);
        return IPC_ERROR;
    }
    return static_cast<Status>(reply.ReadInt32());
}

Status DataObsManagerProxy::NotifyChangeExt(const std::list<Uri> &uris)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        return IPC_PARCEL_ERROR;
    }

    if (!data.WriteInt32(static_cast<int>(uris.size()))) {
        HILOG_ERROR("notifyChange fail, uris error");
        return INVALID_PARAM;
    }

    for (const auto &uri : uris) {
        if (!data.WriteParcelable(&uri)) {
            HILOG_ERROR("notifyChange fail, uri error");
            return INVALID_PARAM;
        }
    }

    auto error = Remote()->SendRequest(IDataObsMgr::NOTIFY_CHANGE_EXT, data, reply, option);
    if (error != 0) {
        HILOG_ERROR("notifyChange fail, error: %d", error);
        return IPC_ERROR;
    }
    return static_cast<Status>(reply.ReadInt32());
}
}  // namespace AAFwk
}  // namespace OHOS
