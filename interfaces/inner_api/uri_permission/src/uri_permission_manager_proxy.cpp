/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "uri_permission_manager_proxy.h"

#include "ability_manager_errors.h"
#include "hilog_tag_wrapper.h"
#include "parcel.h"
#include "securec.h"

namespace OHOS {
namespace AAFwk {
namespace {
const int MAX_URI_COUNT = 200000;
constexpr size_t MAX_IPC_RAW_DATA_SIZE = 128 * 1024 * 1024; // 128M
constexpr int32_t MAX_PARCEL_IPC_DATA_SIZE = 200 * 1024; // 200K

inline size_t GetPadSize(size_t size)
{
    const size_t offset = 3;
    return (((size + offset) & (~offset)) - size);
}

bool CheckUseRawData(const std::vector<std::string> &uriVec)
{
    size_t oriSize = sizeof(int32_t);
    for (auto &uri : uriVec) {
        // calculate ipc data size of string uri, reference to parcel.h
        size_t desire = uri.length() + sizeof(char) + sizeof(int32_t);
        size_t padSize = GetPadSize(desire);
        oriSize += (desire + padSize);
        if (oriSize > MAX_PARCEL_IPC_DATA_SIZE) {
            TAG_LOGI(AAFwkTag::URIPERMMGR, "use raw data %{public}d", static_cast<int32_t>(oriSize));
            return true;
        }
    }
    return false;
}

bool GetData(void *&buffer, size_t size, const void *data)
{
    if (data == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "null data");
        return false;
    }
    if (size == 0 || size > MAX_IPC_RAW_DATA_SIZE) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "size invalid: %{public}zu", size);
        return false;
    }
    buffer = malloc(size);
    if (buffer == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "malloc buffer failed");
        return false;
    }
    if (memcpy_s(buffer, size, data, size) != EOK) {
        free(buffer);
        TAG_LOGE(AAFwkTag::URIPERMMGR, "memcpy failed");
        return false;
    }
    return true;
}

bool WriteStringUriByRawData(MessageParcel &data, const std::vector<std::string> &uriVec)
{
    MessageParcel tempParcel;
    tempParcel.SetMaxCapacity(MAX_IPC_RAW_DATA_SIZE);
    if (!tempParcel.WriteStringVector(uriVec)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write uris failed");
        return false;
    }
    size_t dataSize = tempParcel.GetDataSize();
    if (!data.WriteInt32(static_cast<int32_t>(dataSize))) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write data size failed");
        return false;
    }
    if (!data.WriteRawData(reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write raw data failed");
        return false;
    }
    return true;
}

bool WriteStringUris(MessageParcel &data, const std::vector<std::string> &uriVec)
{
    bool isWriteUriByRawData = CheckUseRawData(uriVec);
    if (!data.WriteBool(isWriteUriByRawData)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "write bool failed");
        return false;
    }
    if (isWriteUriByRawData) {
        // write uris by raw data
        return WriteStringUriByRawData(data, uriVec);
    }
    // write uris by parcel
    return data.WriteStringVector(uriVec);
}

bool ReadBatchResultByRawData(MessageParcel &data, std::vector<bool> &result)
{
    size_t dataSize = static_cast<size_t>(data.ReadInt32());
    if (dataSize == 0) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "parcel no data");
        return false;
    }

    void *buffer = nullptr;
    if (!GetData(buffer, dataSize, data.ReadRawData(dataSize))) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "read raw data failed: %{public}zu", dataSize);
        return false;
    }

    MessageParcel tempParcel;
    if (!tempParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "failed to parseFrom");
        return false;
    }
    tempParcel.ReadBoolVector(&result);
    return true;
}
}

UriPermissionManagerProxy::UriPermissionManagerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IUriPermissionManager>(impl) {}

bool UriPermissionManagerProxy::WriteBatchUris(MessageParcel &data, const std::vector<Uri> &uriVec)
{
    std::vector<std::string> uriStrVec;
    for (auto &uri : uriVec) {
        uriStrVec.emplace_back(uri.ToString());
    }
    if (!data.WriteUint32(uriStrVec.size())) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write uri size failed");
        return false;
    }
    if (!WriteStringUris(data, uriStrVec)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write uris failed");
        return false;
    }
    return true;
}

int UriPermissionManagerProxy::GrantUriPermission(const Uri &uri, unsigned int flag,
    const std::string targetBundleName, int32_t appIndex, uint32_t initiatorTokenId)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    MessageParcel data;
    if (!data.WriteInterfaceToken(IUriPermissionManager::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write interfaceToken failed");
        return INNER_ERR;
    }
    if (!data.WriteParcelable(&uri)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write uri failed");
        return INNER_ERR;
    }
    if (!data.WriteUint32(flag)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write flag failed");
        return INNER_ERR;
    }
    if (!data.WriteString(targetBundleName)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write targetBundleName failed");
        return INNER_ERR;
    }
    if (!data.WriteInt32(appIndex)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write appIndex failed");
        return INNER_ERR;
    }
    if (!data.WriteUint32(initiatorTokenId)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write initiatorTokenId failed");
        return INNER_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(UriPermMgrCmd::ON_GRANT_URI_PERMISSION, data, reply, option);
    if (error != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "SendRequest failed, error:%{public}d", error);
        return INNER_ERR;
    }
    return reply.ReadInt32();
}

int UriPermissionManagerProxy::GrantUriPermission(const std::vector<Uri> &uriVec, unsigned int flag,
    const std::string targetBundleName, int32_t appIndex, uint32_t initiatorTokenId)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    if (uriVec.empty() || uriVec.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "uriVec empty or exceed maxSize %{public}d", MAX_URI_COUNT);
        return ERR_URI_LIST_OUT_OF_RANGE;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(IUriPermissionManager::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write interfaceToken failed");
        return INNER_ERR;
    }
    if (!WriteBatchUris(data, uriVec)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write Batch uris failed");
        return INNER_ERR;
    }
    if (!data.WriteUint32(flag)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write flag failed");
        return INNER_ERR;
    }
    if (!data.WriteString(targetBundleName)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write targetBundleName failed");
        return INNER_ERR;
    }
    if (!data.WriteInt32(appIndex)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write appIndex failed");
        return INNER_ERR;
    }
    if (!data.WriteUint32(initiatorTokenId)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write initiatorTokenId failed");
        return INNER_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(UriPermMgrCmd::ON_BATCH_GRANT_URI_PERMISSION, data, reply, option);
    if (error != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "SendRequest failed, error:%{public}d", error);
        return INNER_ERR;
    }
    return reply.ReadInt32();
}

int32_t UriPermissionManagerProxy::GrantUriPermissionPrivileged(const std::vector<Uri> &uriVec, uint32_t flag,
    const std::string &targetBundleName, int32_t appIndex, uint32_t initiatorTokenId, int32_t hideSensitiveType)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "GrantUriPermissionPrivileged call");
    if (uriVec.empty() || uriVec.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "uriVec empty or exceed maxSize %{public}d", MAX_URI_COUNT);
        return ERR_URI_LIST_OUT_OF_RANGE;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(IUriPermissionManager::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write interfaceToken failed");
        return INNER_ERR;
    }
    if (!WriteBatchUris(data, uriVec)) {
        return INNER_ERR;
    }
    if (!data.WriteUint32(flag)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write flag failed");
        return INNER_ERR;
    }
    if (!data.WriteString(targetBundleName)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write targetBundleName failed");
        return INNER_ERR;
    }
    if (!data.WriteInt32(appIndex)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write appIndex failed");
        return INNER_ERR;
    }
    if (!data.WriteUint32(initiatorTokenId)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write initiatorTokenId failed");
        return INNER_ERR;
    }
    if (!data.WriteInt32(hideSensitiveType)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write hideSensitiveType failed");
        return INNER_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(UriPermMgrCmd::ON_GRANT_URI_PERMISSION_PRIVILEGED, data, reply, option);
    if (error != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "SendRequest failed, error:%{public}d", error);
        return INNER_ERR;
    }
    return reply.ReadInt32();
}

int UriPermissionManagerProxy::RevokeAllUriPermissions(const uint32_t tokenId)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    MessageParcel data;
    if (!data.WriteInterfaceToken(IUriPermissionManager::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write interfaceToken failed");
        return INNER_ERR;
    }
    if (!data.WriteUint32(tokenId)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write AccessTokenID failed");
        return INNER_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(UriPermMgrCmd::ON_REVOKE_ALL_URI_PERMISSION, data, reply, option);
    if (error != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "SendRequest fail, error:%{public}d", error);
        return INNER_ERR;
    }
    return reply.ReadInt32();
}

int UriPermissionManagerProxy::RevokeUriPermissionManually(const Uri &uri, const std::string bundleName,
    int32_t appIndex)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    MessageParcel data;
    if (!data.WriteInterfaceToken(IUriPermissionManager::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write interfaceToken failed");
        return INNER_ERR;
    }
    if (!data.WriteParcelable(&uri)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write uri failed");
        return INNER_ERR;
    }
    if (!data.WriteString(bundleName)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write bundleName failed");
        return INNER_ERR;
    }
    if (!data.WriteInt32(appIndex)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write appIndex failed");
        return INNER_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(UriPermMgrCmd::ON_REVOKE_URI_PERMISSION_MANUALLY, data, reply, option);
    if (error != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "SendRequest fail, error:%{public}d", error);
        return INNER_ERR;
    }
    return reply.ReadInt32();
}

bool UriPermissionManagerProxy::VerifyUriPermission(const Uri& uri, uint32_t flag, uint32_t tokenId)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    MessageParcel data;
    if (!data.WriteInterfaceToken(IUriPermissionManager::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write interfaceToken failed");
        return false;
    }
    if (!data.WriteParcelable(&uri)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write uri failed");
        return false;
    }
    if (!data.WriteUint32(flag)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write flag failed");
        return false;
    }
    if (!data.WriteUint32(tokenId)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write tokenId failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(UriPermMgrCmd::ON_VERIFY_URI_PERMISSION, data, reply, option);
    if (error != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "SendRequest fail, error:%{public}d", error);
        return false;
    }
    return reply.ReadBool();
}

std::vector<bool> UriPermissionManagerProxy::CheckUriAuthorization(const std::vector<std::string> &uriVec,
    uint32_t flag, uint32_t tokenId)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "CheckUriAuthorization call");
    std::vector<bool> result(uriVec.size(), false);
    if (uriVec.empty() || uriVec.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "uriVec empty or exceed maxSize %{public}d", MAX_URI_COUNT);
        return result;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(IUriPermissionManager::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write interfaceToken failed");
        return result;
    }
    if (!data.WriteUint32(uriVec.size())) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write uris size failed");
        return result;
    }
    if (!WriteStringUris(data, uriVec)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write uris failed");
        return result;
    }
    if (!data.WriteUint32(flag)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write flag failed");
        return result;
    }
    if (!data.WriteUint32(tokenId)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write tokenId failed");
        return result;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(UriPermMgrCmd::ON_CHECK_URI_AUTHORIZATION, data, reply, option);
    if (error != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "SendRequest error:%{public}d", error);
        return result;
    }
    if (!ReadBatchResultByRawData(reply, result) || uriVec.size() != result.size()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "ReadBatchResultByRawData failed");
        result = std::vector<bool>(uriVec.size(), false);
    }
    TAG_LOGI(AAFwkTag::URIPERMMGR, "CheckUriAuthorization end");
    return result;
}

int32_t UriPermissionManagerProxy::SendTransactCmd(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "remoteObject null");
        return ERR_NULL_OBJECT;
    }

    int32_t ret = remote->SendRequest(code, data, reply, option);
    if (ret != NO_ERROR) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "SendRequest failed. code:%{public}d, ret:%{public}d", code, ret);
        return ret;
    }
    return NO_ERROR;
}

int UriPermissionManagerProxy::ClearPermissionTokenByMap(const uint32_t tokenId)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    MessageParcel data;
    if (!data.WriteInterfaceToken(IUriPermissionManager::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write interfaceToken failed");
        return INNER_ERR;
    }
    if (!data.WriteUint32(tokenId)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write AccessTokenID failed");
        return INNER_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(UriPermMgrCmd::ON_CLEAR_PERMISSION_TOKEN_BY_MAP, data, reply, option);
    if (error != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "SendRequest fail, error:%{public}d", error);
        return INNER_ERR;
    }
    return reply.ReadInt32();
}

#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
int UriPermissionManagerProxy::Active(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    if (policy.empty() || policy.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "uriVec empty or exceed maxSize %{public}d", MAX_URI_COUNT);
        return ERR_URI_LIST_OUT_OF_RANGE;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(IUriPermissionManager::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write interfaceToken failed");
        return INNER_ERR;
    }
    if (!data.WriteUint32(policy.size())) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write size of policy failed");
        return INNER_ERR;
    }
    for (const auto &policyInfo : policy) {
        if (!data.WriteString(policyInfo.path)) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "Write policy path failed");
            return INNER_ERR;
        }
        if (!data.WriteUint64(policyInfo.mode)) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "Write policy mode failed");
            return INNER_ERR;
        }
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(UriPermMgrCmd::ON_ACTIVE, data, reply, option);
    if (error != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "SendRequest fail, error:%{public}d", error);
        return INNER_ERR;
    }
    auto res = reply.ReadUInt32Vector(&result);
    if (res) {
        return ERR_OK;
    }
    return INNER_ERR;
}
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
}  // namespace AAFwk
}  // namespace OHOS
