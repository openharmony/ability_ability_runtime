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

#include "uri_permission_manager_stub.h"

#include "ability_manager_errors.h"
#include "hilog_tag_wrapper.h"
#include "securec.h"

namespace OHOS {
namespace AAFwk {
namespace {
const int MAX_URI_COUNT = 200000;
constexpr size_t MAX_IPC_RAW_DATA_SIZE = 128 * 1024 * 1024; // 128M

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

bool ReadStringUrisByRawData(MessageParcel &data, std::vector<std::string> &uriVec)
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
    tempParcel.ReadStringVector(&uriVec);
    return true;
}

bool ReadStringUris(MessageParcel &data, std::vector<std::string> &uriVec)
{
    bool isWriteUriByRawData = data.ReadBool();
    if (isWriteUriByRawData) {
        return ReadStringUrisByRawData(data, uriVec);
    }
    return data.ReadStringVector(&uriVec);
}

bool WriteBatchResultByRawData(MessageParcel &data, const std::vector<bool> &result)
{
    MessageParcel tempParcel;
    tempParcel.SetMaxCapacity(MAX_IPC_RAW_DATA_SIZE);
    if (!tempParcel.WriteBoolVector(result)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write result failed");
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
}

int UriPermissionManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != IUriPermissionManager::GetDescriptor()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "InterfaceToken invalid");
        return ERR_INVALID_VALUE;
    }
    ErrCode errCode = ERR_OK;
    switch (code) {
        case UriPermMgrCmd::ON_GRANT_URI_PERMISSION : {
            return HandleGrantUriPermission(data, reply);
        }
        case UriPermMgrCmd::ON_BATCH_GRANT_URI_PERMISSION : {
            return HandleBatchGrantUriPermission(data, reply);
        }
        case UriPermMgrCmd::ON_GRANT_URI_PERMISSION_PRIVILEGED : {
            return HandleGrantUriPermissionPrivileged(data, reply);
        }
        case UriPermMgrCmd::ON_REVOKE_ALL_URI_PERMISSION : {
            return HandleRevokeAllUriPermission(data, reply);
        }
        case UriPermMgrCmd::ON_REVOKE_URI_PERMISSION_MANUALLY : {
            return HandleRevokeUriPermissionManually(data, reply);
        }
        case UriPermMgrCmd::ON_VERIFY_URI_PERMISSION : {
            return HandleVerifyUriPermission(data, reply);
        }
        case UriPermMgrCmd::ON_CHECK_URI_AUTHORIZATION : {
            return HandleCheckUriAuthorization(data, reply);
        }
        case UriPermMgrCmd::ON_CLEAR_PERMISSION_TOKEN_BY_MAP : {
            return HandleClearPermissionTokenByMap(data, reply);
        }
#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
        case UriPermMgrCmd::ON_ACTIVE : {
            return HandleActive(data, reply);
        }
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return errCode;
}

int32_t UriPermissionManagerStub::ReadBatchUris(MessageParcel &data, std::vector<Uri> &uriVec)
{
    uint32_t size = data.ReadUint32();
    if (size == 0 || size > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "out of range: %{public}u", size);
        return ERR_URI_LIST_OUT_OF_RANGE;
    }
    std::vector<std::string> uris;
    if (!ReadStringUris(data, uris)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "read uris failed");
        return ERR_DEAD_OBJECT;
    }
    for (auto &uri : uris) {
        uriVec.emplace_back(uri);
    }
    return ERR_OK;
}

int UriPermissionManagerStub::HandleRevokeAllUriPermission(MessageParcel &data, MessageParcel &reply)
{
    auto tokenId = data.ReadUint32();
    int result = RevokeAllUriPermissions(tokenId);
    reply.WriteInt32(result);
    return ERR_OK;
}

int UriPermissionManagerStub::HandleGrantUriPermission(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (!uri) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "read uri failed");
        return ERR_DEAD_OBJECT;
    }
    auto flag = data.ReadUint32();
    auto targetBundleName = data.ReadString();
    auto appIndex = data.ReadInt32();
    auto initiatorTokenId = data.ReadUint32();
    int result = GrantUriPermission(*uri, flag, targetBundleName, appIndex, initiatorTokenId);
    reply.WriteInt32(result);
    return ERR_OK;
}

int UriPermissionManagerStub::HandleBatchGrantUriPermission(MessageParcel &data, MessageParcel &reply)
{
    std::vector<Uri> uriVec;
    auto ret = ReadBatchUris(data, uriVec);
    if (ret != ERR_OK) {
        return ret;
    }
    auto flag = data.ReadUint32();
    auto targetBundleName = data.ReadString();
    auto appIndex = data.ReadInt32();
    auto initiatorTokenId = data.ReadUint32();
    int result = GrantUriPermission(uriVec, flag, targetBundleName, appIndex, initiatorTokenId);
    reply.WriteInt32(result);
    return ERR_OK;
}

int32_t UriPermissionManagerStub::HandleGrantUriPermissionPrivileged(MessageParcel &data, MessageParcel &reply)
{
    std::vector<Uri> uriVec;
    auto ret = ReadBatchUris(data, uriVec);
    if (ret != ERR_OK) {
        return ret;
    }
    auto flag = data.ReadUint32();
    auto targetBundleName = data.ReadString();
    auto appIndex = data.ReadInt32();
    auto initiatorTokenId = data.ReadUint32();
    auto hideSensitiveType = data.ReadInt32();
    int32_t result = GrantUriPermissionPrivileged(uriVec, flag, targetBundleName, appIndex,
        initiatorTokenId, hideSensitiveType);
    reply.WriteInt32(result);
    return ERR_OK;
}

int UriPermissionManagerStub::HandleRevokeUriPermissionManually(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (!uri) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "read uri failed");
        return ERR_DEAD_OBJECT;
    }
    auto bundleName = data.ReadString();
    auto appIndex = data.ReadInt32();
    int result = RevokeUriPermissionManually(*uri, bundleName, appIndex);
    reply.WriteInt32(result);
    return ERR_OK;
}

int UriPermissionManagerStub::HandleVerifyUriPermission(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Uri> uri(data.ReadParcelable<Uri>());
    if (!uri) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "read uri failed");
        return ERR_DEAD_OBJECT;
    }
    auto flag = data.ReadUint32();
    auto tokenId = data.ReadUint32();
    bool result = VerifyUriPermission(*uri, flag, tokenId);
    reply.WriteBool(result);
    return ERR_OK;
}

int32_t UriPermissionManagerStub::HandleCheckUriAuthorization(MessageParcel &data, MessageParcel &reply)
{
    auto size = data.ReadUint32();
    if (size == 0 || size > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "uriVec empty or exceed maxSize %{public}d", MAX_URI_COUNT);
        return ERR_URI_LIST_OUT_OF_RANGE;
    }
    std::vector<std::string> uriVec;
    if (!ReadStringUris(data, uriVec)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "ReadStringUris failed");
        return ERR_DEAD_OBJECT;
    }
    auto flag = data.ReadUint32();
    auto tokenId = data.ReadUint32();
    auto result = CheckUriAuthorization(uriVec, flag, tokenId);
    if (!WriteBatchResultByRawData(reply, result)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "WriteBatchResultByRawData failed");
        return ERR_DEAD_OBJECT;
    }
    return ERR_OK;
}

int UriPermissionManagerStub::HandleClearPermissionTokenByMap(MessageParcel &data, MessageParcel &reply)
{
    auto tokenId = data.ReadUint32();
    int result = ClearPermissionTokenByMap(tokenId);
    reply.WriteInt32(result);
    return ERR_OK;
}

#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
int UriPermissionManagerStub::HandleActive(MessageParcel &data, MessageParcel &reply)
{
    auto policySize = data.ReadUint32();
    if (policySize == 0 || policySize > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "policy empty or exceed maxSize %{public}d", MAX_URI_COUNT);
        return ERR_URI_LIST_OUT_OF_RANGE;
    }
    std::vector<PolicyInfo> policy;
    for (uint32_t i = 0; i < policySize; i++) {
        PolicyInfo info = {data.ReadString(), data.ReadUint64()};
        policy.emplace_back(info);
    }
    std::vector<uint32_t> result;
    int res = Active(policy, result);
    if (!reply.WriteUInt32Vector(result)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write result failed");
        return ERR_DEAD_OBJECT;
    }
    if (!reply.WriteInt32(res)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Write res failed");
        return ERR_DEAD_OBJECT;
    }
    return ERR_OK;
}
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
}  // namespace AAFwk
}  // namespace OHOS
