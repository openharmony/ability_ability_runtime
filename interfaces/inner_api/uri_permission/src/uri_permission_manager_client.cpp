/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "uri_permission_manager_client.h"

#include "ability_manager_errors.h"
#include "hilog_tag_wrapper.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "uri_permission_load_callback.h"

namespace OHOS {
namespace AAFwk {
namespace {
const int LOAD_SA_TIMEOUT_MS = 4 * 1000;
const int MAX_URI_COUNT = 200000;
constexpr size_t MAX_IPC_RAW_DATA_SIZE = 128 * 1024 * 1024; // 128M
constexpr int32_t MAX_PARCEL_IPC_DATA_SIZE = 200 * 1024; // 200K

inline size_t GetPadSize(size_t size)
{
    const size_t offset = 3;
    return (((size + offset) & (~offset)) - size);
}

bool CheckUseRawData(const std::vector<std::string>& uriVec)
{
    size_t oriSize = sizeof(int32_t);
    for (auto& uri : uriVec) {
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
} // namespace

UriPermissionManagerClient& UriPermissionManagerClient::GetInstance()
{
    static UriPermissionManagerClient instance;
    return instance;
}

int UriPermissionManagerClient::GrantUriPermission(const Uri &uri, unsigned int flag,
    const std::string targetBundleName, int32_t appIndex, uint32_t initiatorTokenId)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "targetBundleName:%{public}s", targetBundleName.c_str());
    auto uriPermMgr = ConnectUriPermService();
    if (uriPermMgr) {
        int32_t funcResult = -1;
        auto res = uriPermMgr->GrantUriPermission(uri, flag, targetBundleName, appIndex,
            initiatorTokenId, funcResult);
        if (res != ERR_OK) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "IPC failed, error:%{public}d", INNER_ERR);
            return INNER_ERR;
        }
        return funcResult;
    }
    return INNER_ERR;
}

int UriPermissionManagerClient::GrantUriPermission(const std::vector<Uri> &uriVec, unsigned int flag,
    const std::string targetBundleName, int32_t appIndex, uint32_t initiatorTokenId)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "targetBundleName:%{public}s, uriVecSize:%{public}zu", targetBundleName.c_str(),
        uriVec.size());
    if (uriVec.empty() || uriVec.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "uriVec empty or exceed maxSize %{public}d", MAX_URI_COUNT);
        return ERR_URI_LIST_OUT_OF_RANGE;
    }
    auto uriPermMgr = ConnectUriPermService();
    if (uriPermMgr == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "null uriPermMgr");
        return INNER_ERR;
    }
    std::vector<std::string> uriStrVec;
    for (auto &uri : uriVec) {
        uriStrVec.emplace_back(uri.ToString());
    }
    bool isWriteUriByRawData = CheckUseRawData(uriStrVec);
    ErrCode res = -1;
    int32_t funcResult = -1;
    if (isWriteUriByRawData) {
        UriPermissionRawData rawData;
        StringVecToRawData(uriStrVec, rawData);
        if (rawData.size > MAX_IPC_RAW_DATA_SIZE) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "rawData is too large");
            return INNER_ERR;
        }
        res = uriPermMgr->GrantUriPermission(rawData, flag, targetBundleName, appIndex, initiatorTokenId, funcResult);
        if (res != ERR_OK) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "IPC failed, error:%{public}d", INNER_ERR);
            return INNER_ERR;
        }
        return funcResult;
    }
    res = uriPermMgr->GrantUriPermission(uriStrVec, flag, targetBundleName, appIndex, initiatorTokenId, funcResult);
    if (res != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "IPC failed, error:%{public}d", INNER_ERR);
        return INNER_ERR;
    }
    return funcResult;
}

int32_t UriPermissionManagerClient::GrantUriPermissionPrivileged(const std::vector<Uri> &uriVec, uint32_t flag,
    const std::string &targetBundleName, int32_t appIndex, uint32_t initiatorTokenId, int32_t hideSensitiveType)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "targetBundleName:%{public}s, uriVecSize:%{public}zu",
        targetBundleName.c_str(), uriVec.size());
    if (uriVec.empty() || uriVec.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "uriVec empty or exceed maxSize %{public}d", MAX_URI_COUNT);
        return ERR_URI_LIST_OUT_OF_RANGE;
    }
    auto uriPermMgr = ConnectUriPermService();
    if (uriPermMgr == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "null uriPermMgr");
        return INNER_ERR;
    }
    std::vector<std::string> uriStrVec;
    for (auto &uri : uriVec) {
        uriStrVec.emplace_back(uri.ToString());
    }
    bool isWriteUriByRawData = CheckUseRawData(uriStrVec);
    ErrCode res = -1;
    int32_t funcResult = -1;
    if (isWriteUriByRawData) {
        UriPermissionRawData rawData;
        StringVecToRawData(uriStrVec, rawData);
        if (rawData.size > MAX_IPC_RAW_DATA_SIZE) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "rawData is too large");
            return INNER_ERR;
        }
        res = uriPermMgr->GrantUriPermissionPrivileged(rawData, flag, targetBundleName, appIndex,
            initiatorTokenId, hideSensitiveType, funcResult);
        if (res != ERR_OK) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "IPC failed, error:%{public}d", INNER_ERR);
            return INNER_ERR;
        }
        return funcResult;
    }
    res = uriPermMgr->GrantUriPermissionPrivileged(uriStrVec, flag, targetBundleName, appIndex,
        initiatorTokenId, hideSensitiveType, funcResult);
    if (res != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "IPC failed, error:%{public}d", INNER_ERR);
        return INNER_ERR;
    }
    return funcResult;
}

int UriPermissionManagerClient::RevokeAllUriPermissions(const uint32_t tokenId)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    auto uriPermMgr = ConnectUriPermService();
    if (uriPermMgr) {
        int32_t funcResult = -1;
        auto res = uriPermMgr->RevokeAllUriPermissions(tokenId, funcResult);
        if (res != ERR_OK) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "IPC failed, error:%{public}d", INNER_ERR);
            return INNER_ERR;
        }
        return funcResult;
    }
    return INNER_ERR;
}

int UriPermissionManagerClient::RevokeUriPermissionManually(const Uri &uri, const std::string bundleName,
    int32_t appIndex)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    auto uriPermMgr = ConnectUriPermService();
    if (uriPermMgr) {
        int32_t funcResult = -1;
        auto res = uriPermMgr->RevokeUriPermissionManually(uri, bundleName, appIndex, funcResult);
        if (res != ERR_OK) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "IPC failed, error:%{public}d", INNER_ERR);
            return INNER_ERR;
        }
        return funcResult;
    }
    return INNER_ERR;
}

bool UriPermissionManagerClient::VerifyUriPermission(const Uri& uri, uint32_t flag, uint32_t tokenId)
{
    auto uriPermMgr = ConnectUriPermService();
    if (uriPermMgr) {
        bool funcResult = false;
        auto res = uriPermMgr->VerifyUriPermission(uri, flag, tokenId, funcResult);
        if (res != ERR_OK) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "IPC fail, error:%{public}d", res);
        }
        return funcResult;
    }
    return false;
}

std::vector<bool> UriPermissionManagerClient::CheckUriAuthorization(const std::vector<std::string> &uriVec,
    uint32_t flag, uint32_t tokenId)
{
    uint32_t size = uriVec.size();
    TAG_LOGI(AAFwkTag::URIPERMMGR, "flag:%{public}u, tokenId:%{public}u", flag, tokenId);
    std::vector<bool> errorRes(size, false);
    if (uriVec.empty() || uriVec.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "uriVec empty or exceed maxSize %{public}d", MAX_URI_COUNT);
        return errorRes;
    }
    auto uriPermMgr = ConnectUriPermService();
    if (uriPermMgr == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "null uriPermMgr");
        return errorRes;
    }
    bool isWriteUriByRawData = CheckUseRawData(uriVec);
    if (isWriteUriByRawData) {
        UriPermissionRawData resRawData;
        UriPermissionRawData rawData;
        StringVecToRawData(uriVec, rawData);
        if (rawData.size > MAX_IPC_RAW_DATA_SIZE) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "rawData is too large");
            return errorRes;
        }
        uriPermMgr->CheckUriAuthorization(rawData, flag, tokenId, resRawData);
        auto result = RawDataToBoolVec(resRawData, errorRes);
        if (!result) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "RawDataToBoolVec failed");
            return errorRes;
        }
    } else {
        std::vector<bool> funcResult;
        uriPermMgr->CheckUriAuthorization(uriVec, flag, tokenId, funcResult);
        errorRes = funcResult;
    }
    if (errorRes.size() != uriVec.size()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "invalid result");
        errorRes = std::vector<bool>(uriVec.size(), false);
    }
    return errorRes;
}

sptr<IUriPermissionManager> UriPermissionManagerClient::ConnectUriPermService()
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    auto uriPermMgr = GetUriPermMgr();
    if (uriPermMgr == nullptr) {
        if (!LoadUriPermService()) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "LoadUriPermService failed");
            return nullptr;
        }
        uriPermMgr = GetUriPermMgr();
        if (uriPermMgr == nullptr || uriPermMgr->AsObject() == nullptr) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "GetUriPermMgr failed");
            return nullptr;
        }
        const auto& onClearProxyCallback = [] {
            UriPermissionManagerClient::GetInstance().ClearProxy();
        };
        sptr<UpmsDeathRecipient> recipient(new UpmsDeathRecipient(onClearProxyCallback));
        uriPermMgr->AsObject()->AddDeathRecipient(recipient);
    }
    TAG_LOGD(AAFwkTag::URIPERMMGR, "End");
    return uriPermMgr;
}

bool UriPermissionManagerClient::LoadUriPermService()
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "GetSystemAbilityManager failed");
        return false;
    }

    sptr<UriPermissionLoadCallback> loadCallback = new (std::nothrow) UriPermissionLoadCallback();
    if (loadCallback == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Create loadCallback failed");
        return false;
    }

    auto ret = systemAbilityMgr->LoadSystemAbility(URI_PERMISSION_MGR_SERVICE_ID, loadCallback);
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "LoadSystemAbility %{public}d failed:%{public}d",
            URI_PERMISSION_MGR_SERVICE_ID, ret);
        return false;
    }

    {
        std::unique_lock<std::mutex> lock(saLoadMutex_);
        auto waitStatus = loadSaVariable_.wait_for(lock, std::chrono::milliseconds(LOAD_SA_TIMEOUT_MS),
            [this]() {
                return saLoadFinished_;
            });
        if (!waitStatus) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "Wait for load sa timeout");
            return false;
        }
    }
    return true;
}

sptr<IUriPermissionManager> UriPermissionManagerClient::GetUriPermMgr()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return uriPermMgr_;
}

void UriPermissionManagerClient::SetUriPermMgr(const sptr<IRemoteObject> &remoteObject)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    std::lock_guard<std::mutex> lock(mutex_);
    uriPermMgr_ = iface_cast<IUriPermissionManager>(remoteObject);
}

void UriPermissionManagerClient::OnLoadSystemAbilitySuccess(const sptr<IRemoteObject> &remoteObject)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    SetUriPermMgr(remoteObject);
    std::unique_lock<std::mutex> lock(saLoadMutex_);
    saLoadFinished_ = true;
    loadSaVariable_.notify_one();
}

void UriPermissionManagerClient::OnLoadSystemAbilityFail()
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    SetUriPermMgr(nullptr);
    std::unique_lock<std::mutex> lock(saLoadMutex_);
    saLoadFinished_ = true;
    loadSaVariable_.notify_one();
}

void UriPermissionManagerClient::ClearProxy()
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        uriPermMgr_ = nullptr;
    }
    std::unique_lock<std::mutex> lock(saLoadMutex_);
    saLoadFinished_ = false;
}

void UriPermissionManagerClient::UpmsDeathRecipient::OnRemoteDied([[maybe_unused]] const wptr<IRemoteObject>& remote)
{
    TAG_LOGE(AAFwkTag::URIPERMMGR, "call");
    proxy_();
}

int32_t UriPermissionManagerClient::ClearPermissionTokenByMap(const uint32_t tokenId)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    auto uriPermMgr = ConnectUriPermService();
    if (uriPermMgr) {
        int32_t funcResult = -1;
        auto res = uriPermMgr->ClearPermissionTokenByMap(tokenId, funcResult);
        if (res != ERR_OK) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "IPC failed, error:%{public}d", INNER_ERR);
            return INNER_ERR;
        }
        return funcResult;
    }
    return INNER_ERR;
}

bool UriPermissionManagerClient::RawDataToBoolVec(const UriPermissionRawData& rawData, std::vector<bool>& boolVec)
{
    std::stringstream ss;
    ss.write(reinterpret_cast<const char *>(rawData.data), rawData.size);
    ss.seekg(0, std::ios::beg);
    uint32_t boolCount = 0;
    ss.read(reinterpret_cast<char*>(&boolCount), sizeof(boolCount));
    if (boolCount != boolVec.size()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "vector size not match");
        return false;
    }
    for (uint32_t i = 0; i < boolCount; ++i) {
        bool resBool = false;
        ss.read(reinterpret_cast<char *>(&resBool), sizeof(resBool));
        boolVec.at(i) = static_cast<bool>(resBool);
    }
    return true;
}

void UriPermissionManagerClient::StringVecToRawData(const std::vector<std::string>& stringVec,
    UriPermissionRawData& rawData)
{
    std::stringstream ss;
    uint32_t stringCount = stringVec.size();
    ss.write(reinterpret_cast<const char*>(&stringCount), sizeof(stringCount));

    for (uint32_t i = 0; i < stringCount; ++i) {
        uint32_t strLen = stringVec[i].length();
        ss.write(reinterpret_cast<const char*>(&strLen), sizeof(strLen));
        ss.write(stringVec[i].c_str(), strLen);
    }
    std::string result = ss.str();
    rawData.ownedData = std::move(result);
    rawData.data = rawData.ownedData.data();
    rawData.size = rawData.ownedData.size();
}

#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
int32_t UriPermissionManagerClient::Active(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    if (policy.empty() || policy.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "uriVec empty or exceed maxSize %{public}d", MAX_URI_COUNT);
        return ERR_URI_LIST_OUT_OF_RANGE;
    }
    auto uriPermMgr = ConnectUriPermService();
    if (uriPermMgr) {
        UriPermissionRawData policyRawData;
        PolicyInfoToRawData(policy, policyRawData);
        if (policyRawData.size > MAX_IPC_RAW_DATA_SIZE) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "rawData is too large");
            return INNER_ERR;
        }
        int32_t funcResult = -1;
        auto res = uriPermMgr->Active(policyRawData, result, funcResult);
        if (res != ERR_OK) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "IPC failed, error:%{public}d", res);
            return INNER_ERR;
        }
        return funcResult;
    }
    return INNER_ERR;
}

void UriPermissionManagerClient::PolicyInfoToRawData(const std::vector<PolicyInfo>& policy,
    UriPermissionRawData& policyRawData)
{
    std::stringstream ss;
    uint32_t policyNum = policy.size();
    ss.write(reinterpret_cast<const char *>(&policyNum), sizeof(policyNum));
    for (uint32_t i = 0; i < policyNum; i++) {
        uint32_t pathLen = policy[i].path.length();
        ss.write(reinterpret_cast<const char *>(&pathLen), sizeof(pathLen));
        ss.write(policy[i].path.c_str(), pathLen);
        ss.write(reinterpret_cast<const char *>(&policy[i].mode), sizeof(policy[i].mode));
    }
    std::string result = ss.str();
    policyRawData.ownedData = std::move(result);
    policyRawData.data = policyRawData.ownedData.data();
    policyRawData.size = policyRawData.ownedData.size();
}
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
}  // namespace AAFwk
}  // namespace OHOS
