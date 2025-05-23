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

#include "uri_permission_manager_stub_impl.h"

#include "ability_manager_errors.h"
#include "ability_manager_client.h"
#include "accesstoken_kit.h"
#include "app_utils.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "if_system_ability_manager.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#ifdef ABILITY_RUNTIME_MEDIA_LIBRARY_ENABLE
#include "media_permission_manager.h"
#endif // ABILITY_RUNTIME_MEDIA_LIBRARY_ENABLE
#include "parameter.h"
#include "permission_constants.h"
#include "permission_verification.h"
#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
#include "sandbox_manager_kit.h"
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
#include "system_ability_definition.h"
#include "tokenid_kit.h"
#include "uri_permission_utils.h"
#include "want.h"

namespace OHOS {
namespace AAFwk {
namespace {
constexpr int32_t ERR_OK = 0;
constexpr uint32_t FLAG_READ_WRITE_URI = Want::FLAG_AUTH_READ_URI_PERMISSION | Want::FLAG_AUTH_WRITE_URI_PERMISSION;
constexpr uint32_t FLAG_WRITE_URI = Want::FLAG_AUTH_WRITE_URI_PERMISSION;
constexpr uint32_t FLAG_READ_URI = Want::FLAG_AUTH_READ_URI_PERMISSION;
constexpr const char* CLOUND_DOCS_URI_MARK = "?networkid=";
constexpr const char* FOUNDATION_PROCESS = "foundation";
constexpr size_t MAX_IPC_RAW_DATA_SIZE = 128 * 1024 * 1024; // 128M
const int MAX_URI_COUNT = 200000;
#ifndef ABILITY_RUNTIME_MEDIA_LIBRARY_ENABLE
constexpr int32_t CAPABILITY_NOT_SUPPORT = 801;
#endif // ABILITY_RUNTIME_MEDIA_LIBRARY_ENABLE
constexpr int32_t SANDBOX_MANAGER_PERMISSION_DENIED = 1;
}

ErrCode UriPermissionManagerStubImpl::VerifyUriPermission(const Uri& uri, uint32_t flag, uint32_t tokenId,
    bool& funcResult)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    // verify if tokenId have uri permission record
    TAG_LOGI(AAFwkTag::URIPERMMGR, "uri:%{private}s, flag:%{public}u, tokenId:%{public}u",
        uri.ToString().c_str(), flag, tokenId);
    if (!UPMSUtils::IsSAOrSystemAppCall()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "not SA/SystemApp");
        funcResult = false;
        return ERR_OK;
    }
    if ((flag & FLAG_READ_WRITE_URI) == 0) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Flag invalid");
        funcResult = false;
        return ERR_OK;
    }
    // only reserve read and write file flag
    flag &= FLAG_READ_WRITE_URI;
    auto uriInner = uri;
    if (uriInner.GetScheme() != "file") {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "type of uri is valid");
        funcResult = false;
        return ERR_OK;
    }
    if (uriInner.GetAuthority() == "media") {
        TAG_LOGW(AAFwkTag::URIPERMMGR, "not support media uri");
        funcResult = false;
        return ERR_OK;
    }
    std::vector<Uri> uriVec = { uriInner };
    auto result = VerifyUriPermissionByMap(uriVec, flag, tokenId);
    if (!result[0]) {
        TAG_LOGI(AAFwkTag::URIPERMMGR, "uri permission not exists");
    }
    funcResult = result[0];
    return ERR_OK;
}

std::vector<bool> UriPermissionManagerStubImpl::VerifyUriPermissionByMap(std::vector<Uri> &uriVec,
    uint32_t flag, uint32_t tokenId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    uint32_t newFlag = FLAG_READ_URI;
    if ((flag & FLAG_WRITE_URI) != 0) {
        newFlag = FLAG_WRITE_URI;
    }
    std::vector<bool> result(uriVec.size(), false);
    std::lock_guard<std::mutex> guard(mutex_);
    for (size_t i = 0; i < uriVec.size(); i++) {
        auto uriStr = uriVec[i].ToString();
        result[i] = VerifySingleUriPermissionByMap(uriStr, newFlag, tokenId);
    }
    return result;
}

bool UriPermissionManagerStubImpl::VerifySingleUriPermissionByMap(const std::string &uri,
    uint32_t flag, uint32_t tokenId)
{
    auto search = uriMap_.find(uri);
    if (search != uriMap_.end()) {
        auto& list = search->second;
        for (auto it = list.begin(); it != list.end(); it++) {
            if ((it->targetTokenId == tokenId) && ((it->flag | FLAG_READ_URI) & flag) != 0) {
                TAG_LOGD(AAFwkTag::URIPERMMGR, "have uri permission");
                return true;
            }
        }
    }
    return VerifySubDirUriPermission(uri, flag, tokenId);
}

bool UriPermissionManagerStubImpl::VerifySubDirUriPermission(const std::string &uriStr,
                                                             uint32_t newFlag, uint32_t tokenId)
{
    auto iPos = uriStr.find(CLOUND_DOCS_URI_MARK);
    if (iPos == std::string::npos) {
        TAG_LOGI(AAFwkTag::URIPERMMGR, "Local uri not support to verify sub directory uri permission");
        return false;
    }

    for (auto search = uriMap_.rbegin(); search != uriMap_.rend(); ++search) {
        if (!IsDistributedSubDirUri(uriStr, search->first)) {
            continue;
        }
        auto& list = search->second;
        for (auto it = list.begin(); it != list.end(); it++) {
            if ((it->targetTokenId == tokenId) && ((it->flag | FLAG_READ_URI) & newFlag) != 0) {
                TAG_LOGD(AAFwkTag::URIPERMMGR, "have uri permission");
                return true;
            }
        }
        break;
    }
    TAG_LOGI(AAFwkTag::URIPERMMGR, "Uri permission not exists");
    return false;
}

bool UriPermissionManagerStubImpl::IsDistributedSubDirUri(const std::string &inputUri, const std::string &cachedUri)
{
    auto iPos = inputUri.find(CLOUND_DOCS_URI_MARK);
    auto cPos = cachedUri.find(CLOUND_DOCS_URI_MARK);
    if ((iPos == std::string::npos) || (cPos == std::string::npos)) {
        TAG_LOGI(AAFwkTag::URIPERMMGR, "not distributed file uri");
        return false;
    }
    std::string iTempUri = inputUri.substr(0, iPos);
    std::string cTempUri = cachedUri.substr(0, cPos);
    std::string iTempNetworkId = inputUri.substr(iPos);
    std::string cTempNetworkId = cachedUri.substr(cPos);
    return (iTempUri.find(cTempUri + "/") == 0 && iTempNetworkId.compare(cTempNetworkId) == 0);
}

ErrCode UriPermissionManagerStubImpl::GrantUriPermission(const Uri& uri, unsigned int flag,
    const std::string& targetBundleName, int32_t appIndex, uint32_t initiatorTokenId, int32_t& funcResult)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "Uri:%{private}s", uri.ToString().c_str());
    std::vector<Uri> uriVec = { uri };
    if (UPMSUtils::IsSystemAppCall() && uriVec[0].GetScheme() != "file") {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Only support file uri");
        funcResult = ERR_CODE_INVALID_URI_TYPE;
        return ERR_OK;
    }
    std::vector<std::string> uriVecStr;
    for (const Uri& uri : uriVec) {
        uriVecStr.push_back(uri.ToString());
    }
    GrantUriPermission(uriVecStr, flag, targetBundleName, appIndex, initiatorTokenId, funcResult);
    return ERR_OK;
}

ErrCode UriPermissionManagerStubImpl::GrantUriPermission(const std::vector<std::string>& uriVec, unsigned int flag,
    const std::string& targetBundleName, int32_t appIndex, uint32_t initiatorTokenId, int32_t& funcResult)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (uriVec.empty() || uriVec.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "uriVec empty or exceed maxSize %{public}d", MAX_URI_COUNT);
        return ERR_URI_LIST_OUT_OF_RANGE;
    }
    TAG_LOGI(AAFwkTag::URIPERMMGR, "BundleName:%{public}s, appIndex:%{public}d, flag:%{public}u, uris:%{public}zu",
        targetBundleName.c_str(), appIndex, flag, uriVec.size());
    if (!UPMSUtils::IsSAOrSystemAppCall()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "not SA/SystemApp");
        funcResult = CHECK_PERMISSION_FAILED;
        return ERR_OK;
    }
    auto checkResult = CheckCalledBySandBox();
    if (checkResult != ERR_OK) {
        funcResult = checkResult;
        return ERR_OK;
    }
    if (uriVec.size() == 0 || uriVec.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "out of range: %{public}zu", uriVec.size());
        funcResult = ERR_URI_LIST_OUT_OF_RANGE;
        return ERR_OK;
    }
    if ((flag & FLAG_READ_WRITE_URI) == 0) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "invalid flag: %{public}u", flag);
        funcResult = ERR_CODE_INVALID_URI_FLAG;
        return ERR_OK;
    }
    uint32_t targetTokenId = 0;
    auto ret = UPMSUtils::GetTokenIdByBundleName(targetBundleName, appIndex, targetTokenId);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "get tokenId by bundle name failed");
        funcResult = ret;
        return ERR_OK;
    }
    uint32_t callerTokenId = initiatorTokenId;
    if (!UPMSUtils::IsFoundationCall()) {
        callerTokenId = IPCSkeleton::GetCallingTokenID();
    }
    std::vector<Uri> uriVecInner;
    for (const auto& str : uriVec) {
        uriVecInner.emplace_back(str);
    }
    funcResult = GrantUriPermissionInner(uriVecInner, flag, callerTokenId, targetTokenId, targetBundleName);
    return ERR_OK;
}

ErrCode UriPermissionManagerStubImpl::GrantUriPermission(const UriPermissionRawData& rawData, uint32_t flag,
    const std::string& targetBundleName, int32_t appIndex, uint32_t initiatorTokenId, int32_t& funcResult)
{
    std::vector<std::string> uriVec;
    auto res = RawDataToStringVec(rawData, uriVec);
    if (res != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "raw data to vec failed");
        funcResult = res;
        return res;
    }
    auto errCode = GrantUriPermission(uriVec, flag, targetBundleName, appIndex, initiatorTokenId, funcResult);
    if (errCode != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "GrantUriPermission failed, errCode:%{public}d", errCode);
        return errCode;
    }
    TAG_LOGI(AAFwkTag::URIPERMMGR, "GrantUriPermission finished.");
    return ERR_OK;
}

int32_t UriPermissionManagerStubImpl::GrantUriPermissionInner(const std::vector<Uri> &uriVec, uint32_t flag,
    uint32_t callerTokenId, uint32_t targetTokenId, const std::string &targetBundleName)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    TokenIdPermission tokenIdPermission(callerTokenId);
    auto checkResult = CheckUriPermission(tokenIdPermission, uriVec, flag);
    if (checkResult.size() != uriVec.size()) {
        TAG_LOGW(AAFwkTag::URIPERMMGR, "result size:%{public}zu", checkResult.size());
        return INNER_ERR;
    }
    std::vector<std::string> permissionedMediaUris;
    std::vector<std::string> permissionedOtherUris;
    size_t permissionedUriCount = 0;
    for (size_t i = 0; i < checkResult.size(); i++) {
        if (!checkResult[i]) {
            TAG_LOGW(AAFwkTag::URIPERMMGR, "No permission, uri:%{private}s", uriVec[i].ToString().c_str());
            continue;
        }
        permissionedUriCount++;
        auto uriInner = uriVec[i];
        if (uriInner.GetScheme() == "media") {
            permissionedMediaUris.emplace_back(uriVec[i].ToString());
        } else {
            permissionedOtherUris.emplace_back(uriVec[i].ToString());
        }
    }
    // some uri is no permission
    if (permissionedUriCount != uriVec.size()) {
        UPMSUtils::SendShareUnPrivilegeUriEvent(callerTokenId, targetTokenId);
    }
    if (permissionedUriCount == 0) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "all uri invalid or no permission");
        return CHECK_PERMISSION_FAILED;
    }
    uint32_t grantRet = INNER_ERR;
    if (GrantBatchUriPermissionImpl(permissionedOtherUris, flag, callerTokenId, targetTokenId) == ERR_OK) {
        grantRet = ERR_OK;
    }
    // for media uri
    if (GrantBatchMediaUriPermissionImpl(permissionedMediaUris, flag, callerTokenId, targetTokenId, 0) == ERR_OK) {
        grantRet = ERR_OK;
    }
    UPMSUtils::SendSystemAppGrantUriPermissionEvent(callerTokenId, targetTokenId, uriVec, checkResult);
    return grantRet;
}

int32_t UriPermissionManagerStubImpl::GrantBatchMediaUriPermissionImpl(const std::vector<std::string> &mediaUris,
    uint32_t flag, uint32_t callerTokenId, uint32_t targetTokenId, int32_t hideSensitiveType)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
#ifdef ABILITY_RUNTIME_MEDIA_LIBRARY_ENABLE
    if (mediaUris.empty()) {
        return INNER_ERR;
    }
    auto ret = MediaPermissionManager::GetInstance().GrantUriPermission(mediaUris, flag, callerTokenId, targetTokenId,
        hideSensitiveType);
    if (ret != ERR_OK) {
        TAG_LOGW(AAFwkTag::URIPERMMGR, "Grant media uri permission failed, ret:%{public}d", ret);
        return ret;
    }
    TAG_LOGD(AAFwkTag::URIPERMMGR, "Grant media uri permission success");
    return ERR_OK;
#else
    return CAPABILITY_NOT_SUPPORT;
#endif // ABILITY_RUNTIME_MEDIA_LIBRARY_ENABLE
}

int32_t UriPermissionManagerStubImpl::GrantBatchContentUriPermissionImpl(const std::vector<std::string> &contentUris,
    uint32_t flag, uint32_t targetTokenId, const std::string &targetBundleName)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (contentUris.empty()) {
        return INNER_ERR;
    }
    auto abilityClient = AAFwk::AbilityManagerClient::GetInstance();
    if (abilityClient == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "abilityClient null");
        return INNER_ERR;
    }
    auto collaborator = IN_PROCESS_CALL(abilityClient->GetAbilityManagerCollaborator());
    if (collaborator == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "collaborator null");
        return INNER_ERR;
    }
    auto ret = collaborator->GrantUriPermission(contentUris, flag, targetTokenId, targetBundleName);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "GrantUriPermission failed:%{public}d", ret);
        return ret;
    }
    AddContentTokenIdRecord(targetTokenId);
    return ERR_OK;
}

int32_t UriPermissionManagerStubImpl::RevokeContentUriPermission(uint32_t tokenId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::URIPERMMGR, "RevokeContentUriPermission null");
    if (!IsContentUriGranted(tokenId)) {
        return ERR_OK;
    }
    auto abilityClient = AAFwk::AbilityManagerClient::GetInstance();
    if (abilityClient == nullptr) {
        TAG_LOGI(AAFwkTag::URIPERMMGR, "abilityClient null");
        return INNER_ERR;
    }
    auto collaborator = IN_PROCESS_CALL(abilityClient->GetAbilityManagerCollaborator());
    if (collaborator == nullptr) {
        TAG_LOGI(AAFwkTag::URIPERMMGR, "collaborator null");
        return INNER_ERR;
    }
    auto ret = collaborator->RevokeUriPermission(tokenId);
    if (ret != ERR_OK) {
        TAG_LOGW(AAFwkTag::URIPERMMGR, "RevokeUriPermission failed:%{public}d", ret);
    }
    RemoveContentTokenIdRecord(tokenId);
    return ret;
}

bool UriPermissionManagerStubImpl::IsContentUriGranted(uint32_t tokenId)
{
    std::lock_guard<std::mutex> lock(contentTokenIdSetMutex_);
    return contentTokenIdSet_.find(tokenId) != contentTokenIdSet_.end();
}

void UriPermissionManagerStubImpl::AddContentTokenIdRecord(uint32_t tokenId)
{
    std::lock_guard<std::mutex> lock(contentTokenIdSetMutex_);
    contentTokenIdSet_.insert(tokenId);
}

void UriPermissionManagerStubImpl::RemoveContentTokenIdRecord(uint32_t tokenId)
{
    std::lock_guard<std::mutex> lock(contentTokenIdSetMutex_);
    contentTokenIdSet_.erase(tokenId);
}

int32_t UriPermissionManagerStubImpl::GrantBatchUriPermissionImpl(const std::vector<std::string> &uriVec,
    uint32_t flag, TokenId callerTokenId, TokenId targetTokenId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "privileged uris: %{public}zu", uriVec.size());
    if (uriVec.empty()) {
        return INNER_ERR;
    }
    // only reserve read and write file flag
    flag &= FLAG_READ_WRITE_URI;
    ConnectManager(storageManager_, STORAGE_MANAGER_MANAGER_ID);
    if (storageManager_ == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "null ConnectManager");
        return INNER_ERR;
    }
    std::vector<int32_t> resVec;
    storageManager_->CreateShareFile(uriVec, targetTokenId, flag, resVec);
    if (resVec.size() == 0) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "CreateShareFile failed, storageManager resVec empty");
        return INNER_ERR;
    }
    if (resVec.size() != uriVec.size()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "failed, ret:%{public}u", resVec[0]);
        return resVec[0];
    }
    int successCount = 0;
    for (size_t i = 0; i < uriVec.size(); i++) {
        auto ret = resVec[i];
        if (ret != 0 && ret != -EEXIST) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "CreateShareFile failed");
            continue;
        }
        AddTempUriPermission(uriVec[i], flag, callerTokenId, targetTokenId);
        successCount++;
    }
    TAG_LOGI(AAFwkTag::URIPERMMGR, "total %{public}d uri permissions added", successCount);
    if (successCount == 0) {
        return INNER_ERR;
    }
    // index that targetTokenId is granted
    std::lock_guard<std::mutex> lock(ptMapMutex_);
    permissionTokenMap_.insert(targetTokenId);
    return ERR_OK;
}

int32_t UriPermissionManagerStubImpl::AddTempUriPermission(const std::string &uri, uint32_t flag,
    TokenId fromTokenId, TokenId targetTokenId)
{
    std::lock_guard<std::mutex> guard(mutex_);
    auto search = uriMap_.find(uri);
    GrantInfo info = { flag, fromTokenId, targetTokenId };
    if (search == uriMap_.end()) {
        std::list<GrantInfo> infoList = { info };
        uriMap_.emplace(uri, infoList);
        return ERR_OK;
    }
    auto& infoList = search->second;
    for (auto& item : infoList) {
        if (item.fromTokenId == fromTokenId && item.targetTokenId == targetTokenId) {
            TAG_LOGI(AAFwkTag::URIPERMMGR, "Item: flag:%{public}u", item.flag);
            if ((item.flag & flag) != flag) {
                item.flag |= flag;
                return ERR_OK;
            }
            return ERR_OK;
        }
    }
    infoList.emplace_back(info);
    return ERR_OK;
}

ErrCode UriPermissionManagerStubImpl::CheckGrantUriPermissionPrivileged(uint32_t callerTokenId, uint32_t flag,
    int32_t& funcResult)
{
    auto permissionName = PermissionConstants::PERMISSION_GRANT_URI_PERMISSION_PRIVILEGED;
    if (!PermissionVerification::GetInstance()->VerifyPermissionByTokenId(callerTokenId, permissionName)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "No permission to call");
        funcResult = CHECK_PERMISSION_FAILED;
        return CHECK_PERMISSION_FAILED;
    }
    if ((flag & FLAG_READ_WRITE_URI) == 0) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "invalid flag:%{public}u", flag);
        funcResult = ERR_CODE_INVALID_URI_FLAG;
        return ERR_CODE_INVALID_URI_FLAG;
    }
    return ERR_OK;
}

ErrCode UriPermissionManagerStubImpl::GrantUriPermissionPrivileged(const std::vector<std::string>& uriVec,
    uint32_t flag, const std::string& targetBundleName, int32_t appIndex, uint32_t initiatorTokenId,
    int32_t hideSensitiveType, int32_t& funcResult)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (uriVec.size() == 0 || uriVec.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "out of range: %{public}zu", uriVec.size());
        funcResult = ERR_URI_LIST_OUT_OF_RANGE;
        return ERR_URI_LIST_OUT_OF_RANGE;
    }
    TAG_LOGI(AAFwkTag::URIPERMMGR, "BundleName:%{public}s, appIndex:%{public}d, flag:%{public}u, uris:%{public}zu",
        targetBundleName.c_str(), appIndex, flag, uriVec.size());
    uint32_t callerTokenId = IPCSkeleton::GetCallingTokenID();
    auto checkRes = CheckGrantUriPermissionPrivileged(callerTokenId, flag, funcResult);
    if (checkRes != ERR_OK) {
        return ERR_OK;
    }
    uint32_t targetTokenId = 0;
    auto ret = UPMSUtils::GetTokenIdByBundleName(targetBundleName, appIndex, targetTokenId);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "get tokenId failed, bundleName:%{public}s", targetBundleName.c_str());
        funcResult = ret;
        return ERR_OK;
    }
    if (UPMSUtils::IsFoundationCall()) {
        callerTokenId = initiatorTokenId;
    } else {
        // hideSensitiveType is only support for foundation
        hideSensitiveType = 0;
    }
    std::string targetAlterBundleName = "";
    UPMSUtils::GetDirByBundleNameAndAppIndex(targetBundleName, appIndex, targetAlterBundleName);
    std::vector<Uri> uriVecInner;
    for (auto& uri : uriVec) {
        uriVecInner.emplace_back(uri);
    }
    UPMSAppInfo targetAppInfo = { targetTokenId, targetBundleName, targetAlterBundleName };
    ret = GrantUriPermissionPrivilegedInner(uriVecInner, flag, callerTokenId, targetAppInfo, hideSensitiveType);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "GrantUriPermissionPrivileged finished.");
    funcResult = ret;
    return ERR_OK;
}

ErrCode UriPermissionManagerStubImpl::GrantUriPermissionPrivileged(const UriPermissionRawData& rawData, uint32_t flag,
    const std::string& targetBundleName, int32_t appIndex, uint32_t initiatorTokenId, int32_t hideSensitiveType,
    int32_t& funcResult)
{
    std::vector<std::string> uriStrVec;
    auto res = RawDataToStringVec(rawData, uriStrVec);
    if (res != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "raw data to vec failed");
        funcResult = res;
        return res;
    }
    auto errCode = GrantUriPermissionPrivileged(uriStrVec, flag, targetBundleName, appIndex, initiatorTokenId,
        hideSensitiveType, funcResult);
    if (errCode != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "GrantUriPermissionPrivileged failed, errCode:%{public}d", errCode);
        return errCode;
    }
    TAG_LOGI(AAFwkTag::URIPERMMGR, "GrantUriPermissionPrivileged finished.");
    return ERR_OK;
}

int32_t UriPermissionManagerStubImpl::GrantUriPermissionPrivilegedInner(const std::vector<Uri> &uriVec, uint32_t flag,
    uint32_t callerTokenId, UPMSAppInfo &targetAppInfo, int32_t hideSensitiveType)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "callerTokenId:%{public}u, targetTokenId:%{public}u", callerTokenId,
        targetAppInfo.tokenId);
    BatchStringUri batchUris;
    int32_t validUriCount = 0;
    int32_t grantRet = INNER_ERR;
    for (auto &uri : uriVec) {
        auto uriInner = uri;
        if (!UPMSUtils::CheckUriTypeIsValid(uriInner)) {
            continue;
        }
        validUriCount++;
        // content and distributed docs uri
        if (uriInner.GetScheme() == "content") {
            batchUris.contentUris.emplace_back(uriInner.ToString());
            continue;
        }
        if (UPMSUtils::IsDocsCloudUri(uriInner)) {
            batchUris.uriStrVec.emplace_back(uriInner.ToString());
            continue;
        }
        if (uriInner.GetAuthority() == targetAppInfo.alterBundleName) {
            grantRet = ERR_OK;
            continue;
        }
        // media
        if (uriInner.GetAuthority() == "media") {
            batchUris.mediaUriVec.emplace_back(uriInner.ToString());
            continue;
        }
        // docs and bundle
        batchUris.uriStrVec.emplace_back(uri.ToString());
    }
    TAG_LOGI(AAFwkTag::URIPERMMGR, "valid uris: %{public}d", validUriCount);
    if (validUriCount == 0) {
        return ERR_CODE_INVALID_URI_TYPE;
    }
    if (GrantUriPermissionPrivilegedImpl(batchUris, flag, callerTokenId, targetAppInfo,
        hideSensitiveType) == ERR_OK) {
        return ERR_OK;
    }
    return grantRet;
}

int32_t UriPermissionManagerStubImpl::GrantUriPermissionPrivilegedImpl(BatchStringUri &batchUris, uint32_t flag,
    uint32_t callerTokenId, UPMSAppInfo &targetAppInfo, int32_t hideSensitiveType)
{
    int32_t result = INNER_ERR;
    if (GrantBatchUriPermissionImpl(batchUris.uriStrVec, flag, callerTokenId, targetAppInfo.tokenId) == ERR_OK) {
        result = ERR_OK;
    }
    if (GrantBatchMediaUriPermissionImpl(batchUris.mediaUriVec, flag, callerTokenId, targetAppInfo.tokenId,
        hideSensitiveType) == ERR_OK) {
        result = ERR_OK;
    }
    if (GrantBatchContentUriPermissionImpl(batchUris.contentUris, flag, targetAppInfo.tokenId,
        targetAppInfo.bundleName) == ERR_OK) {
        result = ERR_OK;
    }
    return result;
}

ErrCode UriPermissionManagerStubImpl::CheckUriAuthorization(const std::vector<std::string>& uriStrVec,
    uint32_t flag, uint32_t tokenId, std::vector<bool>& funcResult)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "tokenId:%{private}u, flag:%{public}u, uris:%{public}zu",
        tokenId, flag, uriStrVec.size());
    funcResult = std::vector<bool>(uriStrVec.size(), false);
    if (uriStrVec.size() == 0 || uriStrVec.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "uriVec empty or exceed maxSize %{public}d", MAX_URI_COUNT);
        return ERR_URI_LIST_OUT_OF_RANGE;
    }
    if (!UPMSUtils::IsSAOrSystemAppCall()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "not SA/SystemApp");
        return ERR_OK;
    }
    if ((flag & FLAG_READ_WRITE_URI) == 0) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Flag invalid");
        return ERR_OK;
    }
    std::vector<Uri> uriVec;
    for (auto& uriStr: uriStrVec) {
        uriVec.emplace_back(uriStr);
    }
    TokenIdPermission tokenIdPermission(tokenId);
    funcResult = CheckUriPermission(tokenIdPermission, uriVec, flag);
    return ERR_OK;
}

ErrCode UriPermissionManagerStubImpl::CheckUriAuthorization(const UriPermissionRawData& rawData, uint32_t flag,
    uint32_t tokenId, UriPermissionRawData& funcResult)
{
    std::vector<std::string> uriStringVec;
    std::vector<char> resultCharVec;
    auto res = RawDataToStringVec(rawData, uriStringVec);
    if (res != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "raw data to vec failed");
        std::vector<bool> defaultFalseResult(1, false);
        BoolVecToRawData(defaultFalseResult, funcResult, resultCharVec);
        return res;
    }
    std::vector<bool> resultBoolVec(uriStringVec.size(), false);
    auto errCode = CheckUriAuthorization(uriStringVec, flag, tokenId, resultBoolVec);
    if (errCode != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "CheckUriAuthorization failed, errCode:%{public}d", errCode);
        return errCode;
    }
    BoolVecToRawData(resultBoolVec, funcResult, resultCharVec);
    if (funcResult.size > MAX_IPC_RAW_DATA_SIZE) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "funcResultSize is too large");
        std::vector<bool> defaultFalseResult(1, false);
        BoolVecToRawData(defaultFalseResult, funcResult, resultCharVec);
        return ERR_DEAD_OBJECT;
    }
    return ERR_OK;
}

std::vector<bool> UriPermissionManagerStubImpl::CheckUriPermission(TokenIdPermission& tokenIdPermission,
    const std::vector<Uri>& uriVec, uint32_t flag)
{
    // only reserve read and write file flag
    flag &= FLAG_READ_WRITE_URI;
    auto tokenId = tokenIdPermission.GetTokenId();
    std::vector<bool> result(uriVec.size(), false);
    std::vector<Uri> mediaUris;
    std::vector<int32_t> mediaUriIndexs;
    std::string callerAlterableBundleName;
    UPMSUtils::GetAlterableBundleNameByTokenId(tokenId, callerAlterableBundleName);
    for (size_t i = 0; i < uriVec.size(); i++) {
        auto uri = uriVec[i];
        auto &&scheme = uri.GetScheme();
        // checkUriPermission not support content uri
        if (scheme != "file") {
            TAG_LOGW(AAFwkTag::URIPERMMGR, "invalid uri:%{private}s", uri.ToString().c_str());
            result[i] = false;
            continue;
        }
        auto &&authority = uri.GetAuthority();
        TAG_LOGD(AAFwkTag::URIPERMMGR, "UriAuth:%{public}s", authority.c_str());
        if (authority == "docs" && tokenIdPermission.VerifyFileAccessManagerPermission()) {
            result[i] = true;
            continue;
        }
        if (authority == "media") {
            mediaUris.emplace_back(uri);
            mediaUriIndexs.emplace_back(i);
            continue;
        }
        // bundle uri
        result[i] = (authority == callerAlterableBundleName);
    }
#ifdef ABILITY_RUNTIME_MEDIA_LIBRARY_ENABLE
    if (!mediaUris.empty()) {
        auto mediaUriResult = MediaPermissionManager::GetInstance().CheckUriPermission(mediaUris, tokenId, flag);
        for (size_t i = 0; i < mediaUriResult.size(); i++) {
            result[mediaUriIndexs[i]] = mediaUriResult[i];
        }
    }
#endif // ABILITY_RUNTIME_MEDIA_LIBRARY_ENABLE
    CheckProxyUriPermission(tokenIdPermission, uriVec, flag, result);
    return result;
}

void UriPermissionManagerStubImpl::CheckProxyUriPermission(TokenIdPermission &tokenIdPermission,
    const std::vector<Uri> &uriVec, uint32_t flag, std::vector<bool> &result)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "Call");
    if (uriVec.size() != result.size()) {
        TAG_LOGW(AAFwkTag::URIPERMMGR, "param size not equal");
        return;
    }
    if (!tokenIdPermission.VerifyProxyAuthorizationUriPermission()) {
        TAG_LOGW(AAFwkTag::URIPERMMGR, "no proxy permission");
        return;
    }
    auto tokenId = tokenIdPermission.GetTokenId();
    for (size_t i = 0; i < uriVec.size(); i++) {
        if (result[i]) {
            continue;
        }
        // media no need to check proxy permission, has checked by medialibrary
        auto uriInner = uriVec[i];
        if (uriInner.GetAuthority() != "media") {
            bool funcResult = false;
            VerifyUriPermission(uriInner, flag, tokenId, funcResult);
            result[i] = funcResult;
        }
    }
}

void UriPermissionManagerStubImpl::RevokeMapUriPermission(uint32_t tokenId)
{
    // revoke uri permission record cache of tokenId when application exit
    TAG_LOGD(AAFwkTag::URIPERMMGR, "RevokeMapUriPermission call");
    std::lock_guard<std::mutex> guard(mutex_);
    std::vector<std::string> uriList;
    int32_t deleteCount = 0;
    for (auto iter = uriMap_.begin(); iter != uriMap_.end();) {
        auto& list = iter->second;
        bool findUriRecord = false;
        for (auto it = list.begin(); it != list.end();) {
            if (it->targetTokenId == tokenId) {
                deleteCount++;
                it = list.erase(it);
                findUriRecord = true;
                continue;
            }
            it++;
        }
        if (findUriRecord) {
            uriList.emplace_back(iter->first);
        }
        if (list.empty()) {
            iter = uriMap_.erase(iter);
            continue;
        }
        ++iter;
    }
    if (!uriList.empty()) {
        DeleteShareFile(tokenId, uriList);
    }
    TAG_LOGI(AAFwkTag::URIPERMMGR, "revoke map: %{public}d", deleteCount);
}

ErrCode UriPermissionManagerStubImpl::RevokeAllUriPermissions(uint32_t tokenId, int32_t& funcResult)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "RevokeAllUriPermissions, tokenId:%{public}u", tokenId);
    if (!UPMSUtils::IsFoundationCall()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "No permission to revoke all uri permission");
        funcResult = CHECK_PERMISSION_FAILED;
        return ERR_OK;
    }
    RevokeAllMapUriPermissions(tokenId);
    RevokeContentUriPermission(tokenId);
    funcResult = ERR_OK;
    return ERR_OK;
}

int32_t UriPermissionManagerStubImpl::RevokeAllMapUriPermissions(uint32_t tokenId)
{
    std::string callerAuthority = "";
    UPMSUtils::GetAlterableBundleNameByTokenId(tokenId, callerAuthority);
    std::map<uint32_t, std::vector<std::string>> uriLists;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        for (auto iter = uriMap_.begin(); iter != uriMap_.end();) {
            auto uriAuthority = Uri(iter->first).GetAuthority();
            // uri belong to target tokenId.
            if (callerAuthority == uriAuthority) {
                for (const auto &record : iter->second) {
                    uriLists[record.targetTokenId].emplace_back(iter->first);
                }
                iter = uriMap_.erase(iter);
                continue;
            }
            auto& list = iter->second;
            for (auto it = list.begin(); it != list.end();) {
                if (it->targetTokenId == tokenId || it->fromTokenId == tokenId) {
                    TAG_LOGI(AAFwkTag::URIPERMMGR, "Erase an uri permission record");
                    uriLists[it->targetTokenId].emplace_back(iter->first);
                    it = list.erase(it);
                    continue;
                }
                it++;
            }
            if (list.empty()) {
                iter = uriMap_.erase(iter);
                continue;
            }
            iter++;
        }
    }

    for (auto iter = uriLists.begin(); iter != uriLists.end(); iter++) {
        if (DeleteShareFile(iter->first, iter->second) != ERR_OK) {
            return INNER_ERR;
        }
    }
    return ERR_OK;
}

ErrCode UriPermissionManagerStubImpl::RevokeUriPermissionManually(const Uri& uri, const std::string& bundleName,
    int32_t appIndex, int32_t& funcResult)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "uri:%{private}s, bundleName:%{public}s, appIndex:%{public}d",
        uri.ToString().c_str(), bundleName.c_str(), appIndex);
    if (!UPMSUtils::IsSAOrSystemAppCall()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "not SA/SystemApp");
        funcResult = CHECK_PERMISSION_FAILED;
        return ERR_OK;
    }
    auto uriInner = uri;
    if (!UPMSUtils::CheckUriTypeIsValid(uriInner)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "CheckUriType failed, uri:%{private}s", uri.ToString().c_str());
        funcResult = ERR_CODE_INVALID_URI_TYPE;
        return ERR_OK;
    }
    uint32_t targetTokenId = 0;
    auto ret = UPMSUtils::GetTokenIdByBundleName(bundleName, appIndex, targetTokenId);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "get tokenId by bundleName fail");
        funcResult = ret;
        return ERR_OK;
    }
    funcResult = RevokeUriPermissionManuallyInner(uriInner, targetTokenId);
    return ERR_OK;
}

int32_t UriPermissionManagerStubImpl::RevokeUriPermissionManuallyInner(Uri &uri, uint32_t targetTokenId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto callerTokenId = IPCSkeleton::GetCallingTokenID();
    TAG_LOGI(AAFwkTag::URIPERMMGR, "callerTokenId: %{public}u, targetTokenId:%{public}u",
        callerTokenId, targetTokenId);
    
    if (UPMSUtils::IsDocsCloudUri(uri)) {
        return RevokeMapUriPermissionManually(callerTokenId, targetTokenId, uri);
    }
    if (uri.GetAuthority() == "media") {
        return RevokeMediaUriPermissionManually(callerTokenId, targetTokenId, uri);
    }
    // docs and bundle uri
    return RevokeMapUriPermissionManually(callerTokenId, targetTokenId, uri);
}

int32_t UriPermissionManagerStubImpl::RevokeMapUriPermissionManually(uint32_t callerTokenId,
    uint32_t targetTokenId, Uri &uri)
{
    auto uriStr = uri.ToString();
    auto uriAuthority = uri.GetAuthority();
    // uri belong to caller or caller is target.
    std::string callerAuthority = "";
    UPMSUtils::GetAlterableBundleNameByTokenId(callerTokenId, callerAuthority);
    bool isRevokeSelfUri = (callerTokenId == targetTokenId || callerAuthority == uriAuthority);
    std::vector<std::string> uriList;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        auto search = uriMap_.find(uriStr);
        if (search == uriMap_.end()) {
            TAG_LOGI(AAFwkTag::URIPERMMGR, "URI not exist on uri map");
            return ERR_OK;
        }
        auto& list = search->second;
        for (auto it = list.begin(); it != list.end(); it++) {
            if (it->targetTokenId == targetTokenId && (callerTokenId == it->fromTokenId || isRevokeSelfUri)) {
                uriList.emplace_back(search->first);
                TAG_LOGD(AAFwkTag::URIPERMMGR, "revoke uri permission record");
                list.erase(it);
                break;
            }
        }
        if (list.empty()) {
            uriMap_.erase(search);
        }
    }
    return DeleteShareFile(targetTokenId, uriList);
}

int32_t UriPermissionManagerStubImpl::DeleteShareFile(uint32_t targetTokenId, const std::vector<std::string> &uriVec)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    ConnectManager(storageManager_, STORAGE_MANAGER_MANAGER_ID);
    if (storageManager_ == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "null StorageManager");
        return INNER_ERR;
    }
    auto ret = storageManager_->DeleteShareFile(targetTokenId, uriVec);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "DeleteShareFile failed:%{public}d", ret);
    }
    return ret;
}

int32_t UriPermissionManagerStubImpl::RevokeMediaUriPermissionManually(uint32_t callerTokenId, uint32_t targetTokenId,
    Uri &uri)
{
#ifdef ABILITY_RUNTIME_MEDIA_LIBRARY_ENABLE
    std::string uriStr = uri.ToString();
    return MediaPermissionManager::GetInstance().RevokeUriPermission(callerTokenId, targetTokenId, uriStr);
#else
    return CAPABILITY_NOT_SUPPORT;
#endif // ABILITY_RUNTIME_MEDIA_LIBRARY_ENABLE
}

template<typename T>
void UriPermissionManagerStubImpl::ConnectManager(sptr<T> &mgr, int32_t serviceId)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "Call");
    std::lock_guard<std::mutex> lock(mgrMutex_);
    if (mgr == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "mgr null");
        auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemAbilityMgr == nullptr) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "null systemAbilityMgr");
            return;
        }

        auto remoteObj = systemAbilityMgr->GetSystemAbility(serviceId);
        if (remoteObj == nullptr) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "null Obj");
            return;
        }
        TAG_LOGE(AAFwkTag::URIPERMMGR, "to cast");
        mgr = iface_cast<T>(remoteObj);
        if (mgr == nullptr || mgr->AsObject() == nullptr) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "null mgr");
            return;
        }
        wptr<T> manager = mgr;
        auto self = weak_from_this();
        auto onClearProxyCallback = [manager, self](const auto& remote) {
            auto mgrSptr = manager.promote();
            auto impl = self.lock();
            if (impl && mgrSptr && mgrSptr->AsObject() == remote.promote()) {
                std::lock_guard<std::mutex> lock(impl->mgrMutex_);
                mgrSptr.clear();
            }
        };
        sptr<ProxyDeathRecipient> recipient(new ProxyDeathRecipient(std::move(onClearProxyCallback)));
        if (!mgr->AsObject()->AddDeathRecipient(recipient)) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "AddDeathRecipient failed");
        }
    }
}

void UriPermissionManagerStubImpl::ProxyDeathRecipient::OnRemoteDied([[maybe_unused]]
    const wptr<IRemoteObject>& remote)
{
    if (proxy_) {
        TAG_LOGD(AAFwkTag::URIPERMMGR, "mgr stub died");
        proxy_(remote);
    }
}

int32_t UriPermissionManagerStubImpl::CheckCalledBySandBox()
{
    // reject sandbox to grant uri permission
    ConnectManager(appMgr_, APP_MGR_SERVICE_ID);
    if (appMgr_ == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "appMgr null");
        return INNER_ERR;
    }
    auto callerPid = IPCSkeleton::GetCallingPid();
    bool isSandbox = false;
    if (IN_PROCESS_CALL(appMgr_->JudgeSandboxByPid(callerPid, isSandbox)) != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "JudgeSandboxByPid failed");
        return INNER_ERR;
    }
    if (isSandbox) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "sandbox app not grant URI permission");
        return ERR_CODE_GRANT_URI_PERMISSION;
    }
    return ERR_OK;
}

ErrCode UriPermissionManagerStubImpl::ClearPermissionTokenByMap(const uint32_t tokenId, int32_t& funcResult)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    bool isCallingPermission =
        AAFwk::PermissionVerification::GetInstance()->CheckSpecificSystemAbilityAccessPermission(FOUNDATION_PROCESS);
    if (!isCallingPermission) {
        TAG_LOGE(AAFwkTag::APPMGR, "verification failed");
        funcResult = ERR_PERMISSION_DENIED;
        return ERR_OK;
    }
    RevokeContentUriPermission(tokenId);
    std::lock_guard<std::mutex> lock(ptMapMutex_);
    if (permissionTokenMap_.find(tokenId) == permissionTokenMap_.end()) {
        TAG_LOGD(AAFwkTag::URIPERMMGR, "permissionTokenMap_ empty");
        funcResult = ERR_OK;
        return ERR_OK;
    }
    RevokeMapUriPermission(tokenId);
#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
    uint64_t timeNow = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count());
    TAG_LOGD(AAFwkTag::URIPERMMGR, "clear %{private}d permission", tokenId);
    auto ret = SandboxManagerKit::UnSetAllPolicyByToken(tokenId, timeNow);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "clear permission end");
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "ClearPermission failed, ret is %{public}d", ret);
        funcResult = ret;
        return ERR_OK;
    }
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
    permissionTokenMap_.erase(tokenId);
    funcResult = ERR_OK;
    return ERR_OK;
}

void UriPermissionManagerStubImpl::BoolVecToCharVec(const std::vector<bool>& boolVector, std::vector<char>& charVector)
{
    charVector.clear();
    if (boolVector.empty()) {
        return;
    }
    for (bool b : boolVector) {
        char value = b ? static_cast<char>(1) : static_cast<char>(0);
        charVector.push_back(value);
    }
}

void UriPermissionManagerStubImpl::BoolVecToRawData(const std::vector<bool>& boolVector, UriPermissionRawData& rawData,
    std::vector<char>& charVector)
{
    BoolVecToCharVec(boolVector, charVector);
    std::stringstream ss;
    uint32_t boolCount = boolVector.size();
    ss.write(reinterpret_cast<const char *>(&boolCount), sizeof(boolCount));
    for (uint32_t i = 0; i < boolCount; i++) {
        ss.write(reinterpret_cast<const char *>(&charVector[i]), sizeof(boolVector[i]));
    }
    std::string result = ss.str();
    rawData.ownedData = std::move(result);
    rawData.data = rawData.ownedData.data();
    rawData.size = rawData.ownedData.size();
}

ErrCode UriPermissionManagerStubImpl::RawDataToStringVec(const UriPermissionRawData& rawData,
    std::vector<std::string>& stringVec)
{
    if (rawData.data == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "null data");
        return ERR_DEAD_OBJECT;
    }
    if (rawData.size == 0 || rawData.size > MAX_IPC_RAW_DATA_SIZE) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "size invalid: %{public}u", rawData.size);
        return ERR_DEAD_OBJECT;
    }
    std::stringstream ss;
    ss.write(reinterpret_cast<const char *>(rawData.data), rawData.size);
    uint32_t stringVecSize = 0;
    ss.read(reinterpret_cast<char *>(&stringVecSize), sizeof(stringVecSize));
    uint32_t ssLength = static_cast<uint32_t>(ss.str().length());
    for (uint32_t i = 0; i < stringVecSize; i++) {
        uint32_t strLen = 0;
        ss.read(reinterpret_cast<char *>(&strLen), sizeof(strLen));
        if (strLen > ssLength - static_cast<uint32_t>(ss.tellg())) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "string length:%{public}u is invalid", strLen);
            return ERR_DEAD_OBJECT;
        }
        std::string str;
        str.resize(strLen);
        ss.read(&str[0], strLen);
        stringVec.emplace_back(str);
    }
    if (stringVec.empty() || stringVec.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "uriVec empty or exceed maxSize %{public}d", MAX_URI_COUNT);
        return ERR_URI_LIST_OUT_OF_RANGE;
    }
    return ERR_OK;
}

#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
ErrCode UriPermissionManagerStubImpl::Active(const UriPermissionRawData& policyRawData, std::vector<uint32_t>& res,
    int32_t& funcResult)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    TAG_LOGD(AAFwkTag::URIPERMMGR, "active %{private}d permission", tokenId);
    auto permissionName = PermissionConstants::PERMISSION_FILE_ACCESS_PERSIST;
    if (!PermissionVerification::GetInstance()->VerifyPermissionByTokenId(tokenId, permissionName)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "No permission to call");
        funcResult = SANDBOX_MANAGER_PERMISSION_DENIED;
        return ERR_OK;
    }
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    std::vector<PolicyInfo> policy;
    auto result = RawDataToPolicyInfo(policyRawData, policy);
    if (!result) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "RawDataToPolicyInfo failed");
        funcResult = INVALID_PARAMETERS_ERR;
        return funcResult;
    }
    if (policy.empty() || policy.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "policy empty or exceed maxSize %{public}d", MAX_URI_COUNT);
        return ERR_URI_LIST_OUT_OF_RANGE;
    }
    uint64_t timeNow = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count());
    auto ret = SandboxManagerKit::StartAccessingPolicy(policy, res, false, tokenId, timeNow);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "active permission end");
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "StartAccessingPolicy failed, ret is %{public}d", ret);
        funcResult = ret;
        return ERR_OK;
    }
    std::lock_guard<std::mutex> lock(ptMapMutex_);
    permissionTokenMap_.insert(tokenId);
    funcResult = ERR_OK;
    return ERR_OK;
}

bool UriPermissionManagerStubImpl::RawDataToPolicyInfo(const UriPermissionRawData& policyRawData,
    std::vector<PolicyInfo>& policy)
{
    std::stringstream ss;
    ss.write(reinterpret_cast<const char *>(policyRawData.data), policyRawData.size);
    ss.seekg(0, std::ios::beg);
    uint32_t ssLength = static_cast<uint32_t>(ss.str().length());
    uint32_t policyInfoSize = 0;
    ss.read(reinterpret_cast<char *>(&policyInfoSize), sizeof(policyInfoSize));
    for (uint32_t i = 0; i < policyInfoSize; i++) {
        uint32_t pathLen = 0;
        ss.read(reinterpret_cast<char *>(&pathLen), sizeof(pathLen));
        if (pathLen > ssLength - static_cast<uint32_t>(ss.tellg())) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "path eln:%{public}u is invalid", pathLen);
            return false;
        }
        PolicyInfo info;
        info.path.resize(pathLen);
        ss.read(info.path.data(), pathLen);
        ss.read(reinterpret_cast<char *>(&info.mode), sizeof(info.mode));
        policy.emplace_back(info);
    }
    return true;
}
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
}  // namespace AAFwk
}  // namespace OHOS
