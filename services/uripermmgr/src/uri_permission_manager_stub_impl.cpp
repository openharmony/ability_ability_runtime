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

#include "uri_permission_manager_stub_impl.h"

#include "ability_manager_errors.h"
#include "accesstoken_kit.h"
#include "app_utils.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "if_system_ability_manager.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "media_permission_manager.h"
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
constexpr int32_t INVALID_PARAMTER = 2; // SandboxManager ative err
constexpr uint32_t FLAG_READ_WRITE_URI = Want::FLAG_AUTH_READ_URI_PERMISSION | Want::FLAG_AUTH_WRITE_URI_PERMISSION;
constexpr uint32_t FLAG_WRITE_URI = Want::FLAG_AUTH_WRITE_URI_PERMISSION;
constexpr uint32_t FLAG_READ_URI = Want::FLAG_AUTH_READ_URI_PERMISSION;
constexpr const char* CLOUND_DOCS_URI_MARK = "?networkid=";
constexpr const char* FOUNDATION_PROCESS = "foundation";
}

bool UriPermissionManagerStubImpl::VerifyUriPermission(const Uri &uri, uint32_t flag, uint32_t tokenId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    // verify if tokenId have uri permission record
    TAG_LOGI(AAFwkTag::URIPERMMGR, "uri:%{private}s, flag:%{public}u, tokenId:%{public}u",
        uri.ToString().c_str(), flag, tokenId);
    if (!UPMSUtils::IsSAOrSystemAppCall()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "not SA/SystemApp");
        return false;
    }
    if ((flag & FLAG_READ_WRITE_URI) == 0) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Flag invalid");
        return false;
    }
    // only reserve read and write file flag
    flag &= FLAG_READ_WRITE_URI;
    auto uriInner = uri;
    if (!UPMSUtils::CheckUriTypeIsValid(uriInner)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "type of uri is valid");
        return false;
    }
    if (uriInner.GetScheme() == "file" && uriInner.GetAuthority() == "media") {
        TAG_LOGW(AAFwkTag::URIPERMMGR, "not support media uri");
        return false;
    }
    std::vector<Uri> uriVec = { uriInner };
    auto result = VerifyUriPermissionByMap(uriVec, flag, tokenId);
    if (!result[0]) {
        TAG_LOGI(AAFwkTag::URIPERMMGR, "uri permission not exists");
    }
    return result[0];
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
    return iTempUri.find(cTempUri + "/") == 0;
}

int UriPermissionManagerStubImpl::GrantUriPermission(const Uri &uri, unsigned int flag,
    const std::string targetBundleName, int32_t appIndex, uint32_t initiatorTokenId)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "Uri:%{private}s", uri.ToString().c_str());
    std::vector<Uri> uriVec = { uri };
    if (UPMSUtils::IsSystemAppCall() && uriVec[0].GetScheme() != "file") {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Only support file uri");
        return ERR_CODE_INVALID_URI_TYPE;
    }
    return GrantUriPermission(uriVec, flag, targetBundleName, appIndex, initiatorTokenId);
}

int UriPermissionManagerStubImpl::GrantUriPermission(const std::vector<Uri> &uriVec, unsigned int flag,
    const std::string targetBundleName, int32_t appIndex, uint32_t initiatorTokenId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "BundleName:%{public}s, appIndex:%{public}d, flag:%{public}u, uris:%{public}zu",
        targetBundleName.c_str(), appIndex, flag, uriVec.size());
    if (!UPMSUtils::IsSAOrSystemAppCall()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "not SA/SystemApp");
        return CHECK_PERMISSION_FAILED;
    }
    auto checkResult = CheckCalledBySandBox();
    if (checkResult != ERR_OK) {
        return checkResult;
    }
    if ((flag & FLAG_READ_WRITE_URI) == 0) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "invalid flag: %{public}u", flag);
        return ERR_CODE_INVALID_URI_FLAG;
    }
    uint32_t targetTokenId = 0;
    auto ret = UPMSUtils::GetTokenIdByBundleName(targetBundleName, appIndex, targetTokenId);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "get tokenId by bundle name failed");
        return ret;
    }
    uint32_t callerTokenId = initiatorTokenId;
    if (!UPMSUtils::IsFoundationCall()) {
        callerTokenId = IPCSkeleton::GetCallingTokenID();
    }

    return GrantUriPermissionInner(uriVec, flag, callerTokenId, targetTokenId, targetBundleName);
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
    auto resVec = storageManager_->CreateShareFile(uriVec, targetTokenId, flag);
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
        TAG_LOGI(AAFwkTag::URIPERMMGR, "Insert an uri r/w permission");
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
                TAG_LOGI(AAFwkTag::URIPERMMGR, "Update uri r/w permission");
                return ERR_OK;
            }
            TAG_LOGD(AAFwkTag::URIPERMMGR, "Uri has been granted");
            return ERR_OK;
        }
    }
    TAG_LOGI(AAFwkTag::URIPERMMGR, "insert new uri permission record");
    infoList.emplace_back(info);
    return ERR_OK;
}

int32_t UriPermissionManagerStubImpl::GrantUriPermissionPrivileged(const std::vector<Uri> &uriVec, uint32_t flag,
    const std::string &targetBundleName, int32_t appIndex, uint32_t initiatorTokenId, int32_t hideSensitiveType)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "BundleName:%{public}s, appIndex:%{public}d, flag:%{public}u, uris:%{public}zu",
        targetBundleName.c_str(), appIndex, flag, uriVec.size());

    uint32_t callerTokenId = IPCSkeleton::GetCallingTokenID();
    auto permissionName = PermissionConstants::PERMISSION_GRANT_URI_PERMISSION_PRIVILEGED;
    if (!PermissionVerification::GetInstance()->VerifyPermissionByTokenId(callerTokenId, permissionName)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "No permission to call");
        return CHECK_PERMISSION_FAILED;
    }

    if ((flag & FLAG_READ_WRITE_URI) == 0) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "invalid flag:%{public}u", flag);
        return ERR_CODE_INVALID_URI_FLAG;
    }
    uint32_t targetTokenId = 0;
    auto ret = UPMSUtils::GetTokenIdByBundleName(targetBundleName, appIndex, targetTokenId);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "get tokenId failed, bundleName:%{public}s", targetBundleName.c_str());
        return ret;
    }
    if (UPMSUtils::IsFoundationCall()) {
        callerTokenId = initiatorTokenId;
    } else {
        // hideSensitiveType is only support for foundation
        hideSensitiveType = 0;
    }
    std::string targetAlterBundleName = "";
    UPMSUtils::GetDirByBundleNameAndAppIndex(targetBundleName, appIndex, targetAlterBundleName);
    ret = GrantUriPermissionPrivilegedInner(uriVec, flag, callerTokenId, targetTokenId, targetAlterBundleName,
        hideSensitiveType);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "GrantUriPermissionPrivileged finished.");
    return ret;
}

int32_t UriPermissionManagerStubImpl::GrantUriPermissionPrivilegedInner(const std::vector<Uri> &uriVec, uint32_t flag,
    uint32_t callerTokenId, uint32_t targetTokenId, const std::string &targetAlterBundleName,
    int32_t hideSensitiveType)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "callerTokenId:%{public}u, targetTokenId:%{public}u", callerTokenId, targetTokenId);
    std::vector<std::string> uriStrVec;
    std::vector<std::string> mediaUriVec;
    int32_t validUriCount = 0;
    int32_t grantRet = INNER_ERR;
    for (auto &uri : uriVec) {
        auto uriInner = uri;
        if (!UPMSUtils::CheckUriTypeIsValid(uriInner)) {
            continue;
        }
        validUriCount++;
        // content and distributed docs uri
        if (uriInner.GetScheme() == "content" || UPMSUtils::IsDocsCloudUri(uriInner)) {
            uriStrVec.emplace_back(uriInner.ToString());
            continue;
        }
        if (uriInner.GetAuthority() == targetAlterBundleName) {
            grantRet = ERR_OK;
            continue;
        }
        // media
        if (uriInner.GetAuthority() == "media") {
            mediaUriVec.emplace_back(uriInner.ToString());
            continue;
        }
        // docs and bundle
        uriStrVec.emplace_back(uri.ToString());
    }
    TAG_LOGI(AAFwkTag::URIPERMMGR, "valid uris: %{public}d", validUriCount);
    if (validUriCount == 0) {
        return ERR_CODE_INVALID_URI_TYPE;
    }
    if (GrantBatchUriPermissionImpl(uriStrVec, flag, callerTokenId, targetTokenId) == ERR_OK) {
        grantRet = ERR_OK;
    }
    if (GrantBatchMediaUriPermissionImpl(mediaUriVec, flag, callerTokenId, targetTokenId,
        hideSensitiveType) == ERR_OK) {
        grantRet = ERR_OK;
    }
    return grantRet;
}

std::vector<bool> UriPermissionManagerStubImpl::CheckUriAuthorization(const std::vector<std::string> &uriStrVec,
    uint32_t flag, uint32_t tokenId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "tokenId:%{public}u, flag:%{public}u, uris:%{public}zu",
        tokenId, flag, uriStrVec.size());
    if (!UPMSUtils::IsSAOrSystemAppCall()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "not SA/SystemApp");
        std::vector<bool> result(uriStrVec.size(), false);
        return result;
    }
    if ((flag & FLAG_READ_WRITE_URI) == 0) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Flag invalid");
        std::vector<bool> result(uriStrVec.size(), false);
        return result;
    }
    std::vector<Uri> uriVec;
    for (auto &uriStr: uriStrVec) {
        uriVec.emplace_back(uriStr);
    }
    TokenIdPermission tokenIdPermission(tokenId);
    return CheckUriPermission(tokenIdPermission, uriVec, flag);
}

std::vector<bool> UriPermissionManagerStubImpl::CheckUriPermission(TokenIdPermission &tokenIdPermission,
    const std::vector<Uri> &uriVec, uint32_t flag)
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
    if (!mediaUris.empty()) {
        auto mediaUriResult = MediaPermissionManager::GetInstance().CheckUriPermission(mediaUris, tokenId, flag);
        for (size_t i = 0; i < mediaUriResult.size(); i++) {
            result[mediaUriIndexs[i]] = mediaUriResult[i];
        }
    }
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
            result[i] = VerifyUriPermission(uriInner, flag, tokenId);
        }
    }
}

void UriPermissionManagerStubImpl::RevokeMapUriPermission(uint32_t tokenId)
{
    // revoke uri permission record cache of tokenId when application exit
    TAG_LOGD(AAFwkTag::URIPERMMGR, "RevokeMapUriPermission call");
    std::lock_guard<std::mutex> guard(mutex_);
    std::vector<std::string> uriList;
    for (auto iter = uriMap_.begin(); iter != uriMap_.end();) {
        auto& list = iter->second;
        bool findUriRecord = false;
        for (auto it = list.begin(); it != list.end();) {
            if (it->targetTokenId == tokenId) {
                TAG_LOGI(AAFwkTag::URIPERMMGR, "Erase an info form list");
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
    TAG_LOGD(AAFwkTag::URIPERMMGR, "end");
}

int UriPermissionManagerStubImpl::RevokeAllUriPermissions(uint32_t tokenId)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "RevokeAllUriPermissions, tokenId:%{public}u", tokenId);
    if (!UPMSUtils::IsFoundationCall()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "No permission to revoke all uri permission");
        return CHECK_PERMISSION_FAILED;
    }
    RevokeAllMapUriPermissions(tokenId);
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

int UriPermissionManagerStubImpl::RevokeUriPermissionManually(const Uri &uri, const std::string bundleName,
    int32_t appIndex)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "uri:%{private}s, bundleName:%{public}s, appIndex:%{public}d",
        uri.ToString().c_str(), bundleName.c_str(), appIndex);
    if (!UPMSUtils::IsSAOrSystemAppCall()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "not SA/SystemApp");
        return CHECK_PERMISSION_FAILED;
    }
    auto uriInner = uri;
    if (!UPMSUtils::CheckUriTypeIsValid(uriInner)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "CheckUriType failed, uri:%{private}s", uri.ToString().c_str());
        return ERR_CODE_INVALID_URI_TYPE;
    }
    uint32_t targetTokenId = 0;
    auto ret = UPMSUtils::GetTokenIdByBundleName(bundleName, appIndex, targetTokenId);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "get tokenId by bundleName fail");
        return ret;
    }
    return RevokeUriPermissionManuallyInner(uriInner, targetTokenId);
}

int32_t UriPermissionManagerStubImpl::RevokeUriPermissionManuallyInner(Uri &uri, uint32_t targetTokenId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto callerTokenId = IPCSkeleton::GetCallingTokenID();
    TAG_LOGI(AAFwkTag::URIPERMMGR, "callerTokenId: %{public}u, targetTokenId:%{public}u",
        callerTokenId, targetTokenId);
    
    if (uri.GetScheme() == "content" || UPMSUtils::IsDocsCloudUri(uri)) {
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
                TAG_LOGI(AAFwkTag::URIPERMMGR, "revoke uri permission record");
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
    std::string uriStr = uri.ToString();
    return MediaPermissionManager::GetInstance().RevokeUriPermission(callerTokenId, targetTokenId, uriStr);
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
        if (mgr == nullptr) {
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

int32_t UriPermissionManagerStubImpl::ClearPermissionTokenByMap(const uint32_t tokenId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    bool isCallingPermission =
        AAFwk::PermissionVerification::GetInstance()->CheckSpecificSystemAbilityAccessPermission(FOUNDATION_PROCESS);
    if (!isCallingPermission) {
        TAG_LOGE(AAFwkTag::APPMGR, "verification failed");
        return ERR_PERMISSION_DENIED;
    }
    std::lock_guard<std::mutex> lock(ptMapMutex_);
    if (permissionTokenMap_.find(tokenId) == permissionTokenMap_.end()) {
        TAG_LOGD(AAFwkTag::URIPERMMGR, "permissionTokenMap_ empty");
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
        return ret;
    }
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
    permissionTokenMap_.erase(tokenId);
    return ERR_OK;
}

#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
int32_t UriPermissionManagerStubImpl::Active(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    auto callingPid = IPCSkeleton::GetCallingPid();
    ConnectManager(appMgr_, APP_MGR_SERVICE_ID);
    if (appMgr_ == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "appMgr_ null");
        return INVALID_PARAMTER;
    }
    bool isTerminating = false;
    if (IN_PROCESS_CALL(appMgr_->IsTerminatingByPid(callingPid, isTerminating)) != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "IsTerminatingByPid failed");
        return INVALID_PARAMTER;
    }
    if (isTerminating) {
        TAG_LOGD(AAFwkTag::URIPERMMGR, "app is terminating");
        return INVALID_PARAMTER;
    }
    uint64_t timeNow = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count());
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    TAG_LOGD(AAFwkTag::URIPERMMGR, "active %{private}d permission", tokenId);
    auto ret = SandboxManagerKit::StartAccessingPolicy(policy, result, false, tokenId, timeNow);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "active permission end");
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "StartAccessingPolicy failed, ret is %{public}d", ret);
        return ret;
    }
    std::lock_guard<std::mutex> lock(ptMapMutex_);
    permissionTokenMap_.insert(tokenId);
    return ERR_OK;
}
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
}  // namespace AAFwk
}  // namespace OHOS
