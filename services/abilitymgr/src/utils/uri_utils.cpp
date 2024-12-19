/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "uri_utils.h"

#include "ability_util.h"
#include "ability_config.h"
#include "ability_record.h"
#include "ability_manager_errors.h"
#include "accesstoken_kit.h"
#include "app_utils.h"
#include "common_event_manager.h"
#include "extension_ability_info.h"
#include "element_name.h"
#include "global_constant.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "ui_extension_utils.h"
#ifdef SUPPORT_UPMS
#include "uri_permission_manager_client.h"
#endif // SUPPORT_UPMS

namespace OHOS {
namespace AAFwk {
namespace {
const std::string PARAMS_URI = "ability.verify.uri";
const std::string DISTRIBUTED_FILES_PATH = "/data/storage/el2/distributedfiles/";
const std::string HIDE_SENSITIVE_TYPE = "ohos.media.params.hideSensitiveType";
const std::string DMS_PROCESS_NAME = "distributedsched";
const int32_t MAX_URI_COUNT = 500;
constexpr int32_t API14 = 14;
constexpr int32_t API_VERSION_MOD = 100;
constexpr uint32_t TOKEN_ID_BIT_SIZE = 32;
}

UriUtils::UriUtils() {}

UriUtils::~UriUtils() {}

UriUtils &UriUtils::GetInstance()
{
    static UriUtils utils;
    return utils;
}

std::vector<Uri> UriUtils::GetUriListFromWantDms(Want &want)
{
    std::vector<std::string> uriStrVec = want.GetStringArrayParam(PARAMS_URI);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "uriVec size: %{public}zu", uriStrVec.size());
    if (uriStrVec.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "uri list size is more than %{public}u", MAX_URI_COUNT);
        uriStrVec.resize(MAX_URI_COUNT);
    }
    std::vector<Uri> validUriVec;
    for (auto &&str : uriStrVec) {
        Uri uri(str);
        auto &&scheme = uri.GetScheme();
        TAG_LOGI(AAFwkTag::ABILITYMGR, "uri scheme: %{public}s", scheme.c_str());
        // only support file scheme
        if (scheme != "file") {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "only support file uri");
            continue;
        }
        std::string srcPath = uri.GetPath();
        if (std::filesystem::exists(srcPath) && std::filesystem::is_symlink(srcPath)) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "soft links not allowed");
            continue;
        }
        std::string absolutePath;
        if (uri.IsRelative()) {
            char path[PATH_MAX] = {0};
            if (realpath(srcPath.c_str(), path) == nullptr) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "fail, errno :%{public}d", errno);
                continue;
            }
            absolutePath = path;
        } else {
            absolutePath = srcPath;
        }
        if (absolutePath.compare(0, DISTRIBUTED_FILES_PATH.size(), DISTRIBUTED_FILES_PATH) != 0) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "uri not distributed path");
            continue;
        }
        validUriVec.emplace_back(uri);
    }
    uriStrVec.clear();
    want.SetParam(PARAMS_URI, uriStrVec);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "size of vaid uri is %{public}zu", validUriVec.size());
    return validUriVec;
}

int32_t UriUtils::CheckNonImplicitShareFileUri(const Want &want, int32_t userId, uint32_t specifyTokenId)
{
    auto element = want.GetElement();
    TAG_LOGD(AAFwkTag::ABILITYMGR, "CheckNonImplicitShareFileUri, %{public}s-%{public}s",
        element.GetBundleName().c_str(), element.GetAbilityName().c_str());
    if (element.GetBundleName().empty() || element.GetAbilityName().empty()) {
        return ERR_OK;
    }
#ifdef SUPPORT_UPMS
    if (!IsGrantUriPermissionFlag(want)) {
        return ERR_OK;
    }
#endif // SUPPORT_UPMS
    bool isFileUri = (!want.GetUriString().empty() && want.GetUri().GetScheme() == "file");
    if (!isFileUri && want.GetStringArrayParam(AbilityConfig::PARAMS_STREAM).empty()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "not file uri");
        return ERR_OK;
    }
    // SA and system app support
    auto callerTokenId = specifyTokenId > 0 ? specifyTokenId : IPCSkeleton::GetCallingTokenID();
    if (CheckNonImplicitShareFileUriInner(callerTokenId, element.GetBundleName(), userId) != ERR_OK) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "share file uri non-implicitly will not support");
    }
    return ERR_OK;
}

int32_t UriUtils::CheckNonImplicitShareFileUriInner(uint32_t callerTokenId, const std::string &targetBundleName,
    int32_t userId)
{
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerTokenId);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "SA call");
        return ERR_OK;
    }
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        Security::AccessToken::HapTokenInfo hapInfo;
        auto ret = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(callerTokenId, hapInfo);
        if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "GetHapTokenInfo failed, ret:%{public}d", ret);
            return INNER_ERR;
        }
        // check api version
        TAG_LOGD(AAFwkTag::ABILITYMGR, "CallerBundleName:%{public}s, API:%{public}d",
            hapInfo.bundleName.c_str(), hapInfo.apiVersion);
        if ((hapInfo.apiVersion % API_VERSION_MOD) <= API14) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "api version lower than 14");
            return ERR_OK;
        }
        // check system app
        uint64_t fullCallerTokenId = (static_cast<uint64_t>(hapInfo.tokenAttr) << TOKEN_ID_BIT_SIZE) + callerTokenId;
        if (Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullCallerTokenId)) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "system app call");
            return ERR_OK;
        }
    }
    // target is system app
    if (IsSystemApplication(targetBundleName, userId)) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "target is system app");
        return ERR_OK;
    }
    return CHECK_PERMISSION_FAILED;
}

bool UriUtils::IsSystemApplication(const std::string &bundleName, int32_t userId)
{
    auto bundleMgrHelper = AbilityUtil::GetBundleManagerHelper();
    if (!bundleMgrHelper) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "GetBundleManagerHelper failed");
        return false;
    }
    AppExecFwk::ApplicationInfo appInfo;
    if (!IN_PROCESS_CALL(bundleMgrHelper->GetApplicationInfo(bundleName,
        AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, userId, appInfo))) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "GetApplicationInfo failed");
        return false;
    }
    return appInfo.isSystemApp;
}

std::vector<Uri> UriUtils::GetPermissionedUriList(const std::vector<std::string> &uriVec,
    const std::vector<bool> &checkResults, Want &want)
{
    std::vector<Uri> permissionedUris;
    if (uriVec.size() != checkResults.size()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Invalid param: %{public}zu : %{public}zu",
            uriVec.size(), checkResults.size());
        return permissionedUris;
    }
    // process uri
    size_t startIndex = 0;
    if (!want.GetUriString().empty()) {
        if (checkResults[startIndex]) {
            permissionedUris.emplace_back(want.GetUri());
        } else if (want.GetUri().GetScheme() == "file") {
            // erase uri param
            want.SetUri("");
            TAG_LOGI(AAFwkTag::ABILITYMGR, "erase uri param.");
        }
        startIndex = 1;
    }
    // process param stream
    std::vector<std::string> paramStreamUris;
    for (size_t index = startIndex; index < checkResults.size(); index++) {
        auto uri = Uri(uriVec[index]);
        if (checkResults[index]) {
            permissionedUris.emplace_back(uri);
            paramStreamUris.emplace_back(uriVec[index]);
        } else if (uri.GetScheme() != "file") {
            paramStreamUris.emplace_back(uriVec[index]);
        }
    }
    if (paramStreamUris.size() != (checkResults.size() - startIndex)) {
        // erase old param stream and set new param stream
        want.RemoveParam(AbilityConfig::PARAMS_STREAM);
        want.SetParam(AbilityConfig::PARAMS_STREAM, paramStreamUris);
        TAG_LOGI(AAFwkTag::ABILITYMGR, "startIndex: %{public}zu, uriVec: %{public}zu, paramStreamUris: %{public}zu",
            startIndex, uriVec.size(), paramStreamUris.size());
    }
    return permissionedUris;
}

bool UriUtils::GetUriListFromWant(Want &want, std::vector<std::string> &uriVec)
{
    // remove uris out of 500
    auto uriStr = want.GetUri().ToString();
    uriVec = want.GetStringArrayParam(AbilityConfig::PARAMS_STREAM);
    if (uriVec.empty() && uriStr.empty()) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "uriVec empty.");
        return false;
    }
    // process param stream
    auto paramStreamUriCount = uriVec.size();
    if (uriStr.empty() && paramStreamUriCount > MAX_URI_COUNT) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "uri empty, paream stream counts: %{public}zu", paramStreamUriCount);
        uriVec.resize(MAX_URI_COUNT);
        want.RemoveParam(AbilityConfig::PARAMS_STREAM);
        want.SetParam(AbilityConfig::PARAMS_STREAM, uriVec);
    }
    if (!uriStr.empty() && paramStreamUriCount > MAX_URI_COUNT - 1) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "paream stream counts: %{public}zu", paramStreamUriCount);
        uriVec.resize(MAX_URI_COUNT - 1);
        want.RemoveParam(AbilityConfig::PARAMS_STREAM);
        want.SetParam(AbilityConfig::PARAMS_STREAM, uriVec);
    }
    // process uri
    if (!uriStr.empty()) {
        uriVec.insert(uriVec.begin(), uriStr);
    }
    return true;
}

#ifdef SUPPORT_UPMS
bool UriUtils::IsGrantUriPermissionFlag(const Want &want)
{
    return ((want.GetFlags() & (Want::FLAG_AUTH_READ_URI_PERMISSION | Want::FLAG_AUTH_WRITE_URI_PERMISSION)) != 0);
}
#endif // SUPPORT_UPMS

bool UriUtils::IsServiceExtensionType(AppExecFwk::ExtensionAbilityType extensionAbilityType)
{
    return extensionAbilityType == AppExecFwk::ExtensionAbilityType::SERVICE ||
        extensionAbilityType == AppExecFwk::ExtensionAbilityType::UI_SERVICE;
}

bool UriUtils::IsDmsCall(uint32_t fromTokenId)
{
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(fromTokenId);
    bool isNativeCall = tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE;
    if (!isNativeCall) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "not native call");
        return false;
    }
    Security::AccessToken::NativeTokenInfo nativeTokenInfo;
    int32_t result = Security::AccessToken::AccessTokenKit::GetNativeTokenInfo(fromTokenId, nativeTokenInfo);
    if (result == ERR_OK && nativeTokenInfo.processName == DMS_PROCESS_NAME) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "dms ability call");
        return true;
    }
    return false;
}

#ifdef SUPPORT_UPMS
void UriUtils::GrantDmsUriPermission(Want &want, uint32_t callerTokenId, std::string targetBundleName, int32_t appIndex)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto validUriVec = GetUriListFromWantDms(want);
    auto hideSensitiveType = want.GetIntParam(HIDE_SENSITIVE_TYPE, 0);
    auto ret = IN_PROCESS_CALL(UriPermissionManagerClient::GetInstance().GrantUriPermissionPrivileged(validUriVec,
        want.GetFlags(), targetBundleName, appIndex, callerTokenId, hideSensitiveType));
    if (ret != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "ret is %{public}d.", ret);
        return;
    }
}

bool UriUtils::GrantShellUriPermission(const std::vector<std::string> &strUriVec, uint32_t flag,
    const std::string &targetPkg, int32_t appIndex)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Grant uri permission to shell.");
    std::vector<Uri> uriVec;
    for (auto&& str : strUriVec) {
        Uri uri(str);
        auto&& scheme = uri.GetScheme();
        if (scheme != "content") {
            return false;
        }
        uriVec.emplace_back(uri);
    }
    uint32_t callerTokendId = IPCSkeleton::GetCallingTokenID();
    auto ret = IN_PROCESS_CALL(UriPermissionManagerClient::GetInstance().GrantUriPermissionPrivileged(
        uriVec, flag, targetPkg, appIndex, callerTokendId));
    if (ret != ERR_OK) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "grant uri to shell failed: %{public}d", ret);
    }
    return true;
}

void UriUtils::CheckUriPermission(uint32_t callerTokenId, Want &want)
{
    // Check and clear no-permission uris in want, not support content uri
    uint32_t flag = want.GetFlags();
    if (!IsGrantUriPermissionFlag(want)) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "No grant uri flag: %{public}u.", flag);
        return;
    }
    std::vector<std::string> uriVec;
    if (!UriUtils::GetUriListFromWant(want, uriVec)) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "No file uri neet grant.");
        return;
    }
    auto checkResults = IN_PROCESS_CALL(UriPermissionManagerClient::GetInstance().CheckUriAuthorization(
        uriVec, flag, callerTokenId));
    auto permissionUris = GetPermissionedUriList(uriVec, checkResults, want);
    if (permissionUris.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "all uris not permissioned.");
        return;
    }
}
#endif // SUPPORT_UPMS

bool UriUtils::IsSandboxApp(uint32_t tokenId)
{
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        Security::AccessToken::HapTokenInfo hapInfo;
        auto ret = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapInfo);
        if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "GetHapTokenInfo failed, ret:%{public}d", ret);
            return false;
        }
        return hapInfo.instIndex > AbilityRuntime::GlobalConstant::MAX_APP_CLONE_INDEX;
    }
    return false;
}

#ifdef SUPPORT_UPMS
void UriUtils::GrantUriPermission(Want &want, std::string targetBundleName, int32_t appIndex,
    bool isSandboxApp, uint32_t callerTokenId, int32_t collaboratorType)
{
    uint32_t flag = want.GetFlags();
    if (!IsGrantUriPermissionFlag(want)) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "No grant uri flag: %{public}u.", flag);
        return;
    }

    if (targetBundleName == AppUtils::GetInstance().GetBrokerDelegateBundleName() &&
        collaboratorType == CollaboratorType::OTHERS_TYPE) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "reject shell application to grant uri permission");
        return;
    }
    if (callerTokenId == 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "callerTokenId is invalid.");
        return;
    }
    if (isSandboxApp || IsSandboxApp(callerTokenId)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "sandbox can not grant UriPermission");
        return;
    }

    if (IsDmsCall(callerTokenId)) {
        GrantDmsUriPermission(want, callerTokenId, targetBundleName, appIndex);
        return;
    }

    std::vector<std::string> uriVec;
    if (!UriUtils::GetUriListFromWant(want, uriVec)) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "No file uri neet grant.");
        return;
    }

    auto callerPkg = want.GetStringParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME);
    if (callerPkg == AppUtils::GetInstance().GetBrokerDelegateBundleName() &&
        GrantShellUriPermission(uriVec, flag, targetBundleName, appIndex)) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "permission to shell");
        return;
    }
    if (!GrantUriPermissionInner(uriVec, callerTokenId, targetBundleName, appIndex, want)) {
        return;
    }
    // report open file event
    PublishFileOpenEvent(want);
}

bool UriUtils::GrantUriPermissionInner(std::vector<std::string> uriVec, uint32_t callerTokenId,
    const std::string &targetBundleName, int32_t appIndex, Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    uint32_t flag = want.GetFlags();
    auto checkResults = IN_PROCESS_CALL(UriPermissionManagerClient::GetInstance().CheckUriAuthorization(
        uriVec, flag, callerTokenId));
    auto permissionUris = GetPermissionedUriList(uriVec, checkResults, want);
    if (permissionUris.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "uris not permissioned.");
        return false;
    }

    auto hideSensitiveType = want.GetIntParam(HIDE_SENSITIVE_TYPE, 0);
    auto ret = IN_PROCESS_CALL(UriPermissionManagerClient::GetInstance().GrantUriPermissionPrivileged(permissionUris,
        flag, targetBundleName, appIndex, callerTokenId, hideSensitiveType));
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed, err:%{public}d", ret);
        return false;
    }
    return true;
}
#endif // SUPPORT_UPMS

void UriUtils::PublishFileOpenEvent(const Want &want)
{
    auto wangUri = want.GetUri();
    std::string uriStr = wangUri.ToString();
    if (!uriStr.empty() && wangUri.GetScheme() == "file") {
        OHOS::AppExecFwk::ElementName element = want.GetElement();
        TAG_LOGI(AAFwkTag::ABILITYMGR, "ability record, file uri:%{private}s, bundle:%{public}s, ability:%{public}s",
            uriStr.c_str(), element.GetBundleName().c_str(), element.GetAbilityName().c_str());
        Want msgWant;
        msgWant.SetAction("file.event.OPEN_TIME");
        msgWant.SetParam("uri", uriStr);
        msgWant.SetParam("bundleName", element.GetBundleName());
        msgWant.SetParam("abilityName", element.GetAbilityName());
        auto timeNow = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::string currentTime = std::to_string(timeNow);
        msgWant.SetParam("viewTime", currentTime);
        EventFwk::CommonEventData commonData{msgWant};
        EventFwk::CommonEventPublishInfo commonEventPublishInfo;
        std::vector<std::string> subscriberPermissions = {"ohos.permission.MANAGE_LOCAL_ACCOUNTS"};
        commonEventPublishInfo.SetSubscriberPermissions(subscriberPermissions);
        IN_PROCESS_CALL(EventFwk::CommonEventManager::PublishCommonEvent(commonData, commonEventPublishInfo));
    }
}

#ifdef SUPPORT_UPMS
void UriUtils::GrantUriPermissionForServiceExtension(const AbilityRequest &abilityRequest)
{
    if (IsServiceExtensionType(abilityRequest.abilityInfo.extensionAbilityType)) {
        auto &abilityInfo = abilityRequest.abilityInfo;
        auto &want = const_cast<Want &>(abilityRequest.want);
        auto callerTokenId = abilityRequest.specifyTokenId > 0 ? abilityRequest.specifyTokenId :
            static_cast<uint32_t>(want.GetIntParam(Want::PARAM_RESV_CALLER_TOKEN, 0));
        GrantUriPermission(want, abilityInfo.bundleName, abilityInfo.appIndex, false, callerTokenId,
            abilityRequest.collaboratorType);
    }
}

void UriUtils::GrantUriPermissionForUIOrServiceExtension(const AbilityRequest &abilityRequest)
{
    auto extensionType = abilityRequest.abilityInfo.extensionAbilityType;
    if (UIExtensionUtils::IsUIExtension(extensionType) || IsServiceExtensionType(extensionType)) {
        auto &abilityInfo = abilityRequest.abilityInfo;
        auto &want = const_cast<Want &>(abilityRequest.want);
        auto callerTokenId = abilityRequest.specifyTokenId > 0 ? abilityRequest.specifyTokenId :
            static_cast<uint32_t>(want.GetIntParam(Want::PARAM_RESV_CALLER_TOKEN, 0));
        GrantUriPermission(want, abilityInfo.bundleName, abilityInfo.appIndex, false, callerTokenId,
            abilityRequest.collaboratorType);
    }
}
#endif // SUPPORT_UPMS
} // AAFwk
} // OHOS
