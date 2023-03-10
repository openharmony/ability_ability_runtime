/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"
#include "hilog_wrapper.h"
#include "if_system_ability_manager.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "os_account_manager_wrapper.h"
#include "permission_constants.h"
#include "permission_verification.h"
#include "singleton.h"
#include "system_ability_definition.h"
#include "want.h"

namespace OHOS {
namespace AAFwk {
const int32_t DEFAULT_USER_ID = 0;
using TokenId = Security::AccessToken::AccessTokenID;

bool UriPermissionManagerStubImpl::GrantUriPermission(const Uri &uri, unsigned int flag,
    const std::string targetBundleName, int autoremove)
{
    if ((flag & (Want::FLAG_AUTH_READ_URI_PERMISSION | Want::FLAG_AUTH_WRITE_URI_PERMISSION)) == 0) {
        HILOG_WARN("UriPermissionManagerStubImpl::GrantUriPermission: The param flag is invalid.");
        return false;
    }
    auto bms = ConnectBundleManager();
    if (bms == nullptr) {
        HILOG_WARN("Failed to get bms.");
        return false;
    }
    auto callerTokenId = IPCSkeleton::GetCallingTokenID();
    HILOG_DEBUG("callerTokenId : %{public}u", callerTokenId);
    auto bundleFlag = AppExecFwk::BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO;
    AppExecFwk::BundleInfo uriBundleInfo;
    Uri uri_inner = uri;
    auto&& authority = uri_inner.GetAuthority();
    if (!IN_PROCESS_CALL(bms->GetBundleInfo(authority, bundleFlag, uriBundleInfo, GetCurrentAccountId()))) {
        HILOG_WARN("To fail to get bundle info according to uri.");
        return false;
    }
    Security::AccessToken::AccessTokenID fromTokenId = uriBundleInfo.applicationInfo.accessTokenId;
    if (!IN_PROCESS_CALL(bms->GetBundleInfo(targetBundleName, bundleFlag, uriBundleInfo, GetCurrentAccountId()))) {
        HILOG_WARN("To fail to get bundle info to targetBundleName.");
        return false;
    }
    Security::AccessToken::AccessTokenID targetTokenId = uriBundleInfo.applicationInfo.accessTokenId;
    // only uri with proxy authorization permission or from process itself can be granted
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(IPCSkeleton::GetCallingTokenID());
    auto permission = PermissionVerification::GetInstance()->VerifyCallingPermission(
        AAFwk::PermissionConstants::PERMISSION_PROXY_AUTHORIZATION_URI);
    if (tokenType != Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE &&
        !permission && (fromTokenId != callerTokenId)) {
        HILOG_WARN("UriPermissionManagerStubImpl::GrantUriPermission: No permission for proxy authorization uri.");
        return false;
    }
    unsigned int tmpFlag = 0;
    if (flag & Want::FLAG_AUTH_WRITE_URI_PERMISSION) {
        tmpFlag = Want::FLAG_AUTH_WRITE_URI_PERMISSION;
    } else {
        tmpFlag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    }
    auto&& scheme = uri_inner.GetScheme();
    if (scheme != "file" && scheme != "dataShare") {
        HILOG_WARN("only support file or dataShare uri.");
        return false;
    }
    return GrantUriPermissionImpl(uri, tmpFlag, fromTokenId, targetTokenId);
}

bool GrantUriPermissionImpl(const Uri &uri, unsigned int flag,
        Security::AccessToken::AccessTokenID fromTokenId,
        Security::AccessToken::AccessTokenID targetTokenId,
        int autoremove)
{
    auto storageMgrProxy = ConnectStorageManager();
    if (storageMgrProxy == nullptr) {
        HILOG_ERROR("ConnectStorageManager failed");
        return false;
    }
    auto uriStr = uri.ToString();
    auto ret = storageMgrProxy->CreateShareFile(uriStr, targetTokenId, flag);
    if (ret != 0 && ret != -EEXIST) {
        HILOG_ERROR("storageMgrProxy failed to CreateShareFile.");
        return false;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    auto search = uriMap_.find(uriStr);
    int autoremove_ = autoremove;
    // auto remove URI permission for clipboard
    Security::AccessToken::NativeTokenInfo nativeInfo;
    Security::AccessToken::AccessTokenKit::GetNativeTokenInfo(fromTokenId, nativeInfo);
    HILOG_DEBUG("callerprocessName : %{public}s", nativeInfo.processName.c_str());
    if (nativeInfo.processName == "pasteboard_serv") {
        autoremove_ = 1;
    }
    GrantInfo info = { tmpFlag, fromTokenId, targetTokenId, autoremove_ };
    if (search == uriMap_.end()) {
        std::list<GrantInfo> infoList = { info };
        uriMap_.emplace(uriStr, infoList);
        return true;
    }
    auto& infoList = search->second;
    for (auto& item : infoList) {
        if (item.fromTokenId == fromTokenId && item.targetTokenId == targetTokenId) {
            if ((tmpFlag & item.flag) == 0) {
                HILOG_INFO("Update uri r/w permission.");
                item.flag = tmpFlag;
            }
            HILOG_INFO("uri permission has granted, not to grant again.");
            return true;
        }
    }
    infoList.emplace_back(info);
    return true;
}

bool UriPermissionManagerStubImpl::VerifyUriPermission(const Uri &uri, unsigned int flag,
    const Security::AccessToken::AccessTokenID tokenId)
{
    if ((flag & (Want::FLAG_AUTH_READ_URI_PERMISSION | Want::FLAG_AUTH_WRITE_URI_PERMISSION)) == 0) {
        HILOG_WARN("UriPermissionManagerStubImpl:::VerifyUriPermission: The param flag is invalid.");
        return false;
    }

    auto bms = ConnectBundleManager();
    auto uriStr = uri.ToString();
    if (bms) {
        AppExecFwk::ExtensionAbilityInfo info;
        if (!IN_PROCESS_CALL(bms->QueryExtensionAbilityInfoByUri(uriStr, GetCurrentAccountId(), info))) {
            HILOG_DEBUG("%{public}s, Fail to get extension info from bundle manager.", __func__);
            return false;
        }
        if (info.type != AppExecFwk::ExtensionAbilityType::FILESHARE) {
            HILOG_DEBUG("%{public}s, The upms only open to FILESHARE. The type is %{public}u.", __func__, info.type);
            return false;
        }

        if (tokenId == info.applicationInfo.accessTokenId) {
            HILOG_DEBUG("The uri belongs to this application.");
            return true;
        }
    }

    std::lock_guard<std::mutex> guard(mutex_);
    auto search = uriMap_.find(uriStr);
    if (search == uriMap_.end()) {
        HILOG_DEBUG("This tokenID does not have permission for this uri.");
        return false;
    }

    unsigned int tmpFlag = 0;
    if (flag & Want::FLAG_AUTH_WRITE_URI_PERMISSION) {
        tmpFlag = Want::FLAG_AUTH_WRITE_URI_PERMISSION;
    } else {
        tmpFlag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    }

    for (const auto& item : search->second) {
        if (item.targetTokenId == tokenId &&
            (item.flag == Want::FLAG_AUTH_WRITE_URI_PERMISSION || item.flag == tmpFlag)) {
            HILOG_DEBUG("This tokenID have permission for this uri.");
            return true;
        }
    }

    HILOG_DEBUG("The application does not have permission for this URI.");
    return false;
}

void UriPermissionManagerStubImpl::RevokeUriPermission(const TokenId tokenId)
{
    HILOG_DEBUG("Start to remove uri permission.");
    std::vector<std::string> uriList;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        for (auto iter = uriMap_.begin(); iter != uriMap_.end();) {
            auto& list = iter->second;
            for (auto it = list.begin(); it != list.end(); it++) {
                if (it->targetTokenId == tokenId && it->autoremove) {
                    HILOG_INFO("Erase an info form list.");
                    list.erase(it);
                    uriList.emplace_back(iter->first);
                    break;
                }
            }
            if (list.size() == 0) {
                uriMap_.erase(iter++);
            } else {
                iter++;
            }
        }
    }

    auto storageMgrProxy = ConnectStorageManager();
    if (storageMgrProxy == nullptr) {
        HILOG_ERROR("ConnectStorageManager failed");
        return;
    }

    if (!uriList.empty()) {
        storageMgrProxy->DeleteShareFile(tokenId, uriList);
    }
    return;
}

bool UriPermissionManagerStubImpl::RevokeUriPermissionManually(const Uri &uri, const std::string bundleName)
{
    HILOG_DEBUG("Start to remove uri permission manually.");
    auto bms = ConnectBundleManager();
    if (bms == nullptr) {
        HILOG_WARN("Failed to get bms.");
        return false;
    }
    AppExecFwk::BundleInfo uriBundleInfo;
    auto bundleFlag = AppExecFwk::BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO;
    if (!IN_PROCESS_CALL(bms->GetBundleInfo(bundleName, bundleFlag, uriBundleInfo, GetCurrentAccountId()))) {
        HILOG_WARN("To fail to get bundle info to bundleName.");
        return false;
    }
    Security::AccessToken::AccessTokenID tokenId = uriBundleInfo.applicationInfo.accessTokenId;
    std::vector<std::string> uriList;
    {
        std::lock_guard<std::mutex> guard(mutex_);

        auto uriStr = uri.ToString();
        auto search = uriMap_.find(uriStr);
        if (search == uriMap_.end()) {
            HILOG_ERROR("URI does not exist on uri map.");
            return false;
        }
        auto& list = search->second;
        for (auto it = list.begin(); it != list.end(); it++) {
            if (it->targetTokenId == tokenId) {
                HILOG_INFO("Erase an info form list.");
                list.erase(it);
                uriList.emplace_back(search->first);
                break;
            }
        }
    }

    auto storageMgrProxy = ConnectStorageManager();
    if (storageMgrProxy == nullptr) {
        HILOG_ERROR("ConnectStorageManager failed");
        return false;
    }

    if (!uriList.empty()) {
        storageMgrProxy->DeleteShareFile(tokenId, uriList);
    }
    return true;
}

sptr<AppExecFwk::IBundleMgr> UriPermissionManagerStubImpl::ConnectBundleManager()
{
    HILOG_DEBUG("%{public}s is called.", __func__);
    std::lock_guard<std::mutex> lock(bmsMutex_);
    if (bundleManager_ == nullptr) {
        auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (!systemAbilityMgr) {
            HILOG_ERROR("Failed to get SystemAbilityManager.");
            return nullptr;
        }

        auto remoteObj = systemAbilityMgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        if (!remoteObj || (bundleManager_ = iface_cast<AppExecFwk::IBundleMgr>(remoteObj)) == nullptr) {
            HILOG_ERROR("Failed to get bms.");
            return nullptr;
        }
        auto self = weak_from_this();
        const auto& onClearProxyCallback = [self](const wptr<IRemoteObject>& remote) {
            auto impl = self.lock();
            if (impl && impl->bundleManager_ == remote) {
                impl->ClearBMSProxy();
            }
        };
        sptr<BMSOrSMDeathRecipient> recipient(new BMSOrSMDeathRecipient(onClearProxyCallback));
        bundleManager_->AsObject()->AddDeathRecipient(recipient);
    }
    HILOG_DEBUG("%{public}s end.", __func__);
    return bundleManager_;
}

sptr<StorageManager::IStorageManager> UriPermissionManagerStubImpl::ConnectStorageManager()
{
    std::lock_guard<std::mutex> lock(storageMutex_);
    if (storageManager_ == nullptr) {
        auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (!systemAbilityMgr) {
            HILOG_ERROR("Failed to get SystemAbilityManager.");
            return nullptr;
        }

        auto remoteObj = systemAbilityMgr->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
        if (!remoteObj || (storageManager_ = iface_cast<StorageManager::IStorageManager>(remoteObj)) == nullptr) {
            HILOG_ERROR("Failed to get storage manager.");
            return nullptr;
        }
        auto self = weak_from_this();
        const auto& onClearProxyCallback = [self](const wptr<IRemoteObject>& remote) {
            auto impl = self.lock();
            if (impl && impl->storageManager_ == remote) {
                impl->ClearSMProxy();
            }
        };
        sptr<BMSOrSMDeathRecipient> recipient(new BMSOrSMDeathRecipient(onClearProxyCallback));
        storageManager_->AsObject()->AddDeathRecipient(recipient);
    }
    HILOG_DEBUG("%{public}s end.", __func__);
    return storageManager_;
}

void UriPermissionManagerStubImpl::ClearBMSProxy()
{
    HILOG_DEBUG("%{public}s is called.", __func__);
    std::lock_guard<std::mutex> lock(bmsMutex_);
    bundleManager_ = nullptr;
}

void UriPermissionManagerStubImpl::ClearSMProxy()
{
    HILOG_DEBUG("%{public}s is called.", __func__);
    std::lock_guard<std::mutex> lock(bmsMutex_);
    storageManager_ = nullptr;
}

void UriPermissionManagerStubImpl::BMSOrSMDeathRecipient::OnRemoteDied(
    [[maybe_unused]] const wptr<IRemoteObject>& remote)
{
    if (proxy_) {
        HILOG_DEBUG("%{public}s, bms stub died.", __func__);
        proxy_(remote);
    }
}

int UriPermissionManagerStubImpl::GetCurrentAccountId()
{
    std::vector<int32_t> osActiveAccountIds;
    ErrCode ret = DelayedSingleton<AppExecFwk::OsAccountManagerWrapper>::GetInstance()->
        QueryActiveOsAccountIds(osActiveAccountIds);
    if (ret != ERR_OK) {
        HILOG_ERROR("QueryActiveOsAccountIds failed.");
        return DEFAULT_USER_ID;
    }
    if (osActiveAccountIds.empty()) {
        HILOG_ERROR("%{public}s, QueryActiveOsAccountIds is empty, no accounts.", __func__);
        return DEFAULT_USER_ID;
    }

    return osActiveAccountIds.front();
}
}  // namespace AAFwk
}  // namespace OHOS