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

#ifndef OHOS_ABILITY_RUNTIME_URI_PERMISSION_MANAGER_STUB_IMPL_H
#define OHOS_ABILITY_RUNTIME_URI_PERMISSION_MANAGER_STUB_IMPL_H

#include <functional>
#include <map>
#include <vector>
#include <unordered_set>
#include "app_mgr_interface.h"
#include "batch_uri.h"
#include "istorage_manager.h"
#include "tokenid_permission.h"
#include "uri.h"
#include "uri_permission_manager_stub.h"

#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
#include "policy_info.h"
#else
#include "upms_policy_info.h"
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER

namespace OHOS::AAFwk {
namespace {
using ClearProxyCallback = std::function<void(const wptr<IRemoteObject>&)>;
using TokenId = Security::AccessToken::AccessTokenID;
#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
using namespace AccessControl::SandboxManager;
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
}

struct GrantInfo {
    unsigned int flag;
    const uint32_t fromTokenId;
    const uint32_t targetTokenId;
};

struct GrantPolicyInfo {
    const uint32_t callerTokenId;
    const uint32_t targetTokenId;
    bool Equal(uint32_t cTokenId, uint32_t tTokenId)
    {
        return callerTokenId == cTokenId && targetTokenId == tTokenId;
    }
};

class UriPermissionManagerStubImpl : public UriPermissionManagerStub,
                                     public std::enable_shared_from_this<UriPermissionManagerStubImpl> {
public:
    UriPermissionManagerStubImpl() = default;
    virtual ~UriPermissionManagerStubImpl() = default;

    /*
    * not support local media file uri.
    */
    bool VerifyUriPermission(const Uri &uri, uint32_t flag, uint32_t tokenId) override;

    /*
    * only support local file uri, not support distribute docs and content uri.
    */
    int GrantUriPermission(const Uri &uri, unsigned int flag, const std::string targetBundleName,
        int32_t appIndex = 0, uint32_t initiatorTokenId = 0) override;

    /*
    * only support local file uri, not support distribute docs and content uri.
    */
    int GrantUriPermission(const std::vector<Uri> &uriVec, unsigned int flag,
        const std::string targetBundleName, int32_t appIndex = 0, uint32_t initiatorTokenId = 0) override;

    /*
    * only support local file uri, not support distribute docs and content uri.
    */
    int32_t GrantUriPermissionPrivileged(const std::vector<Uri> &uriVec, uint32_t flag,
        const std::string &targetBundleName, int32_t appIndex, uint32_t initiatorTokenId,
        int32_t hideSensitiveType) override;

    /*
    * only support local file uri, not support distribute docs and content uri.
    */
    std::vector<bool> CheckUriAuthorization(const std::vector<std::string> &uriVec, uint32_t flag,
        uint32_t tokenId) override;

    int RevokeAllUriPermissions(uint32_t tokenId) override;

    int RevokeUriPermissionManually(const Uri &uri, const std::string bundleName,
        int32_t appIndex = 0) override;

private:
    template<typename T>
    void ConnectManager(sptr<T> &mgr, int32_t serviceId);

    std::vector<bool> VerifyUriPermissionByMap(std::vector<Uri> &uriVec, uint32_t flag, uint32_t tokenId);

    bool VerifySingleUriPermissionByMap(const std::string &uri, uint32_t flag, uint32_t tokenId);

    int32_t AddTempUriPermission(const std::string &uri, uint32_t flag, TokenId fromTokenId, TokenId targetTokenId);

    int32_t GrantUriPermissionInner(const std::vector<Uri> &uriVec, uint32_t flag,
        uint32_t callerTokenId, uint32_t targetTokenId, const std::string &targetBundleName);

    int32_t GrantUriPermissionPrivilegedInner(const std::vector<Uri> &uriVec, uint32_t flag, uint32_t callerTokenId,
        uint32_t targetTokenId, const std::string &targetAlterBundleName, int32_t hideSensitiveType);
    
    int32_t GrantBatchMediaUriPermissionImpl(const std::vector<std::string> &mediaUris, uint32_t flag,
        uint32_t callerTokenId, uint32_t targetTokenId, int32_t hideSensitiveType);

    int32_t GrantBatchUriPermissionImpl(const std::vector<std::string> &uriVec,
        uint32_t flag, TokenId callerTokenId, TokenId targetTokenId);

    std::vector<bool> CheckUriPermission(TokenIdPermission &tokenIdPermission, const std::vector<Uri> &uriVec,
        uint32_t flag);

    void CheckProxyUriPermission(TokenIdPermission &tokenIdPermission, const std::vector<Uri> &uriVec, uint32_t flag,
        std::vector<bool> &result);

    void RevokeMapUriPermission(uint32_t tokenId);

    int32_t RevokeAllMapUriPermissions(uint32_t tokenId);

    int32_t RevokeUriPermissionManuallyInner(Uri &uri, uint32_t targetTokenId);

    int32_t RevokeMapUriPermissionManually(uint32_t callerTokenId, uint32_t targetTokenId, Uri &uri);

    int32_t DeleteShareFile(uint32_t targetTokenId, const std::vector<std::string> &uriVec);

    int32_t RevokeMediaUriPermissionManually(uint32_t callerTokenId, uint32_t targetTokenId, Uri &uri);

    int32_t CheckCalledBySandBox();

    bool VerifySubDirUriPermission(const std::string &uriStr, uint32_t newFlag, uint32_t tokenId);

    bool IsDistributedSubDirUri(const std::string &inputUri, const std::string &cachedUri);

    int32_t ClearPermissionTokenByMap(const uint32_t tokenId) override;

#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
    int32_t Active(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) override;
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER

    class ProxyDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit ProxyDeathRecipient(ClearProxyCallback&& proxy) : proxy_(proxy) {}
        ~ProxyDeathRecipient() = default;
        virtual void OnRemoteDied([[maybe_unused]] const wptr<IRemoteObject>& remote) override;

    private:
        ClearProxyCallback proxy_;
    };

private:
    std::map<std::string, std::list<GrantInfo>> uriMap_;
    std::mutex mutex_;
    std::mutex mgrMutex_;
    sptr<AppExecFwk::IAppMgr> appMgr_ = nullptr;
    sptr<StorageManager::IStorageManager> storageManager_ = nullptr;
    std::set<uint32_t> permissionTokenMap_;
    std::mutex ptMapMutex_;
};
}  // namespace OHOS::AAFwk
#endif  // OHOS_ABILITY_RUNTIME_URI_PERMISSION_MANAGER_STUB_IMPL_H
