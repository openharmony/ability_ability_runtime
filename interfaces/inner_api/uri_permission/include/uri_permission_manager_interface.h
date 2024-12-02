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

#ifndef OHOS_ABILITY_RUNTIME_URI_PERMISSION_MANAGER_INTERFACE_H
#define OHOS_ABILITY_RUNTIME_URI_PERMISSION_MANAGER_INTERFACE_H
#include <vector>
#include "access_token.h"
#include "iremote_broker.h"
#include "uri.h"
#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
#include "policy_info.h"
#else
#include "upms_policy_info.h"
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER

namespace OHOS {
namespace AAFwk {
#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
using namespace AccessControl::SandboxManager;
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
class IUriPermissionManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.ability.UriPermissionManager");

    /**
     * @brief Authorize the uri permission to targetBundleName.
     *
     * @param uri The file uri.
     * @param flag Want::FLAG_AUTH_READ_URI_PERMISSION or Want::FLAG_AUTH_WRITE_URI_PERMISSION.
     * @param targetBundleName The user of uri.
     * @return Returns true if the authorization is successful, otherwise returns false.
     */
    virtual int GrantUriPermission(const Uri &uri, unsigned int flag, const std::string targetBundleName,
        int32_t appIndex = 0, uint32_t initiatorTokenId = 0) = 0;

    /**
     * @brief Authorize the uri permission to targetBundleName.
     *
     * @param uriVec The file urilist.
     * @param flag Want::FLAG_AUTH_READ_URI_PERMISSION or Want::FLAG_AUTH_WRITE_URI_PERMISSION.
     * @param targetBundleName The user of uri.
     * @return Returns true if the authorization is successful, otherwise returns false.
     */
    virtual int GrantUriPermission(const std::vector<Uri> &uriVec, unsigned int flag,
        const std::string targetBundleName, int32_t appIndex = 0, uint32_t initiatorTokenId = 0) = 0;

    /**
     * @brief Authorize the uri permission to targetBundleName.
     *
     * @param uriVec The file urilist.
     * @param flag Want::FLAG_AUTH_READ_URI_PERMISSION or Want::FLAG_AUTH_WRITE_URI_PERMISSION.
     * @param targetBundleName The user of uri.
     * @param appIndex The index of application in sandbox.
     * @return Returns ERR_OK if the authorization is successful, otherwise returns error code.
     */
    virtual int32_t GrantUriPermissionPrivileged(const std::vector<Uri> &uriVec, uint32_t flag,
        const std::string &targetBundleName, int32_t appIndex, uint32_t initiatorTokenId,
        int32_t hideSensitiveType = 0) = 0;

    /**
     * @brief Clear user's all uri authorization record with autoremove flag.
     *
     * @param tokenId A tokenId of an application.
     * @return Returns true if the remove is successful, otherwise returns false.
     */
    virtual int RevokeAllUriPermissions(const uint32_t tokenId) = 0;

    /**
     * @brief Clear user's uri authorization record.
     *
     * @param uri The file uri.
     * @param bundleName bundleName of an application.
     * @param appIndex The index of application in sandbox.
     * @return Returns true if the remove is successful, otherwise returns false.
     */
    virtual int RevokeUriPermissionManually(const Uri &uri, const std::string bundleName,
        int32_t appIndex = 0) = 0;

    /**
     * @brief verify if tokenId have uri permission of flag.
     *
     * @param uri The file uri.
     * @param flag Want::FLAG_AUTH_READ_URI_PERMISSION or Want::FLAG_AUTH_WRITE_URI_PERMISSION.
     * @param tokenId A tokenId of an application.
     */
    virtual bool VerifyUriPermission(const Uri& uri, uint32_t flag, uint32_t tokenId) = 0;

    /**
     * @brief verify if tokenId have uri permission of flag.
     *
     * @param uri The file uri.
     * @param flag Want::FLAG_AUTH_READ_URI_PERMISSION or Want::FLAG_AUTH_WRITE_URI_PERMISSION.
     * @param tokenId A tokenId of an application.
     */
    virtual std::vector<bool> CheckUriAuthorization(const std::vector<std::string> &uriVec,
        uint32_t flag, uint32_t tokenId) = 0;

    virtual int32_t ClearPermissionTokenByMap(uint32_t tokenId) = 0;

#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
    virtual int32_t Active(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) = 0;
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER

    enum UriPermMgrCmd {
        // ipc id for GrantUriPermission
        ON_GRANT_URI_PERMISSION = 0,

        // ipc id for RevokeAllUriPermission
        ON_REVOKE_ALL_URI_PERMISSION,

        // ipc id for RevokeUriPermisionManually
        ON_REVOKE_URI_PERMISSION_MANUALLY,

        // ipc id for VerifyUriPermission
        ON_VERIFY_URI_PERMISSION,

        // ipc id for BatchGrantUriPermission
        ON_BATCH_GRANT_URI_PERMISSION,

        //ipc id for GrantUriPermissionPrivileged
        ON_GRANT_URI_PERMISSION_PRIVILEGED,

        //ipc id for CheckUriAuthorization
        ON_CHECK_URI_AUTHORIZATION,

        //ipc id for ClearPermissionTokenByMap
        ON_CLEAR_PERMISSION_TOKEN_BY_MAP,
#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
        //ipc id for Active
        ON_ACTIVE,
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
    };
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_URI_PERMISSION_MANAGER_INTERFACE_H
