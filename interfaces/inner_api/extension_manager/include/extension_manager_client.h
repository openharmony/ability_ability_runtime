/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_EXTENSION_MANAGER_CLIENT_H
#define OHOS_ABILITY_RUNTIME_EXTENSION_MANAGER_CLIENT_H

#include <mutex>

#include "extension_manager_interface.h"
#include "iremote_object.h"

namespace OHOS {
namespace AAFwk {
/**
 * @class ExtensionManagerClient
 * ExtensionManagerClient is used to access ability manager services.
 */
class ExtensionManagerClient {
public:
    ExtensionManagerClient() = default;
    virtual ~ExtensionManagerClient() = default;
    static ExtensionManagerClient& GetInstance();

    ErrCode ConnectServiceExtensionAbility(const Want &want, const sptr<IRemoteObject> &connect, int32_t userId);

    ErrCode ConnectServiceExtensionAbility(const Want &want, const sptr<IRemoteObject> &connect,
        const sptr<IRemoteObject> &callerToken, int32_t userId);

    ErrCode ConnectEnterpriseAdminExtensionAbility(const Want &want,
        const sptr<IRemoteObject> &connect, const sptr<IRemoteObject> &callerToken, int32_t userId);

    /**
     * Connect extension ability.
     *
     * @param want special want for the extension ability.
     * @param connect callback used to notify caller the result of connecting.
     * @param userId the extension runs in.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ConnectExtensionAbility(const Want &want, const sptr<IRemoteObject> &connect,
        int32_t userId = DEFAULT_INVALID_USER_ID);

    /**
     * Disconnect session with extension ability.
     *
     * @param connect Callback used to notify caller the result of disconnecting.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DisconnectAbility(const sptr<IRemoteObject> &connect);

    ErrCode Release();

    /**
     * Start extension ability with want, send want to ability manager service.
     *
     * @param want, the want of the ability to start.
     * @param callerToken, caller ability token.
     * @param userId, Designation User ID.
     * @param extensionType If an ExtensionAbilityType is set, only extension of that type can be started.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode StartExtensionAbility(
        const Want &want,
        sptr<IRemoteObject> callerToken,
        int32_t userId = DEFAULT_INVALID_USER_ID,
        AppExecFwk::ExtensionAbilityType extensionType = AppExecFwk::ExtensionAbilityType::UNSPECIFIED);

    /**
     * Stop extension ability with want, send want to ability manager service.
     *
     * @param want, the want of the ability to stop.
     * @param callerToken, caller ability token.
     * @param userId, Designation User ID.
     * @param extensionType If an ExtensionAbilityType is set, only extension of that type can be stopped.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode StopExtensionAbility(
        const Want &want,
        sptr<IRemoteObject> callerToken,
        int32_t userId = DEFAULT_INVALID_USER_ID,
        AppExecFwk::ExtensionAbilityType extensionType = AppExecFwk::ExtensionAbilityType::UNSPECIFIED);

    /**
     * @brief Get the extension running information.
     *
     * @param upperLimit The maximum limit of information wish to get.
     * @param info Extension running information.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetExtensionRunningInfos(int upperLimit, std::vector<ExtensionRunningInfo> &info);

    /**
     * Transfer resultCode & want to abms.
     *
     * @param callerToken caller ability token.
     * @param requestCode the resultCode of the ability to start.
     * @param want Indicates the ability to start.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t TransferAbilityResultForExtension(const sptr<IRemoteObject> &callerToken, int32_t resultCode,
        const Want &want);
private:
    class ExtensionMgrDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        ExtensionMgrDeathRecipient() = default;
        ~ExtensionMgrDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    private:
        DISALLOW_COPY_AND_MOVE(ExtensionMgrDeathRecipient);
    };

    sptr<IExtensionManager> GetExtensionManager();
    void Connect();
    void ResetProxy(const wptr<IRemoteObject> &remote);
    ErrCode RemoveDeathRecipient();

    std::mutex mutex_;
    sptr<IExtensionManager> proxy_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_EXTENSION_MANAGER_CLIENT_H
