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

#ifndef OHOS_ABILITY_RUNTIME_CONNECTION_MANAGER_H
#define OHOS_ABILITY_RUNTIME_CONNECTION_MANAGER_H

#include <chrono>
#include <map>
#include <vector>
#include "ability_connect_callback.h"
#include "ability_connection.h"
#include "element_name.h"
#include "errors.h"
#include "extension_ability_info.h"
#include "operation.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
struct ConnectionInfo {
    // connection caller
    sptr<IRemoteObject> connectCaller;
    // connection receiver
    AAFwk::Operation connectReceiver;
    // connection
    sptr<AbilityConnection> abilityConnection;

    int32_t userid;
    void* uiServiceExtProxy = nullptr;
    int64_t connectingTime = 0;

    ConnectionInfo(const sptr<IRemoteObject> &connectCaller, const AAFwk::Operation &connectReceiver,
        const sptr<AbilityConnection> &abilityConnection, int32_t accountId = -1) : connectCaller(connectCaller),
        connectReceiver(connectReceiver), abilityConnection(abilityConnection), userid(accountId)
    {
    }

    void SetUIServiceExtProxyPtr(void* proxyPtr)
    {
        uiServiceExtProxy = proxyPtr;
    }

    void RecordConnectingTime()
    {
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        connectingTime = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    }

    inline bool operator < (const ConnectionInfo &that) const
    {
        if (userid < that.userid) {
            return true;
        }
        if (uiServiceExtProxy < that.uiServiceExtProxy) {
            return true;
        }
        if (connectCaller < that.connectCaller) {
            return true;
        }
        if (connectingTime < that.connectingTime) {
            return true;
        }
        if (connectCaller == that.connectCaller &&
            connectReceiver.GetBundleName() < that.connectReceiver.GetBundleName()) {
            return true;
        }
        if (connectCaller == that.connectCaller &&
            connectReceiver.GetBundleName() == that.connectReceiver.GetBundleName() &&
            connectReceiver.GetModuleName() < that.connectReceiver.GetModuleName()) {
            return true;
        }
        if (connectCaller == that.connectCaller &&
            connectReceiver.GetBundleName() == that.connectReceiver.GetBundleName() &&
            connectReceiver.GetModuleName() == that.connectReceiver.GetModuleName() &&
            connectReceiver.GetAbilityName() < that.connectReceiver.GetAbilityName()) {
            return true;
        }
        if (connectCaller == that.connectCaller &&
            connectReceiver.GetBundleName() == that.connectReceiver.GetBundleName() &&
            connectReceiver.GetModuleName() == that.connectReceiver.GetModuleName() &&
            connectReceiver.GetAbilityName() == that.connectReceiver.GetAbilityName() &&
            !(connectReceiver == that.connectReceiver)) {
            return true;
        }
        return false;
    }
};

class ConnectionManager {
public:
    /**
     * @brief Destructor.
     *
     */
    ~ConnectionManager() = default;

    ConnectionManager(const ConnectionManager&)=delete;

    ConnectionManager& operator=(const ConnectionManager&)=delete;

    static ConnectionManager& GetInstance();

    /**
     * @brief connect ability connection.
     *
     * @param connectCaller The connection caller.
     * @param connectReceiver The connection receiver.
     * @param connectCallback The connection callback.
     * @return Returns the result of connecting ability connection.
     */
    ErrCode ConnectAbility(const sptr<IRemoteObject> &connectCaller,
        const AAFwk::Want &want, const sptr<AbilityConnectCallback> &connectCallback);

    /**
     * @brief connect ability connection by user.
     *
     * @param connectCaller The connection caller.
     * @param connectReceiver The connection receiver.
     * @param accountId caller user.
     * @param connectCallback The connection callback.
     * @return Returns the result of connecting ability connection.
     */
    ErrCode ConnectAbilityWithAccount(const sptr<IRemoteObject> &connectCaller,
        const AAFwk::Want &want, int accountId, const sptr<AbilityConnectCallback> &connectCallback);

    /**
     * @brief connect uiService ability connection.
     *
     * @param connectCaller The connection caller.
     * @param connectReceiver The connection receiver.
     * @param connectCallback The connection callback.
     * @return Returns the result of connecting uiService ability connection.
     */
    ErrCode ConnectUIServiceExtensionAbility(const sptr<IRemoteObject>& connectCaller,
        const AAFwk::Want& want, const sptr<AbilityConnectCallback>& connectCallback);

    /**
     * @brief connect appService ability connection.
     *
     * @param connectCaller The connection caller.
     * @param connectReceiver The connection receiver.
     * @param connectCallback The connection callback.
     * @return Returns the result of connecting appService ability connection.
     */
    ErrCode ConnectAppServiceExtensionAbility(const sptr<IRemoteObject>& connectCaller,
        const AAFwk::Want& want, const sptr<AbilityConnectCallback>& connectCallback);
    
    /**
     * @brief disconnect ability connection.
     *
     * @param connectCaller The connection caller.
     * @param connectReceiver The connection receiver.
     * @param connectCallback The connection callback.
     * @return Returns the result of disconnecting ability connection.
     */
    ErrCode DisconnectAbility(const sptr<IRemoteObject> &connectCaller,
        const AppExecFwk::ElementName &connectReceiver, const sptr<AbilityConnectCallback> &connectCallback);

    /**
     * @brief disconnect ability connection.
     *
     * @param connectCaller The connection caller.
     * @param connectReceiver The connection receiver.
     * @param connectCallback The connection callback.
     * @return Returns the result of disconnecting ability connection.
     */
    ErrCode DisconnectAbility(const sptr<IRemoteObject> &connectCaller, const AAFwk::Want &connectReceiver,
        const sptr<AbilityConnectCallback> &connectCallback, int32_t accountId = -1);

    /**
     * @brief check the ability connection of caller is disconnect.
     *
     * @param connectCaller The connection caller.
     * @return Returns whether the ability connection of caller is disconnect.
     */
    bool DisconnectCaller(const sptr<IRemoteObject> &connectCaller);

    /**
     * @brief When service is dead, remove the connection
     *
     * @param connection The connection.
     * @return Returns whether the connection is removed.
     */
    bool RemoveConnection(const sptr<AbilityConnection> connection);

    /**
     * @brief Report the ability connection leak event.
     *
     * @param pid The process id.
     * @param tid The thread id.
     */
    void ReportConnectionLeakEvent(const int pid, const int tid);

    bool DisconnectNonexistentService(const AppExecFwk::ElementName& element,
        const sptr<AbilityConnection> connection);
private:
    ConnectionManager() = default;
    bool IsConnectCallerEqual(const sptr<IRemoteObject> &connectCaller, const sptr<IRemoteObject> &connectCallerOther);
    bool IsConnectReceiverEqual(AAFwk::Operation &connectReceiver,
        const AppExecFwk::ElementName &connectReceiverOther);
    void* GetUIServiceExtProxyPtr(const AAFwk::Want& want);
    bool MatchConnection(
        const sptr<IRemoteObject>& connectCaller, const AAFwk::Want& connectReceiver, int32_t accountId,
        const std::map<ConnectionInfo, std::vector<sptr<AbilityConnectCallback>>>::value_type& connection);
    std::recursive_mutex connectionsLock_;
    std::map<ConnectionInfo, std::vector<sptr<AbilityConnectCallback>>> abilityConnections_;
    ErrCode ConnectAbilityInner(const sptr<IRemoteObject> &connectCaller,
        const AAFwk::Want &want, int accountId, const sptr<AbilityConnectCallback> &connectCallback,
        AppExecFwk::ExtensionAbilityType extensionType = AppExecFwk::ExtensionAbilityType::SERVICE);
    ErrCode CreateConnection(const sptr<IRemoteObject> &connectCaller, const AAFwk::Want &want, int accountId,
        const sptr<AbilityConnectCallback> &connectCallback,
        AppExecFwk::ExtensionAbilityType extensionType = AppExecFwk::ExtensionAbilityType::SERVICE);
    bool IsConnectingTimeout(const ConnectionInfo& info);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_CONNECTION_MANAGER_H
