/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_CLIENT_IMPL_H
#define ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_CLIENT_IMPL_H

#include <mutex>
#include <unordered_set>

#include "foreground_app_connection.h"
#include "foreground_app_connection_proxy_adapter.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @class ForegroundAppConnectionClientImpl
 * ForegroundAppConnectionClientImpl is used to manage connection observer.
 */
class ForegroundAppConnectionClientImpl : public std::enable_shared_from_this<ForegroundAppConnectionClientImpl> {
public:
    ForegroundAppConnectionClientImpl() = default;
    virtual ~ForegroundAppConnectionClientImpl() = default;

    int32_t RegisterObserver(const std::shared_ptr<ForegroundAppConnection> &observer);
    int32_t UnregisterObserver(const std::shared_ptr<ForegroundAppConnection> &observer);
    void HandleOnForegroundAppConnected(const ForegroundAppConnectionData &data);
    void HandleOnForegroundAppDisconnected(const ForegroundAppConnectionData &data);
    void HandleOnForegroundAppCallerStarted(int32_t callerPid, int32_t callerUid,
        const std::string &bundleName);
    void HandleRemoteDied(const wptr<IRemoteObject> &remote);

private:
    class ServiceDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit ServiceDeathRecipient(
            const std::shared_ptr<ForegroundAppConnectionClientImpl> &owner) : owner_(owner) {}

        virtual ~ServiceDeathRecipient() = default;

        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

    private:
        std::weak_ptr<ForegroundAppConnectionClientImpl> owner_;
    };

    std::unordered_set<std::shared_ptr<ForegroundAppConnection>> GetObservers();
    std::shared_ptr<ForegroundAppConnectionProxyAdapter> GetServiceProxy();
    void ConnectLocked();
    bool RegisterObserverToServiceLocked(const std::shared_ptr<ForegroundAppConnectionProxyAdapter> &proxy);
    void UnregisterFromServiceLocked(const std::shared_ptr<ForegroundAppConnectionProxyAdapter> &proxy);
    int32_t AddObserversLocked(const std::shared_ptr<ForegroundAppConnection> &observer);
    int32_t RemoveObserversLocked(const std::shared_ptr<ForegroundAppConnection> &observer);
    bool ResetProxy(const wptr<IRemoteObject> &remote);
    void ResetStatus();
    void NotifyServiceDiedToObservers();

    std::mutex observerLock_; // observer lock
    bool isRegistered_ = false; // mark whether register observer to abilityms.
    sptr<IForegroundAppConnection> observer_; // observer stub; actually used in abilityms.
    std::unordered_set<std::shared_ptr<ForegroundAppConnection>> userObservers_; // all real registered observers.

    std::mutex proxyLock_; // proxy lock.
    std::shared_ptr<ForegroundAppConnectionProxyAdapter> proxyAdapter_; // abilityms proxy adapter.
    sptr<IRemoteObject::DeathRecipient> deathRecipient_; // abilityms death recipient.
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_CLIENT_IMPL_H
