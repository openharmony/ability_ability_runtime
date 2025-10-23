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

#ifndef OHOS_ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_MANAGER
#define OHOS_ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_MANAGER

#include <map>
#include <mutex>

#include "ability_record.h"
#include "foreground_app_connection_stub.h"
#include "iforeground_app_connection.h"
#include "nocopyable.h"
#include "singleton.h"

namespace OHOS {
namespace AAFwk {
struct ForegroundAppConnectionInfo {
    int32_t callerPid_ = -1;
    int32_t targetPid_ = -1;

    int32_t callerUid_ = 0;
    int32_t targetUid_ = 0;

    std::string callerBundleName_ = "";
    std::string targetBundleName_ = "";

    std::vector<int32_t> abilityRecordIds_;

    ForegroundAppConnectionInfo(int32_t callerPid, int32_t targetPid, int32_t callerUid, int32_t targetUid,
        const std::string &callerBundleName, const std::string &targetBundleName)
        : callerPid_(callerPid), targetPid_(targetPid), callerUid_(callerUid), targetUid_(targetUid),
        callerBundleName_(callerBundleName), targetBundleName_(targetBundleName) {}
    void AddAbilityRecordId(int32_t abilityRecordId);
    void RemoveAbilityRecordId(int32_t abilityRecordId);
};

class ForegroundAppConnectionManager : public std::enable_shared_from_this<ForegroundAppConnectionManager> {
    DECLARE_DELAYED_SINGLETON(ForegroundAppConnectionManager)
public:

    int32_t RegisterObserver(sptr<AbilityRuntime::IForegroundAppConnection> observer);
    int32_t UnregisterObserver(sptr<AbilityRuntime::IForegroundAppConnection> observer);
    void OnConnected(AbilityRuntime::ForegroundAppConnectionData &data);
    void OnDisconnected(AbilityRuntime::ForegroundAppConnectionData &data);
    void OnCallerStarted(int32_t callerPid, int32_t callerUid, const std::string &bundleName);

    void AbilityAddPidConnection(ForegroundAppConnectionInfo &info, int32_t abilityRecordId);
    void AbilityRemovePidConnection(int32_t callerPid, int32_t targetPid, int32_t abilityRecordId);
    void ProcessRemovePidConnection(int32_t diedPid);

private:
    void HandleRemoteDied(const wptr<IRemoteObject> &remoteObject);
    void GenerateConnectionData(ForegroundAppConnectionInfo &info,
        AbilityRuntime::ForegroundAppConnectionData &data);

    class ConnectionDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        using ConnectionDeathHandler = std::function<void(const wptr<IRemoteObject> &remoteObject)>;
        explicit ConnectionDeathRecipient(ConnectionDeathHandler handler);
        ~ConnectionDeathRecipient() = default;

        void OnRemoteDied(const wptr<IRemoteObject> &remoteObject) final;

    private:
        ConnectionDeathHandler deathHandler_;
    };

private:
    std::mutex observerMutex_;
    std::vector<sptr<AbilityRuntime::IForegroundAppConnection>> observerList_;

    std::mutex pidMapMutex_;
    std::map<std::string, ForegroundAppConnectionInfo> pidMap_;

    sptr<IRemoteObject::DeathRecipient> observerDeathRecipient_ = nullptr;

    DISALLOW_COPY_AND_MOVE(ForegroundAppConnectionManager);
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_MANAGER