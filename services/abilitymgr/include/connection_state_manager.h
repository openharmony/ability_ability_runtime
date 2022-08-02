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

#ifndef OHOS_AAFWK_CONNECTION_STATE_MANAGER_H
#define OHOS_AAFWK_CONNECTION_STATE_MANAGER_H

#include <mutex>
#include <unordered_map>

#include "connection_state_item.h"
#include "connection_observer_controller.h"
#include "dlp_state_item.h"

namespace OHOS {
namespace AAFwk {
/**
 * @class ConnectionStateManager
 * ConnectionStateManager manage connection states.
 */
class ConnectionStateManager : public std::enable_shared_from_this<ConnectionStateManager> {
    DECLARE_DELAYED_SINGLETON(ConnectionStateManager)
public:
    static std::string GetProcessNameByPid(int32_t pid);
    void Init();
    int RegisterObserver(const sptr<AbilityRuntime::IConnectionObserver> &observer);
    int UnregisterObserver(const sptr<AbilityRuntime::IConnectionObserver> &observer);
    void AddConnection(const std::shared_ptr<ConnectionRecord> &connectionRecord);
    void RemoveConnection(const std::shared_ptr<ConnectionRecord> &connectionRecord, bool isCallerDied);
    void AddDataAbilityConnection(const DataAbilityCaller &caller,
        const std::shared_ptr<DataAbilityRecord> &record);
    void RemoveDataAbilityConnection(const DataAbilityCaller &caller,
        const std::shared_ptr<DataAbilityRecord> &record);
    void HandleDataAbilityDied(const std::shared_ptr<DataAbilityRecord> &record);
    void HandleDataAbilityCallerDied(int32_t callerPid);
    void AddDlpManager(const std::shared_ptr<AbilityRecord> &dlpManger);
    void RemoveDlpManager(const std::shared_ptr<AbilityRecord> &dlpManger);
    void AddDlpAbility(const std::shared_ptr<AbilityRecord> &dlpAbility);
    void RemoveDlpAbility(const std::shared_ptr<AbilityRecord> &dlpAbility);

private:
    bool AddConnectionInner(const std::shared_ptr<ConnectionRecord> &connectionRecord,
        AbilityRuntime::ConnectionData &data);
    bool RemoveConnectionInner(const std::shared_ptr<ConnectionRecord> &connectionRecord,
        AbilityRuntime::ConnectionData &data);
    bool AddDataAbilityConnectionInner(const DataAbilityCaller &caller,
        const std::shared_ptr<DataAbilityRecord> &record, AbilityRuntime::ConnectionData &data);
    bool RemoveDataAbilityConnectionInner(const DataAbilityCaller &caller,
        const std::shared_ptr<DataAbilityRecord> &record, AbilityRuntime::ConnectionData &data);
    void HandleCallerDied(int32_t callerPid);
    std::shared_ptr<ConnectionStateItem> RemoveDiedCaller(int32_t callerPid);
    void HandleDataAbilityDiedInner(const sptr<IRemoteObject> &abilityToken,
        std::vector<AbilityRuntime::ConnectionData> &allData);
    bool HandleDlpAbilityInner(const std::shared_ptr<AbilityRecord> &dlpAbility,
        bool isAdd, AbilityRuntime::DlpStateData &dlpData);

private:
    std::shared_ptr<ConnectionObserverController> observerController_;

    std::recursive_mutex stateLock_;
    std::unordered_map<int32_t, std::shared_ptr<ConnectionStateItem>> connectionStates_;

    std::recursive_mutex dlpLock_;
    std::unordered_map<int32_t, std::shared_ptr<DlpStateItem>> dlpItems_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_AAFWK_CONNECTION_STATE_MANAGER_H
