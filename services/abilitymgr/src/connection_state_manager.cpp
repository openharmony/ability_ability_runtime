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

#include "connection_state_manager.h"

#include "connection_observer_errors.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AAFwk {
using namespace OHOS::AbilityRuntime;
ConnectionStateManager::ConnectionStateManager() {}

ConnectionStateManager::~ConnectionStateManager() {}

void ConnectionStateManager::Init()
{
    if (!observerController_) {
        observerController_ = std::make_shared<ConnectionObserverController>();
    }
}

int ConnectionStateManager::RegisterObserver(const sptr<AbilityRuntime::IConnectionObserver> &observer)
{
    if (!observerController_) {
        return ERR_SERVICE_NOT_INIT;
    }

    return observerController_->AddObserver(observer);
}

int ConnectionStateManager::UnregisterObserver(const sptr<AbilityRuntime::IConnectionObserver> &observer)
{
    if (!observerController_) {
        return ERR_SERVICE_NOT_INIT;
    }
    observerController_->RemoveObserver(observer);

    return 0;
}

void ConnectionStateManager::AddConnection(const std::shared_ptr<ConnectionRecord> &connectionRecord)
{
    if (!connectionRecord) {
        HILOG_ERROR("connection record is invalid");
        return;
    }

    ConnectionData connectionData;
    if (!AddConnectionInner(connectionRecord, connectionData)) {
        HILOG_WARN("add connection, no need to notify observers");
        return;
    }

    std::shared_ptr<ConnectionObserverController> controller = observerController_;
    if (controller) {
        controller->NotifyExtensionConnected(connectionData);
    }
}

void ConnectionStateManager::RemoveConnection(const std::shared_ptr<ConnectionRecord> &connectionRecord, bool isCallerDied)
{
    if (!connectionRecord) {
        HILOG_ERROR("connection record is invalid when remove connection");
        return;
    }

    // if caller died, notify at once.
    if (isCallerDied) {
        HandleCallerDied(connectionRecord);
        return;
    }

    ConnectionData connectionData;
    if (!RemoveConnectionInner(connectionRecord, connectionData)) {
        HILOG_WARN("remove connection, no need to notify observers");
        return;
    }

    std::shared_ptr<ConnectionObserverController> controller = observerController_;
    if (controller) {
        controller->NotifyExtensionDisconnected(connectionData);
    }
}

void ConnectionStateManager::AddDlpManager(const std::shared_ptr<AbilityRecord> &dlpManger)
{
    if (!dlpManger) {
        return;
    }

    auto userId = dlpManger->GetOwnerMissionUserId();
    std::lock_guard<std::recursive_mutex> guard(stateLock_);
    auto it = dlpItems_.find(userId);
    if (it == dlpItems_.end()) {
        dlpItems_[userId] = std::make_shared<DlpStateItem>(dlpManger->GetUid(), dlpManger->GetPid());
    }
}

void ConnectionStateManager::RemoveDlpManager(const std::shared_ptr<AbilityRecord> &dlpManger)
{
    if (!dlpManger) {
        return;
    }

    std::lock_guard<std::recursive_mutex> guard(stateLock_);
    dlpItems_.erase(dlpManger->GetOwnerMissionUserId());
}

void ConnectionStateManager::AddDlpAbility(const std::shared_ptr<AbilityRecord> &dlpAbility)
{
    DlpStateData dlpData;
    if (!HandleDlpAbilityInner(dlpAbility, true, dlpData)) {
        HILOG_DEBUG("no need to report dlp opened connection state.");
        return;
    }

    std::shared_ptr<ConnectionObserverController> controller = observerController_;
    if (controller) {
        controller->NotifyDlpAbilityOpened(dlpData);
    }
}

void ConnectionStateManager::RemoveDlpAbility(const std::shared_ptr<AbilityRecord> &dlpAbility)
{
    DlpStateData dlpData;
    if (!HandleDlpAbilityInner(dlpAbility, false, dlpData)) {
        HILOG_DEBUG("no need to report dlp closed connection state.");
        return;
    }

    std::shared_ptr<ConnectionObserverController> controller = observerController_;
    if (controller) {
        controller->NotifyDlpAbilityClosed(dlpData);
    }
}

bool ConnectionStateManager::AddConnectionInner(const std::shared_ptr<ConnectionRecord> &connectionRecord,
    AbilityRuntime::ConnectionData &data)
{
    std::shared_ptr<ConnectionStateItem> targetItem = nullptr;
    auto callerPid = connectionRecord->GetCallerPid();
    std::lock_guard<std::recursive_mutex> guard(stateLock_);
    auto it = connectionStates_.find(callerPid);
    if (it == connectionStates_.end()) {
        targetItem = ConnectionStateItem::CreateConnectionStateItem(connectionRecord);
        if (targetItem) {
            connectionStates_[callerPid] = targetItem;
        }
    } else {
        targetItem = it->second;
    }

    if (!targetItem) {
        HILOG_ERROR("failed to find target connection state item.");
        return false;
    }

    return targetItem->AddConnection(connectionRecord, data);
}

bool ConnectionStateManager::RemoveConnectionInner(const std::shared_ptr<ConnectionRecord> &connectionRecord,
    AbilityRuntime::ConnectionData &data)
{
    auto callerPid = connectionRecord->GetCallerPid();
    std::lock_guard<std::recursive_mutex> guard(stateLock_);
    auto it = connectionStates_.find(callerPid);
    if (it == connectionStates_.end()) {
        HILOG_WARN("can not find target item, connection caller pid:%{public}d.", callerPid);
        return false;
    }

    auto targetItem = it->second;
    if (!targetItem) {
        HILOG_ERROR("failed to find target connection state item.");
        return false;
    }

    return targetItem->RemoveConnection(connectionRecord, data);
}

void ConnectionStateManager::HandleCallerDied(const std::shared_ptr<ConnectionRecord> &connectionRecord)
{
    auto connectionStateItem = RemoveDiedCaller(connectionRecord->GetCallerPid());
    if (!connectionStateItem) {
        HILOG_WARN("no connectionStateItem, may already handled.");
        return;
    }

    std::vector<AbilityRuntime::ConnectionData> allConnectionData;
    connectionStateItem->GenerateAllConnectionData(allConnectionData);
    if (allConnectionData.empty()) {
        HILOG_WARN("allConnectionData is empty.");
        return;
    }

    std::shared_ptr<ConnectionObserverController> controller = observerController_;
    if (!controller) {
        return;
    }

    for (auto& connectionData : allConnectionData) {
        controller->NotifyExtensionDisconnected(connectionData);
    }
}

std::shared_ptr<ConnectionStateItem> ConnectionStateManager::RemoveDiedCaller(int32_t callerPid)
{
    std::lock_guard<std::recursive_mutex> guard(stateLock_);
    auto it = connectionStates_.find(callerPid);
    if (it == connectionStates_.end()) {
        HILOG_WARN("can not find target item, connection caller pid:%{public}d, may already handled.", callerPid);
        return nullptr;
    }
    auto stateItem = it->second;
    (void)connectionStates_.erase(it);

    return stateItem;
}

bool ConnectionStateManager::HandleDlpAbilityInner(const std::shared_ptr<AbilityRecord> &dlpAbility,
    bool isAdd, AbilityRuntime::DlpStateData &dlpData)
{
    if (!dlpAbility) {
        HILOG_DEBUG("invalid dlp ability.");
        return false;
    }

    if (dlpAbility->GetAppIndex() == 0) {
        HILOG_DEBUG("this is not dlp ability, do not report connection stat.");
        return false;
    }

    std::lock_guard<std::recursive_mutex> guard(dlpLock_);
    auto it = dlpItems_.find(dlpAbility->GetOwnerMissionUserId());
    if (it == dlpItems_.end()) {
        HILOG_WARN("no dlp manager, invalid state.");
        return false;
    }

    auto dlpItem = it->second;
    if (!dlpItem) {
        HILOG_WARN("invalid dlpItem.");
        return false;
    }

    if (isAdd) {
        return dlpItem->AddDlpConnectionState(dlpAbility, dlpData);
    }

    return dlpItem->RemoveDlpConnectionState(dlpAbility, dlpData);
}
} // namespace AAFwk
} // namespace OHOS
