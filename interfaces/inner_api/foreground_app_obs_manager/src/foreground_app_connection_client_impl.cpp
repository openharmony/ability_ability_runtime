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

#include "foreground_app_connection_client_impl.h"

#include "connection_observer_errors.h"
#include "foreground_app_connection_stub_impl.h"
#include "hilog_tag_wrapper.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AbilityRuntime {
int32_t ForegroundAppConnectionClientImpl::RegisterObserver(const std::shared_ptr<ForegroundAppConnection> &observer)
{
    if (!observer) {
        TAG_LOGE(AAFwkTag::CONNECTION, "invalid observer");
        return ERR_INVALID_OBSERVER;
    }

    auto proxy = GetServiceProxy();

    std::lock_guard<std::mutex> guard(observerLock_);
    if (!RegisterObserverToServiceLocked(proxy)) {
        TAG_LOGE(AAFwkTag::CONNECTION, "register failed");
        return ERR_REGISTER_FAILED;
    }

    return AddObserversLocked(observer);
}

int32_t ForegroundAppConnectionClientImpl::UnregisterObserver(const std::shared_ptr<ForegroundAppConnection> &observer)
{
    if (!observer) {
        TAG_LOGE(AAFwkTag::CONNECTION, "invalid observer");
        return ERR_INVALID_OBSERVER;
    }

    auto proxy = GetServiceProxy();

    std::lock_guard<std::mutex> guard(observerLock_);
    auto ret = RemoveObserversLocked(observer);
    if (userObservers_.empty()) {
        UnregisterFromServiceLocked(proxy);
    }

    return ret;
}

void ForegroundAppConnectionClientImpl::HandleOnForegroundAppConnected(const ForegroundAppConnectionData &data)
{
    TAG_LOGD(AAFwkTag::CONNECTION, "HandleOnForegroundAppConnected called");
    auto observers = GetObservers();
    for (auto it = observers.begin(); it != observers.end(); ++it) {
        auto observer = *it;
        if (observer) {
            observer->OnForegroundAppConnected(data);
        }
    }
}

void ForegroundAppConnectionClientImpl::HandleOnForegroundAppDisconnected(const ForegroundAppConnectionData &data)
{
    TAG_LOGD(AAFwkTag::CONNECTION, "HandleOnForegroundAppDisconnected called");
    auto observers = GetObservers();
    for (auto it = observers.begin(); it != observers.end(); ++it) {
        auto observer = *it;
        if (observer) {
            observer->OnForegroundAppDisconnected(data);
        }
    }
}

void ForegroundAppConnectionClientImpl::HandleOnForegroundAppCallerStarted(int32_t callerPid, int32_t callerUid,
    const std::string &bundleName)
{
    TAG_LOGD(AAFwkTag::CONNECTION, "HandleOnForegroundAppCallerStarted called");
    auto observers = GetObservers();
    for (auto it = observers.begin(); it != observers.end(); ++it) {
        auto observer = *it;
        if (observer) {
            observer->OnForegroundAppCallerStarted(callerPid, callerUid, bundleName);
        }
    }
}

bool ForegroundAppConnectionClientImpl::RegisterObserverToServiceLocked(
    const std::shared_ptr<ForegroundAppConnectionProxyAdapter> &proxy)
{
    if (isRegistered_) {
        return true;
    }

    if (!proxy) {
        TAG_LOGE(AAFwkTag::CONNECTION, "fail to get service");
        return false;
    }

    if (!observer_) {
        observer_ = sptr<ForegroundAppConnectionStubImpl>::MakeSptr(shared_from_this());
    }

    if (proxy->RegisterObserver(observer_) != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONNECTION, "register observer failed");
        return false;
    }
    isRegistered_ = true;
    return true;
}

void ForegroundAppConnectionClientImpl::UnregisterFromServiceLocked(
    const std::shared_ptr<ForegroundAppConnectionProxyAdapter> &proxy)
{
    if (!isRegistered_ || !observer_) {
        return;
    }

    if (!proxy) {
        return;
    }

    if (proxy->UnregisterObserver(observer_) != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONNECTION, "unregister observer failed");
        return;
    }
    isRegistered_ = false;
}

int32_t ForegroundAppConnectionClientImpl::AddObserversLocked(
    const std::shared_ptr<ForegroundAppConnection> &observer)
{
    if (userObservers_.find(observer) != userObservers_.end()) {
        TAG_LOGE(AAFwkTag::CONNECTION, "observer already registered");
        return ERR_OBSERVER_ALREADY_REGISTERED;
    }
    userObservers_.emplace(observer);
    TAG_LOGD(AAFwkTag::CONNECTION, "ForegroundAppConnection add userObserver size: %{public}zu",
        userObservers_.size());
    return ERR_OK;
}

int32_t ForegroundAppConnectionClientImpl::RemoveObserversLocked(
    const std::shared_ptr<ForegroundAppConnection> &observer)
{
    if (userObservers_.find(observer) == userObservers_.end()) {
        TAG_LOGE(AAFwkTag::CONNECTION, "no such observer");
        return ERR_OBSERVER_NOT_REGISTERED;
    }
    userObservers_.erase(observer);
    TAG_LOGD(AAFwkTag::CONNECTION, "ForegroundAppConnection remove userObserver size: %{public}zu",
        userObservers_.size());
    return ERR_OK;
}

std::shared_ptr<ForegroundAppConnectionProxyAdapter> ForegroundAppConnectionClientImpl::GetServiceProxy()
{
    std::lock_guard<std::mutex> guard(proxyLock_);
    if (!proxyAdapter_) {
        ConnectLocked();
    }
    return proxyAdapter_;
}

void ForegroundAppConnectionClientImpl::ConnectLocked()
{
    if (proxyAdapter_ != nullptr) {
        return;
    }
    sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemManager == nullptr) {
        TAG_LOGE(AAFwkTag::CONNECTION, "get system ability registry failed");
        return;
    }
    sptr<IRemoteObject> remoteObj = systemManager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    if (remoteObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONNECTION, "connect failed");
        return;
    }

    deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(
        new (std::nothrow) ServiceDeathRecipient(shared_from_this()));
    if (deathRecipient_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONNECTION, "create DeathRecipient failed");
        return;
    }
    if ((remoteObj->IsProxyObject()) && (!remoteObj->AddDeathRecipient(deathRecipient_))) {
        TAG_LOGE(AAFwkTag::CONNECTION, "Add death recipient failed");
        return;
    }

    proxyAdapter_ = std::make_shared<ForegroundAppConnectionProxyAdapter>(remoteObj);
    TAG_LOGI(AAFwkTag::CONNECTION, "Connect success");
}

void ForegroundAppConnectionClientImpl::HandleRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (!ResetProxy(remote)) {
        return;
    }
    NotifyServiceDiedToObservers();
}

bool ForegroundAppConnectionClientImpl::ResetProxy(const wptr<IRemoteObject> &remote)
{
    std::lock_guard<std::mutex> guard(proxyLock_);
    if (proxyAdapter_ == nullptr) {
        return false;
    }

    auto proxyObject = proxyAdapter_->GetProxyObject();
    if ((proxyObject != nullptr) && (proxyObject == remote.promote())) {
        proxyObject->RemoveDeathRecipient(deathRecipient_);
        proxyAdapter_ = nullptr;
        return true;
    }

    return false;
}

void ForegroundAppConnectionClientImpl::ResetStatus()
{
    std::lock_guard<std::mutex> guard(observerLock_);
    isRegistered_ = false;
    userObservers_.clear();
}

void ForegroundAppConnectionClientImpl::NotifyServiceDiedToObservers()
{
    auto observers = GetObservers();
    ResetStatus();
    for (auto it = observers.begin(); it != observers.end(); ++it) {
        auto observer = *it;
        if (observer) {
            observer->OnServiceDied();
        }
    }
}

std::unordered_set<std::shared_ptr<ForegroundAppConnection>> ForegroundAppConnectionClientImpl::GetObservers()
{
    std::lock_guard<std::mutex> guard(observerLock_);
    return userObservers_;
}

void ForegroundAppConnectionClientImpl::ServiceDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    TAG_LOGI(AAFwkTag::CONNECTION, "onRemoteDied called");
    auto owner = owner_.lock();
    if (!owner) {
        TAG_LOGE(AAFwkTag::CONNECTION, "OnRemoteDied");
        return;
    }
    owner->HandleRemoteDied(remote);
}
} // namespace AbilityRuntime
} // namespace OHOS
