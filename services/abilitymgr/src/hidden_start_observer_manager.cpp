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

#include <mutex>
#include "hidden_start_observer_manager.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "hidden_start_observer_stub.h"

namespace OHOS {
namespace AAFwk {
HiddenStartObserverManager::HiddenStartObserverManager()
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "HiddenStartObserverManager instance is created");
}

HiddenStartObserverManager::~HiddenStartObserverManager()
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "HiddenStartObserverManager instance is destroyed");
}

HiddenStartObserverManager &HiddenStartObserverManager::GetInstance()
{
    static HiddenStartObserverManager manager_;
    return manager_;
}

int32_t HiddenStartObserverManager::RegisterObserver(const sptr<IHiddenStartObserver> &observer)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "RegisterObserver called");
    if (observer == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null observer");
        return ERR_INVALID_VALUE;
    }
    if (ObserverExist(observer)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "observer exist");
        return ERR_INVALID_VALUE;
    }
    std::lock_guard<ffrt::mutex> lockRegister(observerLock_);
    observers_.emplace(observer);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "hidden start observers_ size:%{public}zu", observers_.size());
    AddObserverDeathRecipient(observer);
    return ERR_OK;
}

int32_t HiddenStartObserverManager::UnregisterObserver(const sptr<IHiddenStartObserver> &observer)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "UnregisterObserver called");
    if (observer == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null observer");
        return ERR_INVALID_VALUE;
    }
    std::lock_guard<ffrt::mutex> lockUnregister(observerLock_);
    auto it = observers_.begin();
    for (;it != observers_.end(); ++it) {
        if ((*it)->AsObject() == observer->AsObject()) {
            observers_.erase(it);
            TAG_LOGD(AAFwkTag::ABILITYMGR, "hidden start observers_ size:%{public}zu", observers_.size());
            RemoveObserverDeathRecipient(observer);
            return ERR_OK;
        }
    }
    TAG_LOGE(AAFwkTag::ABILITYMGR, "observer not exist");
    return ERR_INVALID_VALUE;
}

bool HiddenStartObserverManager::ObserverExist(const sptr<IRemoteBroker> &observer)
{
    if (observer == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null observer");
        return false;
    }
    std::lock_guard<ffrt::mutex> lockRegister(observerLock_);
    for (auto it = observers_.begin(); it != observers_.end(); ++it) {
        if ((*it)->AsObject() == observer->AsObject()) {
            return true;
        }
    }
    return false;
}

bool HiddenStartObserverManager::IsHiddenStart(int32_t uid)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto observersCopy = GetObserversCopy();
    TAG_LOGE(AAFwkTag::ABILITYMGR, "Need query %{public}zu observers.", observersCopy.size());
    for (auto it = observersCopy.begin(); it != observersCopy.end(); ++it) {
        if (*it == nullptr) {
            continue;
        }
        if ((*it)->IsHiddenStart(uid)) {
            return true;
        }
    }
    return false;
}

void HiddenStartObserverManager::AddObserverDeathRecipient(const sptr<IRemoteBroker> &observer)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Add observer death recipient begin.");
    if (observer == nullptr || observer->AsObject() == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null observer");
        return;
    }
    std::lock_guard lock(recipientMapMutex_);
    auto it = recipientMap_.find(observer->AsObject());
    if (it != recipientMap_.end()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Death recipient added");
        return;
    }
    sptr<IRemoteObject::DeathRecipient> deathRecipient = nullptr;
    auto deathRecipientFunc = [](const wptr<IRemoteObject> &remote) {
        HiddenStartObserverManager::GetInstance().OnObserverDied(remote);
    };
    deathRecipient = new (std::nothrow) HiddenStartObserverRecipient(deathRecipientFunc);
    if (deathRecipient == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null deathRecipient");
        return;
    }
    if (!observer->AsObject()->AddDeathRecipient(deathRecipient)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AddDeathRecipient failed");
    }
    recipientMap_.emplace(observer->AsObject(), deathRecipient);
}

void HiddenStartObserverManager::RemoveObserverDeathRecipient(const sptr<IRemoteBroker> &observer)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Remove observer death recipient begin.");
    if (observer == nullptr || observer->AsObject() == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null observer");
        return;
    }
    std::lock_guard lock(recipientMapMutex_);
    auto it = recipientMap_.find(observer->AsObject());
    if (it != recipientMap_.end()) {
        it->first->RemoveDeathRecipient(it->second);
        recipientMap_.erase(it);
        return;
    }
}

void HiddenStartObserverManager::OnObserverDied(const wptr<IRemoteObject> &remote)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "OnObserverDied");
    auto object = remote.promote();
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null observer");
        return;
    }

    sptr<IHiddenStartObserver> observer = iface_cast<IHiddenStartObserver>(object);
    UnregisterObserver(observer);
}

HiddenStartObserverSet HiddenStartObserverManager::GetObserversCopy()
{
    std::lock_guard<ffrt::mutex> lock(observerLock_);
    return observers_;
}

HiddenStartObserverRecipient::HiddenStartObserverRecipient(RemoteDiedHandler handler) : handler_(handler)
{}

HiddenStartObserverRecipient::~HiddenStartObserverRecipient()
{}

void HiddenStartObserverRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (handler_) {
        handler_(remote);
    }
}
} // namespace AAFwk
} // namespace OHOS