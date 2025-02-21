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

#ifndef OHOS_ABILITY_RUNTIME_HIDDEN_START_OBSERVER_MANAGER_H
#define OHOS_ABILITY_RUNTIME_HIDDEN_START_OBSERVER_MANAGER_H

#include <set>
#include <map>
#include "ffrt.h"
#include "ihidden_start_observer.h"
#include "singleton.h"

namespace OHOS {
namespace AAFwk {
using HiddenStartObserverSet = std::set<sptr<IHiddenStartObserver>>;

/**
 * @class HiddenStartObserverRecipient
 * HiddenStartObserverRecipient notices IRemoteBroker died.
 */
class HiddenStartObserverRecipient : public IRemoteObject::DeathRecipient {
    public:
        using RemoteDiedHandler = std::function<void(const wptr<IRemoteObject> &)>;
        explicit HiddenStartObserverRecipient(RemoteDiedHandler handler);
        virtual ~HiddenStartObserverRecipient();
        virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);
    
    private:
        RemoteDiedHandler handler_;
};

class HiddenStartObserverManager {
public:
    static HiddenStartObserverManager &GetInstance();
    int32_t RegisterObserver(const sptr<IHiddenStartObserver> &observer);
    int32_t UnregisterObserver(const sptr<IHiddenStartObserver> &observer);
    bool IsHiddenStart(int32_t uid);
    void OnObserverDied(const wptr<IRemoteObject> &remote);
    void AddObserverDeathRecipient(const sptr<IRemoteBroker> &observer);
    void RemoveObserverDeathRecipient(const sptr<IRemoteBroker> &observer);
    HiddenStartObserverSet GetObserversCopy();

private:
    bool ObserverExist(const sptr<IRemoteBroker> &observer);
    HiddenStartObserverManager();
    ~HiddenStartObserverManager();

private:
    ffrt::mutex observerLock_;
    std::map<sptr<IRemoteObject>, sptr<IRemoteObject::DeathRecipient>> recipientMap_;
    HiddenStartObserverSet observers_;
    ffrt::mutex recipientMapMutex_;
    DISALLOW_COPY_AND_MOVE(HiddenStartObserverManager);
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_HIDDEN_START_OBSERVER_MANAGER_H