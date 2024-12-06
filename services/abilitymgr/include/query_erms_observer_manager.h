/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_QUERY_ERMS_OBSERVER_MANAGER_H
#define OHOS_ABILITY_RUNTIME_QUERY_ERMS_OBSERVER_MANAGER_H

#include <map>
#include <mutex>
#include <unordered_map>
#include "cpp/mutex.h"

#include "query_erms_observer_interface.h"
#include "singleton.h"

namespace OHOS {
namespace AAFwk {
using namespace OHOS::AbilityRuntime;
class QueryERMSObserverManager {
public:
    static QueryERMSObserverManager &GetInstance();

    int32_t AddObserver(int32_t recordId, const sptr<IQueryERMSObserver> &observer);

    void OnQueryFinished(int32_t recordId, const std::string &appId, const std::string &startTime,
        const AtomicServiceStartupRule &rule, int resultCode);

    void OnObserverDied(const wptr<IRemoteObject> &remote);

    void HandleOnQueryFinished(int32_t recordId, const std::string &appId, const std::string &startTime,
        const AtomicServiceStartupRule &rule, int resultCode);

private:
    QueryERMSObserverManager();
    ~QueryERMSObserverManager();

private:
    ffrt::mutex observerLock_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
    std::unordered_map<int32_t, sptr<IQueryERMSObserver>> observerMap_;
    DISALLOW_COPY_AND_MOVE(QueryERMSObserverManager);
};

class QueryERMSObserverRecipient : public IRemoteObject::DeathRecipient {
public:
    using RemoteDiedHandler = std::function<void(const wptr<IRemoteObject> &)>;
    explicit QueryERMSObserverRecipient(RemoteDiedHandler handler);
    virtual ~QueryERMSObserverRecipient();
    virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);

private:
    RemoteDiedHandler handler_;
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_QUERY_ERMS_OBSERVER_MANAGER_H