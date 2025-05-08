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
#include "query_erms_observer_manager.h"

#include "ability_manager_service.h"
#include "ability_util.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {

// Mock class for QueryERMSObserver
class MockQueryERMSObserver : public IQueryERMSObserver {
public:
    void OnQueryFinished(const std::string &appId, const std::string &startTime,
        const AbilityRuntime::AtomicServiceStartupRule &rule, int resultCode) override {}
    sptr<IRemoteObject> AsObject() override { return nullptr; }
};

QueryERMSObserverManager::QueryERMSObserverManager()
{}

QueryERMSObserverManager::~QueryERMSObserverManager()
{}

QueryERMSObserverManager &QueryERMSObserverManager::GetInstance()
{
    static QueryERMSObserverManager manager;
    return manager;
}

int32_t QueryERMSObserverManager::AddObserver(int32_t recordId, const sptr<IQueryERMSObserver> &observer)
{
    TAG_LOGD(AAFwkTag::QUERY_ERMS, "test::begin");
    if (observer == nullptr) {
        TAG_LOGE(AAFwkTag::QUERY_ERMS, "null observer");
        return ERR_INVALID_VALUE;
    }
    return ERR_OK;
}

void QueryERMSObserverManager::OnQueryFinished(int32_t recordId, const std::string &appId,
    const std::string &startTime, const AtomicServiceStartupRule &rule, int resultCode)
{
    sptr<IQueryERMSObserver> observer = nullptr;
    if (ERR_OK == resultCode) {
        observer = sptr<IQueryERMSObserver>(new MockQueryERMSObserver());
    }
    observerMap_[recordId] = observer;
    TAG_LOGI(AAFwkTag::QUERY_ERMS, "testcalled");
}

void QueryERMSObserverManager::HandleOnQueryFinished(int32_t recordId, const std::string &appId,
    const std::string &startTime, const AtomicServiceStartupRule &rule, int resultCode)
{
    sptr<IQueryERMSObserver> observer = nullptr;
    if (ERR_OK == resultCode) {
        observer = sptr<IQueryERMSObserver>(new MockQueryERMSObserver());
    }
    observerMap_[recordId] = observer;
    TAG_LOGI(AAFwkTag::QUERY_ERMS, "testcalled");
}

void QueryERMSObserverManager::OnObserverDied(const wptr<IRemoteObject> &remote)
{
    TAG_LOGI(AAFwkTag::QUERY_ERMS, "called");
    auto remoteObj = remote.promote();
    if (remoteObj == nullptr) {
        TAG_LOGE(AAFwkTag::QUERY_ERMS, "null observer");
        return;
    }
    remoteObj->RemoveDeathRecipient(deathRecipient_);

    std::lock_guard<ffrt::mutex> lock(observerLock_);
    for (auto &item : observerMap_) {
        if (item.second && item.second->AsObject() == remoteObj) {
            observerMap_.erase(item.first);
            return;
        }
    }
}

QueryERMSObserverRecipient::QueryERMSObserverRecipient(RemoteDiedHandler handler) : handler_(handler)
{}

QueryERMSObserverRecipient::~QueryERMSObserverRecipient()
{}

void QueryERMSObserverRecipient::OnRemoteDied(const wptr<IRemoteObject> &__attribute__((unused)) remote)
{
    TAG_LOGI(AAFwkTag::QUERY_ERMS, "called");
    if (handler_) {
        handler_(remote);
    }
}
} // namespace AAFwk
} // namespace OHOS