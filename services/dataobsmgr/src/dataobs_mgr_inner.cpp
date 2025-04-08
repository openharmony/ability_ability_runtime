/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "dataobs_mgr_inner.h"

#include "data_ability_observer_stub.h"
#include "dataobs_mgr_errors.h"
#include "hilog_tag_wrapper.h"
#include "common_utils.h"

namespace OHOS {
namespace AAFwk {

DataObsMgrInner::DataObsMgrInner() {}

DataObsMgrInner::~DataObsMgrInner() {}

int DataObsMgrInner::HandleRegisterObserver(const Uri &uri, struct ObserverNode observerNode)
{
    std::lock_guard<ffrt::mutex> lock(innerMutex_);

    auto [obsPair, flag] = observers_.try_emplace(uri.ToString(), std::list<struct ObserverNode>());
    if (!flag && obsPair->second.size() > OBS_NUM_MAX) {
        TAG_LOGE(AAFwkTag::DBOBSMGR,
            "subscribers num:%{public}s maxed",
            CommonUtils::Anonymous(uri.ToString()).c_str());
        return DATAOBS_SERVICE_OBS_LIMMIT;
    }

    for (auto obs = obsPair->second.begin(); obs != obsPair->second.end(); obs++) {
        if ((*obs).observer_->AsObject() == observerNode.observer_->AsObject()) {
            TAG_LOGE(AAFwkTag::DBOBSMGR, "obs registered:%{public}s",
                CommonUtils::Anonymous(uri.ToString()).c_str());
            return OBS_EXIST;
        }
    }

    obsPair->second.push_back(observerNode);

    AddObsDeathRecipient(observerNode.observer_);

    return NO_ERROR;
}

int DataObsMgrInner::HandleUnregisterObserver(const Uri &uri, struct ObserverNode observerNode)
{
    std::lock_guard<ffrt::mutex> lock(innerMutex_);

    auto obsPair = observers_.find(uri.ToString());
    if (obsPair == observers_.end()) {
        TAG_LOGW(
            AAFwkTag::DBOBSMGR, "uri no obs:%{public}s", CommonUtils::Anonymous(uri.ToString()).c_str());
        return NO_OBS_FOR_URI;
    }

    TAG_LOGD(AAFwkTag::DBOBSMGR, "obs num:%{public}zu:%{public}s", obsPair->second.size(),
        CommonUtils::Anonymous(uri.ToString()).c_str());
    auto obs = obsPair->second.begin();
    for (; obs != obsPair->second.end(); obs++) {
        if ((*obs).observer_->AsObject() == observerNode.observer_->AsObject()) {
            break;
        }
    }
    if (obs == obsPair->second.end()) {
        TAG_LOGW(
            AAFwkTag::DBOBSMGR, "uri no obs:%{public}s", CommonUtils::Anonymous(uri.ToString()).c_str());
        return NO_OBS_FOR_URI;
    }
    obsPair->second.remove(*obs);
    if (obsPair->second.empty()) {
        observers_.erase(obsPair);
    }

    if (!HaveRegistered(observerNode.observer_)) {
        RemoveObsDeathRecipient(observerNode.observer_->AsObject());
    }

    return NO_ERROR;
}

int DataObsMgrInner::HandleNotifyChange(const Uri &uri, int32_t userId)
{
    std::list<struct ObserverNode> obsList;
    std::lock_guard<ffrt::mutex> lock(innerMutex_);
    {
        auto obsPair = observers_.find(uri.ToString());
        if (obsPair == observers_.end()) {
            TAG_LOGD(AAFwkTag::DBOBSMGR, "uri no obs:%{public}s",
                CommonUtils::Anonymous(uri.ToString()).c_str());
            return NO_OBS_FOR_URI;
        }
        obsList = obsPair->second;
    }

    for (auto &obs : obsList) {
        if (obs.observer_ == nullptr) {
            continue;
        }
        if (obs.userId_ != 0 && userId != 0 && obs.userId_ != userId) {
            TAG_LOGW(AAFwkTag::DBOBSMGR, "Not allow across user notify, %{public}d to %{public}d, %{public}s",
                userId, obs.userId_, CommonUtils::Anonymous(uri.ToString()).c_str());
            continue;
        }
        obs.observer_->OnChange();
    }

    TAG_LOGD(AAFwkTag::DBOBSMGR, "uri end:%{public}s,obs num:%{public}zu",
        CommonUtils::Anonymous(uri.ToString()).c_str(), obsList.size());
    return NO_ERROR;
}

void DataObsMgrInner::AddObsDeathRecipient(sptr<IDataAbilityObserver> dataObserver)
{
    if ((dataObserver == nullptr) || dataObserver->AsObject() == nullptr) {
        return;
    }

    auto it = obsRecipient_.find(dataObserver->AsObject());
    if (it != obsRecipient_.end()) {
        TAG_LOGW(AAFwkTag::DBOBSMGR, "called");
        return;
    } else {
        std::weak_ptr<DataObsMgrInner> thisWeakPtr(shared_from_this());
        sptr<IRemoteObject::DeathRecipient> deathRecipient =
            new DataObsCallbackRecipient([thisWeakPtr](const wptr<IRemoteObject> &remote) {
                auto dataObsMgrInner = thisWeakPtr.lock();
                if (dataObsMgrInner) {
                    dataObsMgrInner->OnCallBackDied(remote);
                }
            });
        if (!dataObserver->AsObject()->AddDeathRecipient(deathRecipient)) {
            TAG_LOGE(AAFwkTag::DBOBSMGR, "failed");
        }
        obsRecipient_.emplace(dataObserver->AsObject(), deathRecipient);
    }
}

void DataObsMgrInner::RemoveObsDeathRecipient(sptr<IRemoteObject> dataObserver)
{
    if (dataObserver == nullptr) {
        return;
    }

    auto it = obsRecipient_.find(dataObserver);
    if (it != obsRecipient_.end()) {
        it->first->RemoveDeathRecipient(it->second);
        obsRecipient_.erase(it);
        return;
    }
}

void DataObsMgrInner::OnCallBackDied(const wptr<IRemoteObject> &remote)
{
    auto dataObserver = remote.promote();
    if (dataObserver == nullptr) {
        return;
    }
    std::lock_guard<ffrt::mutex> lock(innerMutex_);

    if (dataObserver == nullptr) {
        TAG_LOGE(AAFwkTag::DBOBSMGR, "null dataObserver");
        return;
    }

    RemoveObs(dataObserver);
}

// remove dataObserver of all users
void DataObsMgrInner::RemoveObs(sptr<IRemoteObject> dataObserver)
{
    for (auto iter = observers_.begin(); iter != observers_.end();) {
        auto &obsList = iter->second;
        for (auto it = obsList.begin(); it != obsList.end(); it++) {
            if ((*it).observer_->AsObject() == dataObserver) {
                TAG_LOGD(AAFwkTag::DBOBSMGR, "erase");
                obsList.erase(it);
                break;
            }
        }
        if (obsList.size() == 0) {
            iter = observers_.erase(iter);
        } else {
            iter++;
        }
    }
    RemoveObsDeathRecipient(dataObserver);
}

bool DataObsMgrInner::HaveRegistered(sptr<IDataAbilityObserver> dataObserver)
{
    for (auto &[key, value] : observers_) {
        for (struct ObserverNode& node: value) {
            if (node.observer_ == dataObserver) {
                return true;
            }
        }
    }
    return false;
}
}  // namespace AAFwk
}  // namespace OHOS
