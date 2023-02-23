/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "hilog_wrapper.h"

namespace OHOS {
namespace AAFwk {

DataObsMgrInner::DataObsMgrInner() {}

DataObsMgrInner::~DataObsMgrInner() {}

int DataObsMgrInner::HandleRegisterObserver(const Uri &uri, const sptr<IDataAbilityObserver> &dataObserver)
{
    std::lock_guard<std::mutex> lock_l(innerMutex_);

    auto [obsPair, flag] =obsmap_.try_emplace(uri.ToString(), std::list<sptr<IDataAbilityObserver>>());
    if (!flag && obsPair->second.size() > obs_max_) {
        HILOG_ERROR("The number of subscribers for this uri : %{public}s has reached the upper limit.",
            Anonymous(uri.ToString()).c_str());
        return DATAOBS_SERVICE_OBS_LIMMIT;
    }

    for (auto obs = obsPair->second.begin(); obs != obsPair->second.end(); obs++) {
        if ((*obs)->AsObject() == dataObserver->AsObject()) {
            HILOG_ERROR("the obs has registered on this uri : %{public}s", Anonymous(uri.ToString()).c_str());
            return OBS_EXIST;
        }
    }

    obsPair->second.push_back(dataObserver);

    AddObsDeathRecipient(dataObserver);

    return NO_ERROR;
}

int DataObsMgrInner::HandleUnregisterObserver(const Uri &uri, const sptr<IDataAbilityObserver> &dataObserver)
{
    std::lock_guard<std::mutex> lock_l(innerMutex_);

    auto obsPair = obsmap_.find(uri.ToString());
    if (obsPair == obsmap_.end()) {
        HILOG_WARN("no obs on this uri : %{public}s", Anonymous(uri.ToString()).c_str());
        return NO_OBS_FOR_URI;
    }

    HILOG_DEBUG("obs num is %{public}zu on this uri : %{public}s", obsPair->second.size(),
        Anonymous(uri.ToString()).c_str());
    auto obs = obsPair->second.begin();
    for (; obs != obsPair->second.end(); obs++) {
        if ((*obs)->AsObject() == dataObserver->AsObject()) {
            break;
        }
    }
    if (obs == obsPair->second.end()) {
        HILOG_WARN("no obs on this uri : %{public}s", Anonymous(uri.ToString()).c_str());
        return NO_OBS_FOR_URI;
    }
    obsPair->second.remove(*obs);
    if (obsPair->second.empty()) {
        obsmap_.erase(obsPair);
    }

    if (!ObsExistInMap(dataObserver)) {
        RemoveObsDeathRecipient(dataObserver->AsObject());
    }

    return NO_ERROR;
}

int DataObsMgrInner::HandleNotifyChange(const Uri &uri)
{
    std::list<sptr<IDataAbilityObserver>> obsList;
    std::lock_guard<std::mutex> lock_l(innerMutex_);
    {
        auto obsPair = obsmap_.find(uri.ToString());
        if (obsPair == obsmap_.end()) {
            HILOG_WARN("there is no obs on the uri : %{public}s", Anonymous(uri.ToString()).c_str());
            return NO_OBS_FOR_URI;
        }
        obsList = obsPair->second;
    }

    for (auto &obs : obsList) {
        if (obs != nullptr) {
            obs->OnChange();
        }
    }

    HILOG_DEBUG("called end on the uri : %{public}s,obs num: %{public}zu", Anonymous(uri.ToString()).c_str(),
        obsList.size());
    return NO_ERROR;
}

void DataObsMgrInner::AddObsDeathRecipient(const sptr<IDataAbilityObserver> &dataObserver)
{
    if ((dataObserver == nullptr) || dataObserver->AsObject() == nullptr) {
        return;
    }

    auto it = recipientMap_.find(dataObserver->AsObject());
    if (it != recipientMap_.end()) {
        HILOG_WARN("this death recipient has been added.");
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
        dataObserver->AsObject()->AddDeathRecipient(deathRecipient);
        recipientMap_.emplace(dataObserver->AsObject(), deathRecipient);
    }
}

void DataObsMgrInner::RemoveObsDeathRecipient(const sptr<IRemoteObject> &dataObserver)
{
    if (dataObserver == nullptr) {
        return;
    }

    auto it = recipientMap_.find(dataObserver);
    if (it != recipientMap_.end()) {
        it->first->RemoveDeathRecipient(it->second);
        recipientMap_.erase(it);
        return;
    }
}

void DataObsMgrInner::OnCallBackDied(const wptr<IRemoteObject> &remote)
{
    auto dataObserver = remote.promote();
    if (dataObserver == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock_l(innerMutex_);

    if (dataObserver == nullptr) {
        HILOG_ERROR("dataObserver is nullptr.");
        return;
    }

    RemoveObsFromMap(dataObserver);
}

void DataObsMgrInner::RemoveObsFromMap(const sptr<IRemoteObject> &dataObserver)
{
    for (auto iter = obsmap_.begin(); iter != obsmap_.end();) {
        auto &obsList = iter->second;
        for (auto it = obsList.begin(); it != obsList.end(); it++) {
            if ((*it)->AsObject() == dataObserver) {
                HILOG_DEBUG("Erase an observer form list.");
                obsList.erase(it);
                break;
            }
        }
        if (obsList.size() == 0) {
            obsmap_.erase(iter++);
        } else {
            iter++;
        }
    }
    RemoveObsDeathRecipient(dataObserver);
}

bool DataObsMgrInner::ObsExistInMap(const sptr<IDataAbilityObserver> &dataObserver)
{
    for (auto &[key,value] : obsmap_) {
        auto obs = std::find(value.begin(), value.end(), dataObserver);
        if (obs != value.end()) {
            return true;
        }
    }
    return false;
}

std::string DataObsMgrInner::Anonymous(const std::string &name)
{
    static constexpr uint32_t HEAD_SIZE = 10;
    static constexpr int32_t END_SIZE = 5;
    static constexpr int32_t MIN_SIZE = HEAD_SIZE + END_SIZE + 3;
    static constexpr const char *REPLACE_CHAIN = "***";
    static constexpr const char *DEFAULT_ANONYMOUS = "******";
    if (name.length() <= HEAD_SIZE) {
        return DEFAULT_ANONYMOUS;
    }

    if (name.length() < MIN_SIZE) {
        return (name.substr(0, HEAD_SIZE) + REPLACE_CHAIN);
    }

    return (name.substr(0, HEAD_SIZE) + REPLACE_CHAIN + name.substr(name.length() - END_SIZE, END_SIZE));
}
}  // namespace AAFwk
}  // namespace OHOS
