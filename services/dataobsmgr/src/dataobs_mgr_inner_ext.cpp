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
#include "dataobs_mgr_inner_ext.h"

#include "data_ability_observer_stub.h"
#include "dataobs_mgr_errors.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AAFwk {

DataObsMgrInnerExt::DataObsMgrInnerExt() {}

DataObsMgrInnerExt::~DataObsMgrInnerExt() {}

Status DataObsMgrInnerExt::HandleRegisterObserver(Uri &uri, const sptr<IDataAbilityObserver> &dataObserver,
    bool isDescendants)
{
    std::lock_guard<std::mutex> node_lock(mutex_);
    if (!AddObsDeathRecipient(dataObserver->AsObject())) {
        return ADD_OBS_DEATH_RECIPIENT_FAILED;
    }
    auto node = nodes_.emplace(uri.GetScheme(), std::make_shared<Node>(uri.GetScheme())).first;
    std::vector<std::string> path = { uri.GetAuthority() };
    uri.GetPathSegments(path);
    uint32_t index = 0;
    if (!node->second->AddObserver(path, index, dataObserver, isDescendants)) {
        HILOG_ERROR("The number of subscribers for this uri : %{public}s has reached the upper limit.",
            Anonymous(uri.ToString()).c_str());
        return DATAOBS_SERVICE_OBS_LIMMIT;
    }
    return SUCCESS;
}

Status DataObsMgrInnerExt::HandleUnregisterObserver(Uri &uri, const sptr<IDataAbilityObserver> &dataObserver)
{
    uint32_t index = 0;
    uint32_t rmNum = 0;
    std::lock_guard<std::mutex> node_lock(mutex_);
    auto node = nodes_.find(uri.GetScheme());
    std::vector<std::string> path = { uri.GetAuthority() };
    uri.GetPathSegments(path);
    if (node == nodes_.end()) {
        HILOG_WARN("No observers for the uri: %{public}s.", Anonymous(uri.ToString()).c_str());
        return NO_OBS_FOR_URI;
    }
    if (node->second->RemoveObserver(path, index, dataObserver, rmNum)) {
        nodes_.erase(node);
    }
    RemoveObsDeathRecipient(dataObserver->AsObject(), rmNum);
    return (rmNum == 0) ? NO_OBS_FOR_URI : SUCCESS;
}

Status DataObsMgrInnerExt::HandleUnregisterObserver(const sptr<IDataAbilityObserver> &dataObserver)
{
    uint32_t rmNum = 0;
    std::lock_guard<std::mutex> node_lock(mutex_);
    for (auto node = nodes_.begin(); node != nodes_.end();) {
        if (node->second->RemoveObserver(dataObserver, rmNum)) {
            nodes_.erase(node++);
        } else {
            node++;
        }
    }
    RemoveObsDeathRecipient(dataObserver->AsObject(), rmNum, true);
    return SUCCESS;
}

Status DataObsMgrInnerExt::HandleNotifyChange(const std::list<Uri> &uris)
{
    ObsMapType obsMap;
    std::vector<std::string> path;
    uint32_t index = 0;
    std::lock_guard<std::mutex> node_lock(mutex_);
    for (auto uri : uris) {
        auto node = nodes_.find(uri.GetScheme());
        if (node != nodes_.end()) {
            path.clear();
            path.emplace_back(uri.GetAuthority());
            uri.GetPathSegments(path);
            index = 0;
            node->second->GetObs(path, index, obsMap, uri);
        }
    }
    if (obsMap.empty()) {
        return NO_OBS_FOR_URI;
    }
    for (const auto &[obs, value] : obsMap) {
        if (obs != nullptr && !value.empty()) {
            obs->OnChangeExt(value);
        }
    }

    return SUCCESS;
}

bool DataObsMgrInnerExt::AddObsDeathRecipient(const sptr<IRemoteObject> &dataObserver, uint32_t num)
{
    if (dataObserver == nullptr || num == 0) {
        return false;
    }
    auto it = obsRecipientMap_.find(dataObserver);
    if (it != obsRecipientMap_.end()) {
        if (std::numeric_limits<uint32_t>::max() - num < it->second.second) {
            HILOG_ERROR("the num of observer reach max limit");
            return false;
        }
        it->second.second += num;
        HILOG_DEBUG("this Observer has been added, num:%{public}d, sum:%{public}d", num, it->second.second);
    } else {
        std::weak_ptr<DataObsMgrInnerExt> thisWeakPtr(shared_from_this());
        sptr<IRemoteObject::DeathRecipient> deathRecipient =
            new DataObsCallbackRecipient([thisWeakPtr](const wptr<IRemoteObject> &remote) {
                auto DataObsMgrInnerExt = thisWeakPtr.lock();
                if (DataObsMgrInnerExt) {
                    DataObsMgrInnerExt->OnCallBackDied(remote);
                }
            });
        dataObserver->AddDeathRecipient(deathRecipient);
        obsRecipientMap_.emplace(dataObserver,
            std::pair<sptr<IRemoteObject::DeathRecipient>, uint32_t>(deathRecipient, num));
    }
    return true;
}

void DataObsMgrInnerExt::RemoveObsDeathRecipient(const sptr<IRemoteObject> &dataObserver, uint32_t num, bool isForce)
{
    if (dataObserver == nullptr || (!isForce && num == 0)) {
        return;
    }
    auto it = obsRecipientMap_.find(dataObserver);
    if (it == obsRecipientMap_.end()) {
        return;
    }

    if (isForce || it->second.second <= num) {
        dataObserver->RemoveDeathRecipient(it->second.first);
        obsRecipientMap_.erase(it);
        return;
    }

    it->second.second -= num;
}

void DataObsMgrInnerExt::OnCallBackDied(const wptr<IRemoteObject> &remote)
{
    auto dataObserver = remote.promote();
    if (dataObserver == nullptr) {
        return;
    }
    uint32_t rmNum = 0;
    std::lock_guard<std::mutex> node_lock(mutex_);
    for (auto node = nodes_.begin(); node != nodes_.end();) {
        if (node->second->RemoveObserver(dataObserver, rmNum)) {
            nodes_.erase(node++);
        } else {
            node++;
        }
    }
    RemoveObsDeathRecipient(dataObserver, rmNum, true);
}

DataObsMgrInnerExt::Node::Node(const std::string &name) : name_(name) {}

bool DataObsMgrInnerExt::Node::GetObs(const std::vector<std::string> &path, uint32_t &index,
    DataObsMgrInnerExt::ObsMapType &obsMap, Uri &uri)
{
    if (path.size() == index) {
        for (auto entry : entrys_) {
            obsMap.try_emplace(entry->observer, std::list<Uri>()).first->second.push_back(uri);
        }
        return !entrys_.empty();
    }

    bool hasObs = false;
    for (auto entry : entrys_) {
        if (entry->fuzzySub) {
            hasObs = true;
            obsMap.try_emplace(entry->observer, std::list<Uri>()).first->second.push_back(uri);
        }
    }
    auto it = childrens_.find(path[index]);
    if (it == childrens_.end()) {
        return hasObs;
    }

    return it->second->GetObs(path, ++index, obsMap, uri);
}

bool DataObsMgrInnerExt::Node::AddObserver(const std::vector<std::string> &path, uint32_t &index,
    const sptr<IDataAbilityObserver> &dataObserver, bool fuzzySub)
{
    if (path.size() == index) {
        if (entrys_.size() >= obs_max_) {
            return false;
        }
        entrys_.emplace_back(std::make_shared<Entry>(dataObserver, fuzzySub));
        return true;
    }
    auto it = childrens_.try_emplace(path[index], std::make_shared<Node>(path[index])).first;
    return it->second->AddObserver(path, ++index, dataObserver, fuzzySub);
}

bool DataObsMgrInnerExt::Node::RemoveObserver(const std::vector<std::string> &path, uint32_t &index,
    const sptr<IDataAbilityObserver> &dataObserver, uint32_t &num)
{
    if (index == path.size()) {
        entrys_.remove_if([dataObserver, &num](auto entry) {
            if (entry->observer->AsObject() != dataObserver->AsObject()) {
                return false;
            }
            num++;
            return true;
        });
        return entrys_.empty() && childrens_.empty();
    }
    auto child = childrens_.find(path[index]);
    if (child != childrens_.end() && child->second->RemoveObserver(path, ++index, dataObserver, num)) {
        childrens_.erase(child);
    }
    return entrys_.empty() && childrens_.empty();
}

bool DataObsMgrInnerExt::Node::RemoveObserver(const sptr<IRemoteObject> &dataObserver, uint32_t &num)
{
    for (auto child = childrens_.begin(); child != childrens_.end();) {
        if (child->second->RemoveObserver(dataObserver, num)) {
            childrens_.erase(child++);
        } else {
            child++;
        }
    }
    entrys_.remove_if([dataObserver, &num](auto entry) {
        if (entry->observer->AsObject() != dataObserver) {
            return false;
        }
        num++;
        return true;
    });
    return entrys_.empty() && childrens_.empty();
}

inline bool DataObsMgrInnerExt::Node::RemoveObserver(const sptr<IDataAbilityObserver> &dataObserver, uint32_t &num)
{
    auto obs = dataObserver->AsObject();
    return obs != nullptr && RemoveObserver(obs, num);
}

std::string DataObsMgrInnerExt::Anonymous(const std::string &name)
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

} // namespace AAFwk
} // namespace OHOS
