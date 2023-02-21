/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_DATAOBS_MGR_INNER_EXT_H
#define OHOS_ABILITY_RUNTIME_DATAOBS_MGR_INNER_EXT_H

#include <atomic>
#include <list>
#include <string>
#include <memory>
#include <map>
#include <mutex>

#include "data_ability_observer_interface.h"
#include "dataobs_mgr_errors.h"
#include "event_handler.h"
#include "iremote_object.h"
#include "refbase.h"

namespace OHOS {
namespace AAFwk {
using EventHandler = OHOS::AppExecFwk::EventHandler;
class DataObsMgrInnerExt : public std::enable_shared_from_this<DataObsMgrInnerExt> {
public:

    DataObsMgrInnerExt();
    virtual ~DataObsMgrInnerExt();

    Status HandleRegisterObserver(Uri &uri, const sptr<IDataAbilityObserver> &dataObserver, bool isDescendants = false);
    Status HandleUnregisterObserver(Uri &uri, const sptr<IDataAbilityObserver> &dataObserver);
    Status HandleUnregisterObserver(const sptr<IDataAbilityObserver> &dataObserver);
    Status HandleNotifyChange(const std::list<Uri> &uris);
    void OnCallBackDied(const wptr<IRemoteObject> &remote);

private:
    struct Entry {
        Entry(const sptr<IDataAbilityObserver> &obs, bool fuzz) : observer(obs), fuzzySub(fuzz) {}
        sptr<IDataAbilityObserver> observer;
        bool fuzzySub;
    };

    using ObsMapType = std::map<sptr<IDataAbilityObserver>, std::list<Uri>>;
    using EntryListType = std::list<std::shared_ptr<Entry>>;
    using DeathRecipientRef = std::pair<sptr<IRemoteObject::DeathRecipient>, uint32_t>;

    class Node {
    public:
        Node(const std::string &name);
        bool GetObs(const std::vector<std::string> &path, uint32_t &index, ObsMapType &obsMap, Uri &uri);
        bool AddObserver(const std::vector<std::string> &path, uint32_t &index,
            const sptr<IDataAbilityObserver> &dataObserver, bool isFuzzySub = false);
        bool RemoveObserver(const std::vector<std::string> &path, uint32_t &index,
            const sptr<IDataAbilityObserver> &dataObserver, uint32_t &num);
        inline bool RemoveObserver(const sptr<IDataAbilityObserver> &dataObserver, uint32_t &num);
        bool RemoveObserver(const sptr<IRemoteObject> &dataObserver, uint32_t &num);
    private:
        std::string name_;
        EntryListType entrys_;
        std::map<std::string, std::shared_ptr<Node>> childrens_;
    };

    bool AddObsDeathRecipient(const sptr<IRemoteObject> &dataObserver, uint32_t num = 1);
    void RemoveObsDeathRecipient(const sptr<IRemoteObject> &dataObserver, uint32_t num, bool isForce = false);
    static std::string Anonymous(const std::string &name);

    static constexpr uint32_t obs_max_ = 50;

    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<Node>> nodes_;
    std::map<sptr<IRemoteObject>, DeathRecipientRef> obsRecipientMap_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_DATAOBS_MGR_INNER_H
