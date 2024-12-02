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

#include <thread>
#include "dataobs_mgr_client.h"

#include "common_utils.h"
#include "datashare_log.h"
#include "hilog_tag_wrapper.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace AAFwk {
std::mutex DataObsMgrClient::mutex_;
using namespace DataShare;

class DataObsMgrClient::SystemAbilityStatusChangeListener
    : public SystemAbilityStatusChangeStub {
public:
    SystemAbilityStatusChangeListener()
    {
    }
    ~SystemAbilityStatusChangeListener() = default;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override
    {
    }
};

void DataObsMgrClient::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string &deviceId)
{
    TAG_LOGI(AAFwkTag::DBOBSMGR, "called");
    if (systemAbilityId != DATAOBS_MGR_SERVICE_SA_ID) {
        return;
    }
    GetInstance()->ReRegister();
}

std::shared_ptr<DataObsMgrClient> DataObsMgrClient::GetInstance()
{
    static std::shared_ptr<DataObsMgrClient> proxy = std::make_shared<DataObsMgrClient>();
    return proxy;
}

DataObsMgrClient::DataObsMgrClient()
{
    callback_ = new SystemAbilityStatusChangeListener();
}

DataObsMgrClient::~DataObsMgrClient()
{}

/**
 * Registers an observer to DataObsMgr specified by the given Uri.
 *
 * @param uri, Indicates the path of the data to operate.
 * @param dataObserver, Indicates the IDataAbilityObserver object.
 *
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode DataObsMgrClient::RegisterObserver(const Uri &uri, sptr<IDataAbilityObserver> dataObserver)
{
    auto [errCode, dataObsManger] = GetObsMgr();
    if (errCode != SUCCESS) {
        LOG_ERROR("Failed to get ObsMgr, errCode: %{public}d.", errCode);
        return DATAOBS_SERVICE_NOT_CONNECTED;
    }
    auto status = dataObsManger->RegisterObserver(uri, dataObserver);
    if (status != NO_ERROR) {
        return status;
    }
    observers_.Compute(dataObserver, [&uri](const auto &key, auto &value) {
        value.emplace_back(uri);
        return true;
    });
    return status;
}

/**
 * Deregisters an observer used for DataObsMgr specified by the given Uri.
 *
 * @param uri, Indicates the path of the data to operate.
 * @param dataObserver, Indicates the IDataAbilityObserver object.
 *
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode DataObsMgrClient::UnregisterObserver(const Uri &uri, sptr<IDataAbilityObserver> dataObserver)
{
    auto [errCode, dataObsManger] = GetObsMgr();
    if (errCode != SUCCESS) {
        return DATAOBS_SERVICE_NOT_CONNECTED;
    }
    auto status = dataObsManger->UnregisterObserver(uri, dataObserver);
    if (status != NO_ERROR) {
        return status;
    }
    observers_.Compute(dataObserver, [&uri](const auto &key, auto &value) {
        value.remove_if([&uri](const auto &val) {
            return uri == val;
        });
        return !value.empty();
    });
    return status;
}

/**
 * Notifies the registered observers of a change to the data resource specified by Uri.
 *
 * @param uri, Indicates the path of the data to operate.
 *
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode DataObsMgrClient::NotifyChange(const Uri &uri)
{
    auto [errCode, dataObsManger] = GetObsMgr();
    if (errCode != SUCCESS) {
        return DATAOBS_SERVICE_NOT_CONNECTED;
    }
    return dataObsManger->NotifyChange(uri);
}

/**
 * Connect dataobs manager service.
 *
 * @return Returns SUCCESS on success, others on failure.
 */
__attribute__ ((no_sanitize("cfi"))) std::pair<Status, sptr<IDataObsMgr>> DataObsMgrClient::GetObsMgr()
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (dataObsManger_ != nullptr) {
        return std::make_pair(SUCCESS, dataObsManger_);
    }

    sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemManager == nullptr) {
        TAG_LOGE(AAFwkTag::DBOBSMGR, "registry failed");
        return std::make_pair(GET_DATAOBS_SERVICE_FAILED, nullptr);
    }

    auto remoteObject = systemManager->CheckSystemAbility(DATAOBS_MGR_SERVICE_SA_ID);
    if (remoteObject == nullptr) {
        TAG_LOGE(AAFwkTag::DBOBSMGR, "systemAbility failed");
        return std::make_pair(GET_DATAOBS_SERVICE_FAILED, nullptr);
    }

    dataObsManger_ = iface_cast<IDataObsMgr>(remoteObject);
    if (dataObsManger_ == nullptr) {
        TAG_LOGE(AAFwkTag::DBOBSMGR, "iDataObsMgr failed");
        return std::make_pair(GET_DATAOBS_SERVICE_FAILED, nullptr);
    }
    sptr<ServiceDeathRecipient> serviceDeathRecipient(new (std::nothrow) ServiceDeathRecipient(GetInstance()));
    dataObsManger_->AsObject()->AddDeathRecipient(serviceDeathRecipient);
    return std::make_pair(SUCCESS, dataObsManger_);
}

Status DataObsMgrClient::RegisterObserverExt(const Uri &uri, sptr<IDataAbilityObserver> dataObserver,
    bool isDescendants)
{
    auto [errCode, dataObsManger] = GetObsMgr();
    if (errCode != SUCCESS) {
        return DATAOBS_SERVICE_NOT_CONNECTED;
    }
    auto status = dataObsManger->RegisterObserverExt(uri, dataObserver, isDescendants);
    if (status != SUCCESS) {
        return status;
    }
    observerExts_.Compute(dataObserver, [&uri, isDescendants](const auto &key, auto &value) {
        value.emplace_back(uri, isDescendants);
        return true;
    });
    return status;
}

Status DataObsMgrClient::UnregisterObserverExt(const Uri &uri, sptr<IDataAbilityObserver> dataObserver)
{
    auto [errCode, dataObsManger] = GetObsMgr();
    if (errCode != SUCCESS) {
        return DATAOBS_SERVICE_NOT_CONNECTED;
    }
    auto status = dataObsManger->UnregisterObserverExt(uri, dataObserver);
    if (status != SUCCESS) {
        return status;
    }
    observerExts_.Compute(dataObserver, [&uri](const auto &key, auto &value) {
        value.remove_if([&uri](const auto &param) {
            return uri == param.uri;
        });
        return !value.empty();
    });
    return status;
}

Status DataObsMgrClient::UnregisterObserverExt(sptr<IDataAbilityObserver> dataObserver)
{
    auto [errCode, dataObsManger] = GetObsMgr();
    if (errCode != SUCCESS) {
        return DATAOBS_SERVICE_NOT_CONNECTED;
    }
    auto status = dataObsManger->UnregisterObserverExt(dataObserver);
    if (status != SUCCESS) {
        return status;
    }
    observerExts_.Erase(dataObserver);
    return status;
}

Status DataObsMgrClient::NotifyChangeExt(const ChangeInfo &changeInfo)
{
    auto [errCode, dataObsManger] = GetObsMgr();
    if (errCode != SUCCESS) {
        return DATAOBS_SERVICE_NOT_CONNECTED;
    }
    return dataObsManger->NotifyChangeExt(changeInfo);
}

void DataObsMgrClient::ResetService()
{
    std::lock_guard<std::mutex> lock(mutex_);
    dataObsManger_ = nullptr;
}

void DataObsMgrClient::OnRemoteDied()
{
    std::this_thread::sleep_for(std::chrono::seconds(RESUB_INTERVAL));
    ResetService();
    auto [errCode, dataObsManger] = GetObsMgr();
    if (errCode != SUCCESS) {
        sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemManager == nullptr) {
            TAG_LOGE(AAFwkTag::DBOBSMGR, "null systemmgr");
            return;
        }
        systemManager->SubscribeSystemAbility(DATAOBS_MGR_SERVICE_SA_ID, callback_);
        return;
    }
    ReRegister();
}

void DataObsMgrClient::ReRegister()
{
    decltype(observers_) observers(std::move(observers_));
    observers_.Clear();
    observers.ForEach([this](const auto &key, const auto &value) {
        for (const auto &uri : value) {
            auto ret = RegisterObserver(uri, key);
            if (ret != SUCCESS) {
                LOG_ERROR("RegisterObserver failed, uri:%{public}s, ret:%{public}d",
                    CommonUtils::Anonymous(uri.ToString()).c_str(), ret);
            }
        }
        return false;
    });

    decltype(observerExts_) observerExts(std::move(observerExts_));
    observerExts_.Clear();
    observerExts.ForEach([this](const auto &key, const auto &value) {
        for (const auto &param : value) {
            auto ret = RegisterObserverExt(param.uri, key, param.isDescendants);
            if (ret != SUCCESS) {
                LOG_ERROR(
                    "RegisterObserverExt failed, param.uri:%{public}s, ret:%{public}d, param.isDescendants:%{public}d",
                    CommonUtils::Anonymous(param.uri.ToString()).c_str(), ret, param.isDescendants
                );
            }
        }
        return false;
    });
}
}  // namespace AAFwk
}  // namespace OHOS
