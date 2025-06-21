/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "ability_keep_alive_data_manager.h"

#include <unistd.h>

#include "cJSON.h"
#include "hilog_tag_wrapper.h"
#include "json_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr int32_t CHECK_INTERVAL = 100000; // 100ms
constexpr int32_t MAX_TIMES = 5;           // 5 * 100ms = 500ms
constexpr int32_t U1_USER_ID = 1;
constexpr const char *KEEP_ALIVE_STORAGE_DIR = "/data/service/el1/public/database/keep_alive_service";
const std::string JSON_KEY_BUNDLE_NAME = "bundleName";
const std::string JSON_KEY_USERID = "userId";
const std::string JSON_KEY_APP_TYPE = "appType";
const std::string JSON_KEY_SETTER = "setter";
const std::string JSON_KEY_SETTERID = "setterId";
const std::string JSON_KEY_POLICY = "policy";
} // namespace
const DistributedKv::AppId AbilityKeepAliveDataManager::APP_ID = { "keep_alive_storage" };
const DistributedKv::StoreId AbilityKeepAliveDataManager::STORE_ID = { "keep_alive_infos" };

AbilityKeepAliveDataManager &AbilityKeepAliveDataManager::GetInstance()
{
    static AbilityKeepAliveDataManager instance;
    return instance;
}

AbilityKeepAliveDataManager::AbilityKeepAliveDataManager() {}

AbilityKeepAliveDataManager::~AbilityKeepAliveDataManager()
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    if (kvStorePtr_ != nullptr) {
        dataManager_.CloseKvStore(APP_ID, kvStorePtr_);
    }
}

DistributedKv::Status AbilityKeepAliveDataManager::RestoreKvStore(DistributedKv::Status status)
{
    if (status == DistributedKv::Status::DATA_CORRUPTED) {
        DistributedKv::Options options = {
            .createIfMissing = true,
            .encrypt = false,
            .autoSync = false,
            .syncable = false,
            .securityLevel = DistributedKv::SecurityLevel::S2,
            .area = DistributedKv::EL1,
            .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION,
            .baseDir = KEEP_ALIVE_STORAGE_DIR,
        };
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "corrupted, deleting db");
        dataManager_.DeleteKvStore(APP_ID, STORE_ID, options.baseDir);
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "deleted corrupted db, recreating db");
        status = dataManager_.GetSingleKvStore(options, APP_ID, STORE_ID, kvStorePtr_);
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "recreate db result:%{public}d", status);
    }
    return status;
}

DistributedKv::Status AbilityKeepAliveDataManager::GetKvStore()
{
    DistributedKv::Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .syncable = false,
        .securityLevel = DistributedKv::SecurityLevel::S2,
        .area = DistributedKv::EL1,
        .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION,
        .baseDir = KEEP_ALIVE_STORAGE_DIR,
    };

    DistributedKv::Status status = dataManager_.GetSingleKvStore(options, APP_ID, STORE_ID, kvStorePtr_);
    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "Error: %{public}d", status);
        status = RestoreKvStore(status);
        return status;
    }

    TAG_LOGD(AAFwkTag::KEEP_ALIVE, "Get kvStore success");
    return status;
}

bool AbilityKeepAliveDataManager::CheckKvStore()
{
    if (kvStorePtr_ != nullptr) {
        return true;
    }
    int32_t tryTimes = MAX_TIMES;
    while (tryTimes > 0) {
        DistributedKv::Status status = GetKvStore();
        if (status == DistributedKv::Status::SUCCESS && kvStorePtr_ != nullptr) {
            return true;
        }
        TAG_LOGD(AAFwkTag::KEEP_ALIVE, "Try times: %{public}d", tryTimes);
        usleep(CHECK_INTERVAL);
        tryTimes--;
    }
    return kvStorePtr_ != nullptr;
}

int32_t AbilityKeepAliveDataManager::InsertKeepAliveData(const KeepAliveInfo &info)
{
    if (info.bundleName.empty() || info.userId < 0
        || info.appType == KeepAliveAppType::UNSPECIFIED
        || info.setter == KeepAliveSetter::UNSPECIFIED) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "Invalid value");
        return ERR_INVALID_VALUE;
    }

    TAG_LOGD(AAFwkTag::KEEP_ALIVE,
        "bundleName: %{public}s, userId: %{public}d, appType: %{public}d, setter: %{public}d",
        info.bundleName.c_str(), info.userId, info.appType, info.setter);
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            TAG_LOGE(AAFwkTag::KEEP_ALIVE, "null kvStore");
            return ERR_NO_INIT;
        }
    }

    DistributedKv::Key key = ConvertKeepAliveDataToKey(info);
    DistributedKv::Value value = ConvertKeepAliveStatusToValue(info);
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->Put(key, value);
    }

    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "kvStore insert error: %{public}d", status);
        {
            std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
            status = RestoreKvStore(status);
        }
        return ERR_INVALID_OPERATION;
    }
    return ERR_OK;
}

int32_t AbilityKeepAliveDataManager::DeleteKeepAliveData(const KeepAliveInfo &info)
{
    if (info.userId < 0) {
        TAG_LOGW(AAFwkTag::KEEP_ALIVE, "Invalid value");
        return ERR_INVALID_VALUE;
    }

    TAG_LOGD(AAFwkTag::KEEP_ALIVE,
        "bundleName: %{public}s, userId: %{public}d, appType: %{public}d, setter: %{public}d",
        info.bundleName.c_str(), info.userId, info.appType, info.setter);
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            TAG_LOGE(AAFwkTag::KEEP_ALIVE, "null kvStore");
            return ERR_NO_INIT;
        }
    }

    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Status status = DistributedKv::Status::SUCCESS;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->GetEntries(nullptr, allEntries);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "GetEntries error: %{public}d", status);
        {
            std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
            status = RestoreKvStore(status);
        }
        return ERR_INVALID_OPERATION;
    }

    for (const auto &item : allEntries) {
        if (IsEqual(item.key, info)) {
            {
                std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
                status = kvStorePtr_->Delete(item.key);
            }
            if (status != DistributedKv::Status::SUCCESS) {
                TAG_LOGE(AAFwkTag::KEEP_ALIVE, "kvStore delete error: %{public}d", status);
                {
                    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
                    status = RestoreKvStore(status);
                }
                return ERR_INVALID_OPERATION;
            }
        }
    }

    return ERR_OK;
}

KeepAliveStatus AbilityKeepAliveDataManager::QueryKeepAliveData(const KeepAliveInfo &info)
{
    KeepAliveStatus kaStatus;
    if (info.bundleName.empty() || info.userId < 0) {
        TAG_LOGW(AAFwkTag::KEEP_ALIVE, "Invalid value");
        kaStatus.code = ERR_INVALID_VALUE;
        return kaStatus;
    }

    TAG_LOGD(AAFwkTag::KEEP_ALIVE,
        "bundleName: %{public}s, userId: %{public}d", info.bundleName.c_str(), info.userId);
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            TAG_LOGE(AAFwkTag::KEEP_ALIVE, "null kvStore");
            kaStatus.code = ERR_NO_INIT;
            return kaStatus;
        }
    }

    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Status status = DistributedKv::Status::SUCCESS;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->GetEntries(nullptr, allEntries);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "GetEntries error: %{public}d", status);
        {
            std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
            status = RestoreKvStore(status);
        }
        kaStatus.code = ERR_INVALID_OPERATION;
        return kaStatus;
    }

    kaStatus.code = ERR_NAME_NOT_FOUND;
    for (const auto &item : allEntries) {
        if (IsEqual(item.key, info)) {
            ConvertKeepAliveStatusFromValue(item.value, kaStatus);
            kaStatus.code = ERR_OK;
            break;
        }
    }

    return kaStatus;
}

int32_t AbilityKeepAliveDataManager::QueryKeepAliveApplications(
    const KeepAliveInfo &queryParam, std::vector<KeepAliveInfo> &infoList)
{
    if (queryParam.userId < 0) {
        TAG_LOGW(AAFwkTag::KEEP_ALIVE, "Invalid value");
        return ERR_INVALID_VALUE;
    }

    TAG_LOGD(AAFwkTag::KEEP_ALIVE,
        "bundleName: %{public}s, userId: %{public}d, appType: %{public}d, setter: %{public}d",
        queryParam.bundleName.c_str(), queryParam.userId, queryParam.appType, queryParam.setter);
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            TAG_LOGE(AAFwkTag::KEEP_ALIVE, "null kvStore");
            return ERR_NO_INIT;
        }
    }

    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Status status = DistributedKv::Status::SUCCESS;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->GetEntries(nullptr, allEntries);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "GetEntries: %{public}d", status);
        {
            std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
            status = RestoreKvStore(status);
        }
        return ERR_INVALID_OPERATION;
    }

    for (const auto &item : allEntries) {
        if (!IsEqual(item.key, queryParam)) {
            continue;
        }
        infoList.emplace_back(ConvertKeepAliveInfoFromKey(item.key));
    }
    TAG_LOGD(AAFwkTag::KEEP_ALIVE, "InfoList.size: %{public}zu", infoList.size());
    return ERR_OK;
}

int32_t AbilityKeepAliveDataManager::DeleteKeepAliveDataWithSetterId(const KeepAliveInfo &info)
{
    TAG_LOGD(AAFwkTag::KEEP_ALIVE, "setterId: %{public}d", info.setterId);
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            TAG_LOGE(AAFwkTag::KEEP_ALIVE, "null kvStore");
            return ERR_NO_INIT;
        }
    }

    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Status status = DistributedKv::Status::SUCCESS;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->GetEntries(nullptr, allEntries);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "GetEntries error: %{public}d", status);
        {
            std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
            status = RestoreKvStore(status);
        }
        return ERR_INVALID_OPERATION;
    }

    for (const auto &item : allEntries) {
        if (IsEqualSetterId(item.key, info)) {
            {
                std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
                status = kvStorePtr_->Delete(item.key);
            }
            if (status != DistributedKv::Status::SUCCESS) {
                TAG_LOGE(AAFwkTag::KEEP_ALIVE, "kvStore delete error: %{public}d", status);
                {
                    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
                    status = RestoreKvStore(status);
                }
                return ERR_INVALID_OPERATION;
            }
        }
    }

    return ERR_OK;
}


DistributedKv::Value AbilityKeepAliveDataManager::ConvertKeepAliveStatusToValue(const KeepAliveInfo &info)
{
    cJSON *jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "create jsonObject failed");
        return DistributedKv::Value();
    }
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_SETTER.c_str(), static_cast<double>(info.setter));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_SETTERID.c_str(), static_cast<double>(info.setterId));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_POLICY.c_str(), static_cast<double>(info.policy));
    std::string jsonStr = AAFwk::JsonUtils::GetInstance().ToString(jsonObject);
    cJSON_Delete(jsonObject);
    DistributedKv::Value value(jsonStr);
    TAG_LOGD(AAFwkTag::KEEP_ALIVE, "value: %{public}s", value.ToString().c_str());
    return value;
}

void AbilityKeepAliveDataManager::ConvertKeepAliveStatusFromValue(const DistributedKv::Value &value,
    KeepAliveStatus &status)
{
    cJSON *jsonObject = cJSON_Parse(value.ToString().c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "parse jsonObject failed");
        return;
    }
    cJSON *setterItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_SETTER.c_str());
    if (setterItem != nullptr && cJSON_IsNumber(setterItem)) {
        status.setter = static_cast<KeepAliveSetter>(setterItem->valuedouble);
    }
    cJSON *setterIdItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_SETTERID.c_str());
    if (setterIdItem != nullptr && cJSON_IsNumber(setterIdItem)) {
        status.setterId = static_cast<int32_t>(setterIdItem->valuedouble);
    }
    cJSON *policyItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_POLICY.c_str());
    if (policyItem != nullptr && cJSON_IsNumber(policyItem)) {
        status.policy = static_cast<KeepAlivePolicy>(policyItem->valuedouble);
    }
    cJSON_Delete(jsonObject);
}

DistributedKv::Key AbilityKeepAliveDataManager::ConvertKeepAliveDataToKey(const KeepAliveInfo &info)
{
    cJSON *jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "create jsonObject failed");
        return DistributedKv::Key();
    }
    cJSON_AddStringToObject(jsonObject, JSON_KEY_BUNDLE_NAME.c_str(), info.bundleName.c_str());
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_USERID.c_str(), static_cast<double>(info.userId));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_APP_TYPE.c_str(), static_cast<double>(info.appType));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_SETTER.c_str(), static_cast<double>(info.setter));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_SETTERID.c_str(), static_cast<double>(info.setterId));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_POLICY.c_str(), static_cast<double>(info.policy));
    std::string jsonStr = AAFwk::JsonUtils::GetInstance().ToString(jsonObject);
    cJSON_Delete(jsonObject);
    DistributedKv::Key key(jsonStr);
    TAG_LOGD(AAFwkTag::KEEP_ALIVE, "key: %{public}s", key.ToString().c_str());
    return key;
}

KeepAliveInfo AbilityKeepAliveDataManager::ConvertKeepAliveInfoFromKey(const DistributedKv::Key &key)
{
    KeepAliveInfo info;
    cJSON *jsonObject = cJSON_Parse(key.ToString().c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "parse jsonObject failed");
        return info;
    }
    cJSON *bundleNameItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_BUNDLE_NAME.c_str());
    if (bundleNameItem != nullptr && cJSON_IsString(bundleNameItem)) {
        info.bundleName = bundleNameItem->valuestring;
    }
    cJSON *userIdItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_USERID.c_str());
    if (userIdItem != nullptr && cJSON_IsNumber(userIdItem)) {
        info.userId = static_cast<int32_t>(userIdItem->valuedouble);
    }
    cJSON *appTypeItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_APP_TYPE.c_str());
    if (appTypeItem != nullptr && cJSON_IsNumber(appTypeItem)) {
        info.appType = static_cast<KeepAliveAppType>(static_cast<int32_t>(appTypeItem->valuedouble));
    }
    cJSON *setterItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_SETTER.c_str());
    if (setterItem != nullptr && cJSON_IsNumber(setterItem)) {
        info.setter = static_cast<KeepAliveSetter>(static_cast<int32_t>(setterItem->valuedouble));
    }
    cJSON *setterIdItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_SETTERID.c_str());
    if (setterIdItem != nullptr && cJSON_IsNumber(setterIdItem)) {
        info.setterId = static_cast<int32_t>(setterIdItem->valuedouble);
    }
    cJSON *policyItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_POLICY.c_str());
    if (policyItem != nullptr && cJSON_IsNumber(policyItem)) {
        info.policy = static_cast<KeepAlivePolicy>(policyItem->valuedouble);
    }
    cJSON_Delete(jsonObject);
    return info;
}

bool AbilityKeepAliveDataManager::IsEqualSetterId(const DistributedKv::Key &key, const KeepAliveInfo &info)
{
    cJSON *jsonObject = cJSON_Parse(key.ToString().c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "parse jsonObject fail");
        return false;
    }

    if (!AAFwk::JsonUtils::GetInstance().IsEqual(jsonObject, JSON_KEY_USERID, U1_USER_ID)) {
        cJSON_Delete(jsonObject);
        return false;
    }

    if (info.setterId != -1 &&
        !AAFwk::JsonUtils::GetInstance().IsEqual(jsonObject, JSON_KEY_SETTERID, info.setterId)) {
        cJSON_Delete(jsonObject);
        return false;
    }

    cJSON_Delete(jsonObject);
    return true;
}

bool AbilityKeepAliveDataManager::IsEqual(const DistributedKv::Key &key, const KeepAliveInfo &info)
{
    cJSON *jsonObject = cJSON_Parse(key.ToString().c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "parse jsonObject failed");
        return false;
    }
    if (!AAFwk::JsonUtils::GetInstance().IsEqual(jsonObject, JSON_KEY_USERID, info.userId)) {
        cJSON_Delete(jsonObject);
        return false;
    }
    if (!info.bundleName.empty() &&
        !AAFwk::JsonUtils::GetInstance().IsEqual(jsonObject, JSON_KEY_BUNDLE_NAME, info.bundleName)) {
        cJSON_Delete(jsonObject);
        return false;
    }
    if (info.appType != KeepAliveAppType::UNSPECIFIED &&
        !AAFwk::JsonUtils::GetInstance().IsEqual(jsonObject, JSON_KEY_APP_TYPE, static_cast<int32_t>(info.appType))) {
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_Delete(jsonObject);
    return true;
}
} // namespace AbilityRuntime
} // namespace OHOS
