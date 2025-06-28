/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "ability_auto_startup_data_manager.h"

#include <unistd.h>

#include "ability_manager_constants.h"
#include "accesstoken_kit.h"
#include "hilog_tag_wrapper.h"
#include "json_utils.h"
#include "insight_intent_json_util.h"
#include "os_account_manager_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AAFwk;
namespace {
constexpr int32_t CHECK_INTERVAL = 100000; // 100ms
constexpr int32_t MAX_TIMES = 5;           // 5 * 100ms = 500ms
constexpr const char *AUTO_STARTUP_STORAGE_DIR = "/data/service/el1/public/database/auto_startup_service";
const std::string JSON_KEY_BUNDLE_NAME = "bundleName";
const std::string JSON_KEY_ABILITY_NAME = "abilityName";
const std::string JSON_KEY_MODULE_NAME = "moduleName";
const std::string JSON_KEY_IS_AUTO_STARTUP = "isAutoStartup";
const std::string JSON_KEY_IS_EDM_FORCE = "isEdmForce";
const std::string JSON_KEY_TYPE_NAME = "abilityTypeName";
const std::string JSON_KEY_APP_CLONE_INDEX = "appCloneIndex";
const std::string JSON_KEY_ACCESS_TOKENID = "accessTokenId";
const std::string JSON_KEY_SETTER_USERID = "setterUserId";
const std::string JSON_KEY_USERID = "userId";
const std::string JSON_KEY_SETTER_TYPE = "setterType";
} // namespace
const DistributedKv::AppId AbilityAutoStartupDataManager::APP_ID = { "auto_startup_storage" };
const DistributedKv::StoreId AbilityAutoStartupDataManager::STORE_ID = { "auto_startup_infos" };
AbilityAutoStartupDataManager::AbilityAutoStartupDataManager() {}

AbilityAutoStartupDataManager::~AbilityAutoStartupDataManager()
{
    if (kvStorePtr_ != nullptr) {
        dataManager_.CloseKvStore(APP_ID, kvStorePtr_);
    }
}

DistributedKv::Status AbilityAutoStartupDataManager::RestoreKvStore(DistributedKv::Status status)
{
    if (status == DistributedKv::Status::DATA_CORRUPTED) {
        DistributedKv::Options options = { .createIfMissing = true,
            .encrypt = false,
            .autoSync = false,
            .syncable = false,
            .securityLevel = DistributedKv::SecurityLevel::S2,
            .area = DistributedKv::EL1,
            .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION,
            .baseDir = AUTO_STARTUP_STORAGE_DIR };
        TAG_LOGI(AAFwkTag::AUTO_STARTUP, "corrupted, deleting db");
        dataManager_.DeleteKvStore(APP_ID, STORE_ID, options.baseDir);
        TAG_LOGI(AAFwkTag::AUTO_STARTUP, "deleted corrupted db, recreating db");
        status = dataManager_.GetSingleKvStore(options, APP_ID, STORE_ID, kvStorePtr_);
        TAG_LOGI(AAFwkTag::AUTO_STARTUP, "recreate db result:%{public}d", status);
    }
    return status;
}

DistributedKv::Status AbilityAutoStartupDataManager::GetKvStore()
{
    DistributedKv::Options options = { .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .syncable = false,
        .securityLevel = DistributedKv::SecurityLevel::S2,
        .area = DistributedKv::EL1,
        .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION,
        .baseDir = AUTO_STARTUP_STORAGE_DIR };

    DistributedKv::Status status = dataManager_.GetSingleKvStore(options, APP_ID, STORE_ID, kvStorePtr_);
    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "Error: %{public}d", status);
        status = RestoreKvStore(status);
        return status;
    }

    TAG_LOGD(AAFwkTag::AUTO_STARTUP, "Get kvStore success");
    return status;
}

bool AbilityAutoStartupDataManager::CheckKvStore()
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
        TAG_LOGD(AAFwkTag::AUTO_STARTUP, "Try times: %{public}d", tryTimes);
        usleep(CHECK_INTERVAL);
        tryTimes--;
    }
    return kvStorePtr_ != nullptr;
}

int32_t AbilityAutoStartupDataManager::InsertAutoStartupData(
    const AutoStartupInfo &info, bool isAutoStartup, bool isEdmForce)
{
    if (info.bundleName.empty() || info.abilityName.empty() || info.accessTokenId.empty() ||
        info.setterUserId == -1 || info.userId == -1 || info.setterType == AutoStartupSetterType::UNSPECIFIED) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "Invalid value");
        return ERR_INVALID_VALUE;
    }

    TAG_LOGD(AAFwkTag::AUTO_STARTUP,
        "bundleName: %{public}s, moduleName: %{public}s, abilityName: %{public}s,"
        " accessTokenId: %{public}s, setterUserId: %{public}d, userId: %{public}d, setterType: %{public}d",
        info.bundleName.c_str(), info.moduleName.c_str(),
        info.abilityName.c_str(), info.accessTokenId.c_str(), info.setterUserId, info.userId,
        static_cast<int32_t>(info.setterType));
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            TAG_LOGE(AAFwkTag::AUTO_STARTUP, "null kvStore");
            return ERR_NO_INIT;
        }
    }

    DistributedKv::Key key = ConvertAutoStartupDataToKey(info);
    DistributedKv::Value value = ConvertAutoStartupStatusToValue(info, isAutoStartup, isEdmForce);
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->Put(key, value);
    }

    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "kvStore insert error: %{public}d", status);
        {
            std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
            status = RestoreKvStore(status);
        }
        return ERR_INVALID_OPERATION;
    }
    return ERR_OK;
}

int32_t AbilityAutoStartupDataManager::UpdateAutoStartupData(
    const AutoStartupInfo &info, bool isAutoStartup, bool isEdmForce)
{
    if (info.bundleName.empty() || info.abilityName.empty() || info.accessTokenId.empty() ||
        info.setterUserId == -1 || info.userId == -1 || info.setterType == AutoStartupSetterType::UNSPECIFIED) {
        TAG_LOGW(AAFwkTag::AUTO_STARTUP, "Invalid value");
        return ERR_INVALID_VALUE;
    }

    TAG_LOGD(AAFwkTag::AUTO_STARTUP,
        "bundleName: %{public}s, moduleName: %{public}s, abilityName: %{public}s,"
        " accessTokenId: %{public}s, setterUserId: %{public}d, userId: %{public}d, setterType: %{public}d",
        info.bundleName.c_str(), info.moduleName.c_str(),
        info.abilityName.c_str(), info.accessTokenId.c_str(), info.setterUserId, info.userId,
        static_cast<int32_t>(info.setterType));
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            TAG_LOGE(AAFwkTag::AUTO_STARTUP, "null kvStore");
            return ERR_NO_INIT;
        }
    }

    DistributedKv::Key key = ConvertAutoStartupDataToKey(info);
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->Delete(key);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "kvStore delete error: %{public}d", status);
        {
            std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
            status = RestoreKvStore(status);
        }
        return ERR_INVALID_OPERATION;
    }
    DistributedKv::Value value = ConvertAutoStartupStatusToValue(info, isAutoStartup, isEdmForce);
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->Put(key, value);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "kvStore insert error: %{public}d", status);
        {
            std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
            status = RestoreKvStore(status);
        }
        return ERR_INVALID_OPERATION;
    }

    return ERR_OK;
}

int32_t AbilityAutoStartupDataManager::DeleteAutoStartupData(const AutoStartupInfo &info)
{
    if (info.bundleName.empty() || info.abilityName.empty() || info.accessTokenId.empty() || info.userId == -1) {
        TAG_LOGW(AAFwkTag::AUTO_STARTUP, "Invalid value");
        return ERR_INVALID_VALUE;
    }

    TAG_LOGD(AAFwkTag::AUTO_STARTUP,
        "bundleName: %{public}s, moduleName: %{public}s, abilityName: %{public}s,"
        " accessTokenId: %{public}s, userId:%{public}d",
        info.bundleName.c_str(), info.moduleName.c_str(),
        info.abilityName.c_str(), info.accessTokenId.c_str(), info.userId);
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            TAG_LOGE(AAFwkTag::AUTO_STARTUP, "null kvStore");
            return ERR_NO_INIT;
        }
    }

    DistributedKv::Key key = ConvertAutoStartupDataToKey(info);
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->Delete(key);
    }

    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "kvStore delete error: %{public}d", status);
        {
            std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
            status = RestoreKvStore(status);
        }
        return ERR_INVALID_OPERATION;
    }
    return ERR_OK;
}

int32_t AbilityAutoStartupDataManager::DeleteAutoStartupData(const std::string &bundleName, int32_t accessTokenId)
{
    auto accessTokenIdStr = std::to_string(accessTokenId);
    if (bundleName.empty() || accessTokenIdStr.empty()) {
        TAG_LOGW(AAFwkTag::AUTO_STARTUP, "Invalid value");
        return ERR_INVALID_VALUE;
    }

    TAG_LOGD(AAFwkTag::AUTO_STARTUP, "bundleName: %{public}s, accessTokenId: %{public}s",
        bundleName.c_str(), accessTokenIdStr.c_str());
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            TAG_LOGE(AAFwkTag::AUTO_STARTUP, "null kvStore");
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
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "GetEntries error: %{public}d", status);
        {
            std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
            status = RestoreKvStore(status);
        }
        return ERR_INVALID_OPERATION;
    }

    for (const auto &item : allEntries) {
        if (IsEqual(item.key, accessTokenIdStr)) {
            {
                std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
                status = kvStorePtr_->Delete(item.key);
            }
            if (status != DistributedKv::Status::SUCCESS) {
                TAG_LOGE(AAFwkTag::AUTO_STARTUP, "kvStore delete error: %{public}d", status);
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

AutoStartupStatus AbilityAutoStartupDataManager::QueryAutoStartupData(const AutoStartupInfo &info)
{
    AutoStartupStatus startupStatus;
    if (info.bundleName.empty() || info.abilityName.empty() || info.accessTokenId.empty() || info.userId == -1) {
        TAG_LOGW(AAFwkTag::AUTO_STARTUP, "Invalid value");
        startupStatus.code = ERR_INVALID_VALUE;
        return startupStatus;
    }

    TAG_LOGD(AAFwkTag::AUTO_STARTUP,
        "bundleName: %{public}s, moduleName: %{public}s, abilityName: %{public}s,"
        " accessTokenId: %{public}s, userId: %{public}d",
        info.bundleName.c_str(), info.moduleName.c_str(),
        info.abilityName.c_str(), info.accessTokenId.c_str(), info.userId);
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            TAG_LOGE(AAFwkTag::AUTO_STARTUP, "null kvStore");
            startupStatus.code = ERR_NO_INIT;
            return startupStatus;
        }
    }

    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Status status = DistributedKv::Status::SUCCESS;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->GetEntries(nullptr, allEntries);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "GetEntries error: %{public}d", status);
        {
            std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
            status = RestoreKvStore(status);
        }
        startupStatus.code = ERR_INVALID_OPERATION;
        return startupStatus;
    }

    startupStatus.code = ERR_NAME_NOT_FOUND;
    for (const auto &item : allEntries) {
        if (IsEqual(item.key, info)) {
            ConvertAutoStartupStatusFromValue(item.value, startupStatus);
            startupStatus.code = ERR_OK;
        }
    }

    return startupStatus;
}

int32_t AbilityAutoStartupDataManager::QueryAllAutoStartupApplications(std::vector<AutoStartupInfo> &infoList,
    int32_t userId, bool isCalledByEDM)
{
    TAG_LOGD(AAFwkTag::AUTO_STARTUP, "called");
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            TAG_LOGE(AAFwkTag::AUTO_STARTUP, "null kvStore");
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
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "GetEntries: %{public}d", status);
        {
            std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
            status = RestoreKvStore(status);
        }
        return ERR_INVALID_OPERATION;
    }

    for (const auto &item : allEntries) {
        if ((!isCalledByEDM) && (!IsEqual(item.key, userId))) {
            continue;
        }
        AutoStartupStatus startupStatus;
        ConvertAutoStartupStatusFromValue(item.value, startupStatus);
        if (startupStatus.isAutoStartup) {
            infoList.emplace_back(ConvertAutoStartupInfoFromKeyAndValue(item.key, item.value));
        }
    }
    TAG_LOGD(AAFwkTag::AUTO_STARTUP, "InfoList.size: %{public}zu", infoList.size());
    return ERR_OK;
}

int32_t AbilityAutoStartupDataManager::GetCurrentAppAutoStartupData(
    const std::string &bundleName, std::vector<AutoStartupInfo> &infoList, const std::string &accessTokenId)
{
    TAG_LOGD(AAFwkTag::AUTO_STARTUP, "called");
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            TAG_LOGE(AAFwkTag::AUTO_STARTUP, "null kvStore");
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
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "GetEntries error: %{public}d", status);
        {
            std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
            status = RestoreKvStore(status);
        }
        return ERR_INVALID_OPERATION;
    }

    for (const auto &item : allEntries) {
        if (IsEqual(item.key, accessTokenId)) {
            infoList.emplace_back(ConvertAutoStartupInfoFromKeyAndValue(item.key, item.value));
        }
    }
    TAG_LOGD(AAFwkTag::AUTO_STARTUP, "InfoList.size: %{public}zu", infoList.size());
    return ERR_OK;
}

DistributedKv::Value AbilityAutoStartupDataManager::ConvertAutoStartupStatusToValue(
    const AutoStartupInfo &info, bool isAutoStartup, bool isEdmForce)
{
    cJSON *jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "create jsonObject failed");
        return DistributedKv::Value();
    }

    cJSON_AddBoolToObject(jsonObject, JSON_KEY_IS_AUTO_STARTUP.c_str(), isAutoStartup);
    cJSON_AddBoolToObject(jsonObject, JSON_KEY_IS_EDM_FORCE.c_str(), isEdmForce);
    cJSON_AddStringToObject(jsonObject, JSON_KEY_TYPE_NAME.c_str(), info.abilityTypeName.c_str());
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_SETTER_USERID.c_str(), static_cast<double>(info.setterUserId));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_SETTER_TYPE.c_str(), static_cast<double>(info.setterType));

    std::string jsonStr = AAFwk::JsonUtils::GetInstance().ToString(jsonObject);
    cJSON_Delete(jsonObject);
    DistributedKv::Value value(jsonStr);

    TAG_LOGD(AAFwkTag::AUTO_STARTUP, "value: %{public}s", value.ToString().c_str());
    return value;
}

void AbilityAutoStartupDataManager::ConvertAutoStartupStatusFromValue(
    const DistributedKv::Value &value, AutoStartupStatus &startupStatus)
{
    cJSON *jsonObject = cJSON_Parse(value.ToString().c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "parse jsonObject failed");
        return;
    }
    cJSON *isAutoStartupItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_IS_AUTO_STARTUP.c_str());
    if (isAutoStartupItem != nullptr && cJSON_IsBool(isAutoStartupItem)) {
        startupStatus.isAutoStartup = isAutoStartupItem->type == cJSON_True;
    }
    cJSON *isEdmForceItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_IS_EDM_FORCE.c_str());
    if (isEdmForceItem != nullptr && cJSON_IsBool(isEdmForceItem)) {
        startupStatus.isEdmForce = isEdmForceItem->type == cJSON_True;
    }
    cJSON *setterUserIdItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_SETTER_USERID.c_str());
    if (setterUserIdItem != nullptr && cJSON_IsNumber(setterUserIdItem)) {
        startupStatus.setterUserId = static_cast<int32_t>(setterUserIdItem->valuedouble);
    }
    cJSON *setterTypeItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_SETTER_TYPE.c_str());
    if (setterTypeItem != nullptr && cJSON_IsNumber(setterTypeItem)) {
        startupStatus.setterType = static_cast<AutoStartupSetterType>(setterTypeItem->valuedouble);
    }
    cJSON_Delete(jsonObject);
}

DistributedKv::Key AbilityAutoStartupDataManager::ConvertAutoStartupDataToKey(const AutoStartupInfo &info)
{
    cJSON *jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "create jsonObject failed");
        return DistributedKv::Key();
    }
    cJSON_AddStringToObject(jsonObject, JSON_KEY_BUNDLE_NAME.c_str(), info.bundleName.c_str());
    cJSON_AddStringToObject(jsonObject, JSON_KEY_MODULE_NAME.c_str(), info.moduleName.c_str());
    cJSON_AddStringToObject(jsonObject, JSON_KEY_ABILITY_NAME.c_str(), info.abilityName.c_str());
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_APP_CLONE_INDEX.c_str(), static_cast<double>(info.appCloneIndex));
    cJSON_AddStringToObject(jsonObject, JSON_KEY_ACCESS_TOKENID.c_str(), info.accessTokenId.c_str());
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_USERID.c_str(), static_cast<double>(info.userId));
    std::string jsonStr = AAFwk::JsonUtils::GetInstance().ToString(jsonObject);
    cJSON_Delete(jsonObject);
    DistributedKv::Key key(jsonStr);
    TAG_LOGD(AAFwkTag::AUTO_STARTUP, "key: %{public}s", key.ToString().c_str());
    return key;
}

AutoStartupInfo AbilityAutoStartupDataManager::ConvertAutoStartupInfoFromKeyAndValue(
    const DistributedKv::Key &key, const DistributedKv::Value &value)
{
    AutoStartupInfo info;
    ConvertAutoStartupInfoFromKey(key, info);
    ConvertAutoStartupInfoFromValue(value, info);
    return info;
}

void AbilityAutoStartupDataManager::ConvertAutoStartupInfoFromKey(
    const DistributedKv::Key &key, AutoStartupInfo &info)
{
    cJSON *jsonObject = cJSON_Parse(key.ToString().c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "parse jsonObject fail");
        return;
    }

    cJSON *bundleNameItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_BUNDLE_NAME.c_str());
    if (bundleNameItem != nullptr && cJSON_IsString(bundleNameItem)) {
        info.bundleName = bundleNameItem->valuestring;
    }

    cJSON *moduleNameItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_MODULE_NAME.c_str());
    if (moduleNameItem != nullptr && cJSON_IsString(moduleNameItem)) {
        info.moduleName = moduleNameItem->valuestring;
    }

    cJSON *abilityNameItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_ABILITY_NAME.c_str());
    if (abilityNameItem != nullptr && cJSON_IsString(abilityNameItem)) {
        info.abilityName = abilityNameItem->valuestring;
    }

    cJSON *appCloneIndexItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_APP_CLONE_INDEX.c_str());
    if (appCloneIndexItem != nullptr && cJSON_IsNumber(appCloneIndexItem)) {
        info.appCloneIndex = static_cast<int32_t>(appCloneIndexItem->valuedouble);
    }

    cJSON *accessTokenIdItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_ACCESS_TOKENID.c_str());
    if (accessTokenIdItem != nullptr && cJSON_IsString(accessTokenIdItem)) {
        info.accessTokenId = accessTokenIdItem->valuestring;
    }

    cJSON *userIdItem = cJSON_GetObjectItem(jsonObject, JSON_KEY_USERID.c_str());
    if (userIdItem != nullptr && cJSON_IsNumber(userIdItem)) {
        info.userId = static_cast<int32_t>(userIdItem->valuedouble);
    }
    cJSON_Delete(jsonObject);
}

void AbilityAutoStartupDataManager::ConvertAutoStartupInfoFromValue(
    const DistributedKv::Value &value, AutoStartupInfo &info)
{
    cJSON *jsonValueObject = cJSON_Parse(value.ToString().c_str());
    if (jsonValueObject == nullptr) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "parse jsonValueObject fail");
        return;
    }

    cJSON *typeNameItem = cJSON_GetObjectItem(jsonValueObject, JSON_KEY_TYPE_NAME.c_str());
    if (typeNameItem != nullptr && cJSON_IsString(typeNameItem)) {
        info.abilityTypeName = typeNameItem->valuestring;
    }

    cJSON *isEdmForceItem = cJSON_GetObjectItem(jsonValueObject, JSON_KEY_IS_EDM_FORCE.c_str());
    if (isEdmForceItem != nullptr && cJSON_IsBool(isEdmForceItem)) {
        info.canUserModify = !(isEdmForceItem->type == cJSON_True);
    }

    cJSON *setterUserIdItem = cJSON_GetObjectItem(jsonValueObject, JSON_KEY_SETTER_USERID.c_str());
    if (setterUserIdItem != nullptr && cJSON_IsNumber(setterUserIdItem)) {
        info.setterUserId = static_cast<int32_t>(setterUserIdItem->valuedouble);
    }

    cJSON_Delete(jsonValueObject);
}

bool AbilityAutoStartupDataManager::IsEqual(const DistributedKv::Key &key, const AutoStartupInfo &info)
{
    cJSON *jsonObject = cJSON_Parse(key.ToString().c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "parse jsonObject failed");
        return false;
    }

    if (!AAFwk::JsonUtils::GetInstance().IsEqual(jsonObject, JSON_KEY_BUNDLE_NAME, info.bundleName)
        || !AAFwk::JsonUtils::GetInstance().IsEqual(jsonObject, JSON_KEY_ABILITY_NAME, info.abilityName)
        || !AAFwk::JsonUtils::GetInstance().IsEqual(jsonObject, JSON_KEY_MODULE_NAME, info.moduleName, true)
        || !AAFwk::JsonUtils::GetInstance().IsEqual(jsonObject, JSON_KEY_APP_CLONE_INDEX, info.appCloneIndex)
        || !AAFwk::JsonUtils::GetInstance().IsEqual(jsonObject, JSON_KEY_ACCESS_TOKENID, info.accessTokenId)
        || !AAFwk::JsonUtils::GetInstance().IsEqual(jsonObject, JSON_KEY_USERID, info.userId)) {
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_Delete(jsonObject);
    return true;
}

bool AbilityAutoStartupDataManager::IsEqual(const DistributedKv::Key &key, const std::string &accessTokenId)
{
    cJSON *jsonObject = cJSON_Parse(key.ToString().c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "parse jsonObject fail");
        return false;
    }

    cJSON *itemObject = cJSON_GetObjectItem(jsonObject, JSON_KEY_ACCESS_TOKENID.c_str());
    if (itemObject != nullptr && cJSON_IsString(itemObject)) {
        if (accessTokenId == std::string(itemObject->valuestring)) {
            cJSON_Delete(jsonObject);
            return true;
        }
    }
    cJSON_Delete(jsonObject);
    return false;
}

bool AbilityAutoStartupDataManager::IsEqual(const DistributedKv::Key &key, int32_t userId)
{
    cJSON *jsonObject = cJSON_Parse(key.ToString().c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::AUTO_STARTUP, "parse jsonObject fail");
        return false;
    }
    auto &jsonUtil = AAFwk::JsonUtils::GetInstance();
    if (jsonUtil.IsEqual(jsonObject, JSON_KEY_USERID, userId) ||
        jsonUtil.IsEqual(jsonObject, JSON_KEY_USERID, U0_USER_ID) ||
        jsonUtil.IsEqual(jsonObject, JSON_KEY_USERID, U1_USER_ID)) {
        cJSON_Delete(jsonObject);
        return true;
    }
    cJSON_Delete(jsonObject);
    return false;
}
} // namespace AbilityRuntime
} // namespace OHOS
