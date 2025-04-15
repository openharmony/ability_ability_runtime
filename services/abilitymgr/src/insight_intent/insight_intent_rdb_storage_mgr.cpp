/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")_;
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

#include "insight_intent_rdb_storage_mgr.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AbilityRuntime {
InsightRdbStorageMgr::InsightRdbStorageMgr()
{
    TAG_LOGD(AAFwkTag::INTENT, "InsightRdbStorageMgr is created");
    IntentRdbConfig intentRdbConfig;
    if (!DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->InitIntentTable(intentRdbConfig)) {
        TAG_LOGE(AAFwkTag::INTENT, "insight intent info rdb storage mgr init rdb table fail");
    }
}

InsightRdbStorageMgr::~InsightRdbStorageMgr()
{
    TAG_LOGD(AAFwkTag::INTENT, "InsightRdbStorageMgr is deleted");
}

int32_t InsightRdbStorageMgr::LoadInsightIntentInfos(const int32_t userId,
    std::vector<ExtractInsightIntentInfo> &totalInfos)
{
    TAG_LOGD(AAFwkTag::INTENT, "InsightRdbStorageMgr load all intent total infos");
    std::unordered_map<std::string, std::string> value;
    std::string key = std::to_string(userId);
    bool result = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->QueryDataBeginWithKey(key, value);
    if (!result) {
        TAG_LOGE(AAFwkTag::INTENT, "get entries error");
        return ERR_INVALID_VALUE;
    }
    Transform(value, totalInfos);
    return ERR_OK;
}

int32_t InsightRdbStorageMgr::LoadInsightIntentInfoByName(const std::string &bundleName, const int32_t userId,
    std::vector<ExtractInsightIntentInfo> &totalInfos)
{
    TAG_LOGD(AAFwkTag::INTENT, "load intent total infos by bundleName, %{public}s", bundleName.c_str());
    std::unordered_map<std::string, std::string> value;
    std::string key = std::to_string(userId).append("/").append(bundleName);
    bool result = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->QueryDataBeginWithKey(key, value);
    if (!result) {
        TAG_LOGE(AAFwkTag::INTENT, "get entries error");
        return ERR_INVALID_VALUE;
    }
    Transform(value, totalInfos);
    return ERR_OK;
}

int32_t InsightRdbStorageMgr::LoadInsightIntentInfo(const std::string &bundleName, const std::string &moduleName,
    const std::string &intentName, const int32_t userId, ExtractInsightIntentInfo &totalInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "InsightRdbStorageMgr load intent total info");
    std::string value;
    std::string key = std::to_string(userId).append("/").append(bundleName).append("/")
        .append(moduleName).append("/").append(intentName);
    bool result = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->QueryData(key, value);
    if (!result) {
        TAG_LOGE(AAFwkTag::INTENT, "get entries error");
        return ERR_INVALID_VALUE;
    }
    ExtractInsightIntentProfileInfoVec profileInfos;
    if (!ExtractInsightIntentProfile::TransformTo(value, profileInfos)) {
        TAG_LOGE(AAFwkTag::INTENT, "error key: %{private}s", key.c_str());
        DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->DeleteData(key);
    }
    for (const auto &profileInfo : profileInfos.insightIntents) {
        if (!ExtractInsightIntentProfile::ProfileInfoFormat(profileInfo, totalInfo)) {
            TAG_LOGE(AAFwkTag::INTENT, "ProfileInfoFormat error, key: %{private}s", key.c_str());
        }
    }
    return ERR_OK;
}

void InsightRdbStorageMgr::Transform(std::unordered_map<std::string, std::string> value,
    std::vector<ExtractInsightIntentInfo> &totalInfos)
{
    for (const auto &item : value) {
        ExtractInsightIntentProfileInfoVec profileInfos;
        if (!ExtractInsightIntentProfile::TransformTo(item.second, profileInfos)) {
            TAG_LOGE(AAFwkTag::INTENT, "error key: %{private}s", item.first.c_str());
            DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->DeleteData(item.first);
        }
        for (const auto &profileInfo : profileInfos.insightIntents) {
            ExtractInsightIntentInfo totalInfo;
            if (!ExtractInsightIntentProfile::ProfileInfoFormat(profileInfo, totalInfo)) {
                TAG_LOGE(AAFwkTag::INTENT, "ProfileInfoFormat error, key: %{private}s", item.first.c_str());
            }
            totalInfos.emplace_back(totalInfo);
        }
    }
}

int32_t InsightRdbStorageMgr::SaveStorageInsightIntentData(const std::string &bundleName, const std::string &moduleName,
    const int32_t userId, ExtractInsightIntentProfileInfoVec &profileInfos)
{
    std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
    for (auto profileInfo : profileInfos.insightIntents) {
        std::string key = std::to_string(userId).append("/").append(bundleName).append("/")
            .append(moduleName).append("/").append(profileInfo.intentName);
        nlohmann::json jsonObject;
        if (!ExtractInsightIntentProfile::ToJson(profileInfo, jsonObject)) {
            TAG_LOGE(AAFwkTag::INTENT, "Transform error, key: %{private}s", key.c_str());
            return ERR_INVALID_VALUE;
        }
        bool result = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->InsertData(key, jsonObject.dump());
        if (!result) {
            TAG_LOGE(AAFwkTag::INTENT, "InsertData error, key: %{private}s", key.c_str());
        }
    }
    return ERR_OK;
}

int32_t InsightRdbStorageMgr::DeleteStorageInsightIntentByUserId(const int32_t userId)
{
    bool result;
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        std::string key = std::to_string(userId);
        result = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->DeleteDataBeginWithKey(key);
    }
    if (!result) {
        TAG_LOGE(AAFwkTag::INTENT, "delete key by Id error");
        return ERR_INVALID_VALUE;
    }
    return ERR_OK;
}

int32_t InsightRdbStorageMgr::DeleteStorageInsightIntentData(const std::string &bundleName, const int32_t userId)
{
    bool result;
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        std::string key = std::to_string(userId).append("/").append(bundleName);
        result = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->DeleteDataBeginWithKey(key);
    }
    if (!result) {
        TAG_LOGE(AAFwkTag::INTENT, "delete key error");
        return ERR_INVALID_VALUE;
    }
    return ERR_OK;
}
} // namespace AbilityRuntime
} // namespace OHOS
