/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "insight_intent_db_cache.h"

namespace OHOS {
namespace AbilityRuntime {
InsightIntentDbCache::InsightIntentDbCache()
{}

void InsightIntentDbCache::InitInsightIntentCache(const int32_t userId)
{
    std::vector<ExtractInsightIntentInfo> totalInfos;
    totalInfos.clear();
    if (DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadInsightIntentInfos(userId, totalInfos) != ERR_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "Load All IntentData failed");
        return;
    }
    std::lock_guard<std::mutex> lock(genericInfosMutex_);
    for (size_t i = 0; i < totalInfos.size(); i++) {
        ExtractInsightIntentInfo info = totalInfos.at(i);
        std::string bundleName = info.genericInfo.bundleName;
        intentGenericInfos_[bundleName].push_back(info.genericInfo);
    }
    userId_ = userId;
}

InsightIntentDbCache::~InsightIntentDbCache()
{}

int32_t InsightIntentDbCache::SaveInsightIntentTotalInfo(const std::string &bundleName, const std::string &moduleName,
    const int32_t userId, ExtractInsightIntentProfileInfoVec profileInfos)
{
    std::lock_guard<std::mutex> lock(genericInfosMutex_);
    if (userId != userId_) {
        TAG_LOGE(AAFwkTag::INTENT, "The userId %{public}d. is not the cache userId %{public}d.", userId, userId_);
        return ERR_INVALID_VALUE;
    }
    std::vector<ExtractInsightIntentGenericInfo> genericInfos;
    for (auto profileInfo : profileInfos.insightIntents) {
        ExtractInsightIntentInfo info;
        ExtractInsightIntentProfile::ProfileInfoFormat(profileInfo, info);
        ExtractInsightIntentGenericInfo genericInfo = info.genericInfo;
        genericInfos.emplace_back(genericInfo);
    }
    auto it = intentGenericInfos_.find(bundleName);
    if (it != intentGenericInfos_.end()) {
        TAG_LOGW(AAFwkTag::INTENT, "need update, bundleName %{public}s", bundleName.c_str());
        for (auto iter = intentGenericInfos_[bundleName].begin(); iter != intentGenericInfos_[bundleName].end();) {
            if (iter->moduleName == moduleName) {
                iter = intentGenericInfos_[bundleName].erase(iter);
            } else {
                iter++;
            }
        }
        it->second.insert(it->second.end(), genericInfos.begin(), genericInfos.end());
    } else {
        intentGenericInfos_[bundleName] = genericInfos;
    }
    return DelayedSingleton<InsightRdbStorageMgr>::GetInstance()
            ->SaveStorageInsightIntentData(bundleName, moduleName, userId, profileInfos);
}

int32_t InsightIntentDbCache::DeleteInsightIntentTotalInfo(const std::string &bundleName, const int32_t userId)
{
    std::lock_guard<std::mutex> lock(genericInfosMutex_);
    if (userId != userId_) {
        TAG_LOGE(AAFwkTag::INTENT, "userId %{public}d. is not the cache userId %{public}d.", userId, userId_);
        return ERR_INVALID_VALUE;
    }
    intentGenericInfos_.erase(bundleName);
    return DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->DeleteStorageInsightIntentData(bundleName, userId);
}

int32_t InsightIntentDbCache::DeleteInsightIntentByUserId(const int32_t userId)
{
    std::lock_guard<std::mutex> lock(genericInfosMutex_);
    if (userId == userId_) {
        TAG_LOGE(AAFwkTag::INTENT, "can't delete the current user, userId %{public}d.", userId_);
        return ERR_INVALID_VALUE;
    }
    return DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->DeleteStorageInsightIntentByUserId(userId);
}

void InsightIntentDbCache::GetAllInsightIntentGenericInfo(std::vector<ExtractInsightIntentGenericInfo> &genericInfos)
{
    std::lock_guard<std::mutex> lock(genericInfosMutex_);
    for (auto iter = intentGenericInfos_.begin(); iter != intentGenericInfos_.end(); ++iter) {
        genericInfos.insert(genericInfos.end(), iter->second.begin(), iter->second.end());
    }
}

void InsightIntentDbCache::GetInsightIntentGenericInfoByName(const std::string &bundleName,
    std::vector<ExtractInsightIntentGenericInfo> &genericInfos)
{
    std::lock_guard<std::mutex> lock(genericInfosMutex_);
    genericInfos = intentGenericInfos_[bundleName];
}

void InsightIntentDbCache::GetInsightIntentGenericInfo(const std::string &bundleName, const std::string &moduleName,
    const std::string &intentName, ExtractInsightIntentGenericInfo &genericInfo)
{
    std::lock_guard<std::mutex> lock(genericInfosMutex_);
    for (auto info : intentGenericInfos_[bundleName]) {
        if (info.moduleName == moduleName && info.intentName == intentName) {
            genericInfo = info;
        }
    }
}

void InsightIntentDbCache::GetAllInsightIntentInfo(const int32_t userId, std::vector<ExtractInsightIntentInfo> &infos)
{
    std::lock_guard<std::mutex> lock(genericInfosMutex_);
    if (userId != userId_) {
        TAG_LOGE(AAFwkTag::INTENT, "The userId %{public}d. is not the cache userId %{public}d.", userId, userId_);
        return;
    }
    if (DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadInsightIntentInfos(userId, infos) != ERR_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "LoadIntentData failed");
        return;
    }
}

void InsightIntentDbCache::GetInsightIntentInfoByName(const std::string &bundleName, const int32_t userId,
    std::vector<ExtractInsightIntentInfo> &infos)
{
    std::lock_guard<std::mutex> lock(genericInfosMutex_);
    if (userId != userId_) {
        TAG_LOGE(AAFwkTag::INTENT, "The userId %{public}d. is not the cache userId %{public}d.", userId, userId_);
        return;
    }
    if (DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->
        LoadInsightIntentInfoByName(bundleName, userId, infos) != ERR_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "GetInsightIntentInfoByName failed");
        return;
    }
}

void InsightIntentDbCache::GetInsightIntentInfo(const std::string &bundleName, const std::string &moduleName,
    const std::string &intentName, const int32_t userId, ExtractInsightIntentInfo &info)
{
    std::lock_guard<std::mutex> lock(genericInfosMutex_);
    if (userId != userId_) {
        TAG_LOGE(AAFwkTag::INTENT, "The userId %{public}d. is not the cache userId %{public}d.", userId, userId_);
        return;
    }
    if (DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->
        LoadInsightIntentInfo(bundleName, moduleName, intentName, userId, info) != ERR_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "GetInsightIntentInfo failed");
        return;
    }
}
} // namespace AbilityRuntime
} // namespace OHOS
