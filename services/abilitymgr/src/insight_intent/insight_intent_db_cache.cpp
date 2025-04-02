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
namespace AAFwk {
void InsightIntentDbCache::InitInsightIntentCache()
{
    std::vector<ExtraInsightIntentTotalInfo> totalInfos;
    totalInfos.clear();
    if (DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadInsightIntentInfos(totalInfos) != ERR_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "LoadIntentData failed");
        return;
    }
    std::lock_guard<std::mutex> lock(totalInfosMutex_);
    for (unsigned int i = 0; i < totalInfos.size(); i++) {
        ExtraInsightIntentTotalInfo info = totalInfos.at(i);
        std::string bundleName = totalInfos.at(i).bundleName;
        intentTotalInfos_[bundleName].push_back(info);
    }
}

int32_t InsightIntentDbCache::SaveInsightIntentTotalInfo(const std::string bundleName, const std::string moduleName,
    std::vector<ExtraInsightIntentTotalInfo> totalInfos)
{
    std::lock_guard<std::mutex> lock(totalInfosMutex_);
    auto it = intentTotalInfos_.find(bundleName);
    if (it != intentTotalInfos_.end()) {
        TAG_LOGW(AAFwkTag::INTENT, "need update, bundleName %{public}s", bundleName.c_str());
        for (auto iter = intentTotalInfos_[bundleName].begin(); iter != intentTotalInfos_[bundleName].end();) {
            if (strcmp(iter->moduleName.c_str(), moduleName.c_str()) == 0) {
                iter = intentTotalInfos_[bundleName].erase(iter);
            } else {
                iter++;
            }
        }
        it->second.insert(it->second.end(), totalInfos.begin(), totalInfos.end());
    } else {
        intentTotalInfos_[bundleName] = totalInfos;
    }
    return DelayedSingleton<InsightRdbStorageMgr>::GetInstance()
            ->SaveStorageInsightIntentData(bundleName, moduleName, totalInfos);
}

int32_t InsightIntentDbCache::DeleteInsightIntentTotalInfo(const std::string bundleName)
{
    std::lock_guard<std::mutex> lock(totalInfosMutex_);
    intentTotalInfos_.erase(bundleName);
    if (DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->DeleteStorageInsightIntentData(bundleName) == ERR_OK) {
        return ERR_OK;
    } else {
        return ERR_INVALID_VALUE;
    }
}

void InsightIntentDbCache::GetAllInsightIntentTotalInfo(std::vector<ExtraInsightIntentTotalInfo> &totalInfos)
{
    std::lock_guard<std::mutex> lock(totalInfosMutex_);
    for (auto iter = intentTotalInfos_.begin(); iter != intentTotalInfos_.end(); ++iter) {
        totalInfos.insert(totalInfos.end(), iter->second.begin(), iter->second.end());
    }
}

void InsightIntentDbCache::GetInsightIntentTotalInfoByName(const std::string bundleName,
    std::vector<ExtraInsightIntentTotalInfo> &totalInfos)
{
    std::lock_guard<std::mutex> lock(totalInfosMutex_);
    totalInfos = intentTotalInfos_[bundleName];
}

void InsightIntentDbCache::GetInsightIntentTotalInfo(const std::string bundleName,
    const std::string intentName, std::vector<ExtraInsightIntentTotalInfo> &totalInfos)
{
    std::lock_guard<std::mutex> lock(totalInfosMutex_);
    for (auto info : intentTotalInfos_[bundleName]) {
        if (strcmp(info.intentName.c_str(), intentName.c_str()) == 0) {
            totalInfos.push_back(info);
        }
    }
}
} // namespace AAFwk
} // namespace OHOS
