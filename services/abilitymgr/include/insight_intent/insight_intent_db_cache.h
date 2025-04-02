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

#ifndef OHOS_INSIGHT_INTENT_DB_CACHE_H
#define OHOS_INSIGHT_INTENT_DB_CACHE_H

#include <mutex>
#include <set>
#include <singleton.h>
#include <vector>
#include "insight_intent_rdb_storage_mgr.h"

namespace OHOS {
namespace AAFwk {
class InsightIntentDbCache : public std::enable_shared_from_this<InsightIntentDbCache> {
    DECLARE_DELAYED_SINGLETON(InsightIntentDbCache)
public:
    void InitInsightIntentCache();
    void GetAllInsightIntentTotalInfo(std::vector<ExtraInsightIntentTotalInfo> &totalInfos);
    void GetInsightIntentTotalInfoByName(const std::string bundleName,
        std::vector<ExtraInsightIntentTotalInfo> &totalInfos);
    void GetInsightIntentTotalInfo(const std::string bundleName, const std::string intentName,
        std::vector<ExtraInsightIntentTotalInfo> &totalInfos);
    int32_t SaveInsightIntentTotalInfo(const std::string bundleName, const std::string moduleName,
        std::vector<ExtraInsightIntentTotalInfo> totalInfos);
    int32_t DeleteInsightIntentTotalInfo(const std::string bundleName);
private:
    mutable std::mutex totalInfosMutex_;
    std::map<std::string, std::vector<ExtraInsightIntentTotalInfo>> intentTotalInfos_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_INSIGHT_INTENT_DB_CACHE_H
