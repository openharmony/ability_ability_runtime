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

#ifndef OHOS_INSIGHT_INTENT_RDB_STORAGE_MGR_H
#define OHOS_INSIGHT_INTENT_RDB_STORAGE_MGR_H

#include <singleton.h>
#include <string>
#include "insight_intent_rdb_data_mgr.h"
#include "hilog_tag_wrapper.h"
#include "extra_insight_intent_total_info.h"

namespace OHOS {
namespace AAFwk {
class InsightRdbStorageMgr : public std::enable_shared_from_this<InsightRdbStorageMgr> {
    DECLARE_DELAYED_SINGLETON(InsightRdbStorageMgr)
public:

    int32_t LoadInsightIntentInfos(std::vector<ExtraInsightIntentTotalInfo> &genericInfos);
    int32_t SaveStorageInsightIntentData(const std::string bundleName, const std::string moduleName,
        std::vector<ExtraInsightIntentTotalInfo> &genericInfos);
    int32_t DeleteStorageInsightIntentData(const std::string bundleName);
private:
    mutable std::mutex rdbStorePtrMutex_;
};
}  // namespace AAFwk
}  // namespace OHOS

#endif // OHOS_INSIGHT_INTENT_RDB_STORAGE_MGR_H