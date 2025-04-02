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

#ifndef OHOS_EXTRA_INSIGHT_INTENT_TOTAL_INFO_H
#define OHOS_EXTRA_INSIGHT_INTENT_TOTAL_INFO_H

#include <vector>
#include <mutex>
#include <string>
#include "nlohmann/json.hpp"
#include <singleton.h>
#include "rdb_store_config.h"

namespace OHOS {
namespace AAFwk {
struct ExtraInsightIntentGenericInfo {
};
struct ExtraInsightIntentTotalInfo {
    std::string bundleName;
    std::string moduleName;
    std::string intentName;
    ExtraInsightIntentGenericInfo extraInsightIntentGenericInfo;

    std::string ToString() const
    {
        nlohmann::json obj;
        return obj.dump();
    }

    bool FromJson(const nlohmann::json &jsonObject) const
    {
        return true;
    }
};
} // namespace AAFwk
} // namespace OHOS

#endif // OHOS_EXTRA_INSIGHT_INTENT_TOTAL_INFO_H