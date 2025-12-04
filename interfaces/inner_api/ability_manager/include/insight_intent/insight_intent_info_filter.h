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

#ifndef OHOS_ABILITY_RUNTIME_INSIGHT_INTENT_INFO_FILTER_H
#define OHOS_ABILITY_RUNTIME_INSIGHT_INTENT_INFO_FILTER_H

#include <string>
#include <vector>

#include "insight_intent_constant.h"

namespace OHOS {
namespace AppExecFwk {
class InsightIntentInfoFilter {
    const int32_t DEFAULT_INVAL_VALUE = -1;
public:
    InsightIntentInfoFilter() = default;
    ~InsightIntentInfoFilter() = default;

    AbilityRuntime::GetInsightIntentFlag intentFlags_;
    std::string bundleName_;
    std::string moduleName_;
    std::string intentName_;
    int32_t userId_ = DEFAULT_INVAL_VALUE;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_INSIGHT_INTENT_INFO_FILTER_H
