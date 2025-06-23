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

#ifndef OHOS_ABILITY_RUNTIME_CJ_INSIGHT_INTENT_EXECUTOR_INFO_H
#define OHOS_ABILITY_RUNTIME_CJ_INSIGHT_INTENT_EXECUTOR_INFO_H

#include <string>

#include "cj_utils_ffi.h"
#include "insight_intent_execute_param.h"

namespace OHOS::Rosen {
class CJWindowStageImpl;
}

namespace OHOS::AbilityRuntime {
const int32_t CALL_ERROR = -1;
using InsightIntentExecuteParam = AppExecFwk::InsightIntentExecuteParam;

struct CJExecuteResult {
    int32_t code = CALL_ERROR;
    char* result;
    CArrString uris;
    int32_t flags;
};

struct CJPageLoader {
    Rosen::CJWindowStageImpl* windowPageLoader = nullptr;
    int64_t sessionPageLoader = 0;
};

struct CJInsightIntentExecutorInfo {
    std::string srcEntry;
    std::string hapPath;
    bool esmodule = true;
    int32_t windowMode = 0;
    sptr<IRemoteObject> token = nullptr;
    CJPageLoader pageLoader = {};
    std::shared_ptr<InsightIntentExecuteParam> executeParam = nullptr;
};
} // namespace OHOS::AbilityRuntime
#endif // OHOS_ABILITY_RUNTIME_CJ_INSIGHT_INTENT_EXECUTOR_INFO_H
