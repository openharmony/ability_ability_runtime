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

#ifndef OHOS_ABILITY_RUNTIME_JS_INSIGHT_INTENT_UTILS_H
#define OHOS_ABILITY_RUNTIME_JS_INSIGHT_INTENT_UTILS_H

#include "insight_intent_execute_result.h"
#include "insight_intent_executor.h"
#include "napi/native_api.h"

namespace OHOS {
namespace AbilityRuntime {
class JsInsightIntentUtils final {
public:
    enum class State : uint8_t {
        INVALID,
        CREATED,
        INITIALIZED,
        EXECUTING,
        EXECUTATION_DONE,
        DESTROYED
    };

    static bool CallJsFunctionWithResult(
        napi_env env,
        napi_value obj,
        const char* funcName,
        size_t argc,
        const napi_value* argv,
        napi_value& result
    );

    static std::shared_ptr<AppExecFwk::InsightIntentExecuteResult> GetResultFromJs(napi_env env, napi_value resultJs);

    static napi_value ResolveCbCpp(napi_env env, napi_callback_info info);

    static napi_value RejectCbCpp(napi_env env, napi_callback_info info);

    static void ReplyFailed(InsightIntentExecutorAsyncCallback* callback,
        InsightIntentInnerErr innerErr = InsightIntentInnerErr::INSIGHT_INTENT_EXECUTE_REPLY_FAILED);

    static void ReplySucceeded(InsightIntentExecutorAsyncCallback* callback,
        std::shared_ptr<AppExecFwk::InsightIntentExecuteResult> resultCpp);

    static std::string StringifyObject(napi_env env, napi_value result);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_JS_INSIGHT_INTENT_UTILS_H