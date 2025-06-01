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

#include "js_insight_intent_utils.h"

namespace OHOS {
namespace AbilityRuntime {
bool JsInsightIntentUtils::CallJsFunctionWithResult(
    napi_env env,
    napi_value obj,
    const char* funcName,
    size_t argc,
    const napi_value* argv,
    napi_value& result)
{
    return false;
}

std::shared_ptr<AppExecFwk::InsightIntentExecuteResult> JsInsightIntentUtils::GetResultFromJs(
    napi_env env, napi_value resultJs)
{
    return nullptr;
}

napi_value JsInsightIntentUtils::ResolveCbCpp(napi_env env, napi_callback_info info)
{
    return nullptr;
}

napi_value JsInsightIntentUtils::RejectCbCpp(napi_env env, napi_callback_info info)
{
    return nullptr;
}

void JsInsightIntentUtils::ReplyFailed(InsightIntentExecutorAsyncCallback* callback,
    InsightIntentInnerErr innerErr)
{
}

void JsInsightIntentUtils::ReplySucceeded(InsightIntentExecutorAsyncCallback* callback,
    std::shared_ptr<AppExecFwk::InsightIntentExecuteResult> resultCpp)
{
}

std::string JsInsightIntentUtils::StringifyObject(napi_env env, napi_value result)
{
    return "";
}
} // namespace AbilityRuntime
} // namespace OHOS
