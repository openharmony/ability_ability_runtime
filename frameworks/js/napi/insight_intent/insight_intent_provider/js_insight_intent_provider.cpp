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

#include "js_insight_intent_provider.h"

#include "hilog_tag_wrapper.h"
#include "js_runtime_utils.h"
#include "js_error_utils.h"


#include "napi_common_execute_result.h"
#include "insight_intent_delay_result_callback_mgr.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
const char *JS_INSIGHT_INTENT_PROVIDER_NAME = "JsInsightIntentProvider";
constexpr size_t ARGC_TWO = 2;
} // namespace

class JsInsightIntentProvider {
public:
    JsInsightIntentProvider() = default;
    ~JsInsightIntentProvider() = default;

    static void Finalizer(napi_env env, void *data, void *hint)
    {
        TAG_LOGD(AAFwkTag::INTENT, "called");
        std::unique_ptr<JsInsightIntentProvider>(static_cast<JsInsightIntentProvider*>(data));
    }

    static napi_value SendExecuteResult(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsInsightIntentProvider, OnSendExecuteResult);
    }

    static napi_value SendIntentResult(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsInsightIntentProvider, OnSendIntentResult);
    }

private:
    napi_value OnSendExecuteResult(napi_env env, NapiCallbackInfo& info)
    {
        TAG_LOGD(AAFwkTag::INTENT, "called");
        return OnSendExecuteResultCommon(env, info, false);
    }

    napi_value OnSendIntentResult(napi_env env, NapiCallbackInfo& info)
    {
        TAG_LOGD(AAFwkTag::INTENT, "called");
        return OnSendExecuteResultCommon(env, info, true);
    }

    napi_value OnSendExecuteResultCommon(napi_env env, NapiCallbackInfo& info, bool isDecorator)
    {
        TAG_LOGD(AAFwkTag::INTENT, "called");
        if (info.argc < ARGC_TWO) {
            TAG_LOGE(AAFwkTag::INTENT, "invalid argc");
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }
        int32_t insightIntentId = -1;
        if (!ConvertFromJsValue(env, info.argv[0], insightIntentId)) {
            TAG_LOGE(AAFwkTag::INTENT, "Parse insightIntentId failed");
            ThrowError(env, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
            return CreateJsUndefined(env);
        }
        auto nativeResult = std::make_shared<AppExecFwk::InsightIntentExecuteResult>();
        if (!UnwrapExecuteResult(env, info.argv[1], *nativeResult, isDecorator)) {
            TAG_LOGE(AAFwkTag::INTENT, " failed to UnwrapExecuteResult");
            ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
            return CreateJsUndefined(env);
        }
        auto innerErrorCode = std::make_shared<int32_t>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [innerErrorCode, insightIntentId, nativeResult, isDecorator]() {
            *innerErrorCode = InsightIntentDelayResultCallbackMgr::GetInstance().HandleExecuteDone(
                insightIntentId, *nativeResult, isDecorator);
        };

        NapiAsyncTask::CompleteCallback complete = [innerErrorCode](napi_env env, NapiAsyncTask &task, int32_t status) {
            if (*innerErrorCode != ERR_OK) {
                TAG_LOGE(AAFwkTag::INTENT, "error: %{public}d",
                    *innerErrorCode);
                task.Reject(env, CreateJsError(env, static_cast<AbilityErrorCode>(*innerErrorCode)));
                return;
            }
            task.ResolveWithNoError(env, CreateJsUndefined(env));
        };

        napi_value lastParam = (info.argc > ARGC_TWO) ? info. argv[ARGC_TWO] : nullptr;
        napi_value result = nullptr;
        NapiAsyncTask::Schedule("JsInsightIntentProvider::OnSendIntentResult", env,
            CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }
};

napi_value CreateJsInsightIntentProvider(napi_env env, napi_value exportObj)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    if (env == nullptr || exportObj == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env or exportObj");
        return nullptr;
    }

    std::unique_ptr<JsInsightIntentProvider> provider = std::make_unique<JsInsightIntentProvider>();
    napi_wrap(env, exportObj, provider.release(), JsInsightIntentProvider::Finalizer, nullptr, nullptr);
    BindNativeFunction(env, exportObj, "sendExecuteResult", JS_INSIGHT_INTENT_PROVIDER_NAME,
        JsInsightIntentProvider::SendExecuteResult);
    BindNativeFunction(env, exportObj, "sendIntentResult", JS_INSIGHT_INTENT_PROVIDER_NAME,
        JsInsightIntentProvider::SendIntentResult);

    return CreateJsUndefined(env);
}
} // namespace AbilityRuntime
} // namespace OHOS
