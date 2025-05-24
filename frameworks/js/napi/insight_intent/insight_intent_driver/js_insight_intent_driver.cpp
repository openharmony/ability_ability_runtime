/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "js_insight_intent_driver.h"

#include "ability_business_error.h"
#include "ability_manager_client.h"
#include "event_handler.h"
#include "event_runner.h"
#include "hilog_tag_wrapper.h"
#include "insight_intent_callback_interface.h"
#include "insight_intent_host_client.h"
#include "insight_intent_execute_result.h"
#include "js_error_utils.h"
#include "js_insight_intent_driver_utils.h"
#include "js_runtime_utils.h"
#include "napi_common_execute_param.h"
#include "napi_common_util.h"
#include "native_engine/native_value.h"

#include <mutex>

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
namespace {
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;
constexpr int32_t INDEX_TWO = 2;
constexpr int32_t INDEX_THREE = 3;
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr size_t ARGC_FOUR = 4;
}
class JsInsightIntentExecuteCallbackClient : public InsightIntentExecuteCallbackInterface,
    public std::enable_shared_from_this<JsInsightIntentExecuteCallbackClient> {
public:
    JsInsightIntentExecuteCallbackClient(napi_env env, napi_deferred nativeDeferred, napi_ref callbackRef)
        : env_(env), nativeDeferred_(nativeDeferred), callbackRef_(callbackRef) {}

    virtual ~JsInsightIntentExecuteCallbackClient() = default;

    void ProcessInsightIntentExecute(int32_t resultCode,
        AppExecFwk::InsightIntentExecuteResult executeResult) override
    {
        NapiAsyncTask::CompleteCallback complete = [resultCode = resultCode, executeResult = executeResult]
            (napi_env env, NapiAsyncTask &task, int32_t status) {
            if (resultCode != 0) {
                task.Reject(env, CreateJsError(env, GetJsErrorCodeByNativeError(resultCode)));
            } else {
                task.ResolveWithNoError(env, CreateJsExecuteResult(env, executeResult));
            }
        };
        std::unique_ptr<NapiAsyncTask> asyncTask = nullptr;
        if (nativeDeferred_) {
            asyncTask = std::make_unique<NapiAsyncTask>(nativeDeferred_, nullptr,
                std::make_unique<NapiAsyncTask::CompleteCallback>(std::move(complete)));
        } else {
            asyncTask = std::make_unique<NapiAsyncTask>(callbackRef_, nullptr,
                std::make_unique<NapiAsyncTask::CompleteCallback>(std::move(complete)));
        }
        NapiAsyncTask::Schedule("JsInsightIntentDriver::OnExecute", env_, std::move(asyncTask));
    }
private:
    napi_env env_;
    napi_deferred nativeDeferred_ = nullptr;
    napi_ref callbackRef_ = nullptr;
};

class JsInsightIntentDriver {
public:
    JsInsightIntentDriver() = default;
    ~JsInsightIntentDriver() = default;

    static void Finalizer(napi_env env, void *data, void *hint)
    {
        TAG_LOGI(AAFwkTag::INTENT, "called");
        std::unique_ptr<JsInsightIntentDriver>(static_cast<JsInsightIntentDriver*>(data));
    }

    static napi_value Execute(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsInsightIntentDriver, OnExecute);
    }

    static napi_value GetAllInsightIntentInfo(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsInsightIntentDriver, OnGetAllInsightIntentInfo);
    }

    static napi_value GetInsightIntentInfoByBundleName(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsInsightIntentDriver, OnGetInsightIntentInfoByBundleName);
    }

    static napi_value GetInsightIntentInfoByIntentName(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsInsightIntentDriver, OnGetInsightIntentInfoByIntentName);
    }

private:
    napi_value OnExecute(napi_env env, NapiCallbackInfo& info)
    {
        TAG_LOGD(AAFwkTag::INTENT, "called");
        if (info.argc < ARGC_ONE) {
            TAG_LOGE(AAFwkTag::INTENT, "invalid argc");
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }

        InsightIntentExecuteParam param;
        if (!UnwrapExecuteParam(env, info.argv[INDEX_ZERO], param)) {
            TAG_LOGE(AAFwkTag::INTENT, "parse on off type failed");
            ThrowInvalidParamError(env, "Parameter error: Parse param failed, param must be a ExecuteParam.");
            return CreateJsUndefined(env);
        }

        napi_value lastParam = (info.argc == 1) ? nullptr : info.argv[INDEX_ONE];
        napi_valuetype type = napi_undefined;
        napi_typeof(env, lastParam, &type);

        napi_value result = nullptr;
        napi_deferred nativeDeferred = nullptr;
        napi_ref callbackRef = nullptr;
        std::unique_ptr<NapiAsyncTask> asyncTask = nullptr;
        if (lastParam == nullptr || type != napi_function) {
            napi_create_promise(env, &nativeDeferred, &result);
            asyncTask = std::make_unique<NapiAsyncTask>(nativeDeferred, nullptr, nullptr);
        } else {
            napi_get_undefined(env, &result);
            napi_create_reference(env, lastParam, 1, &callbackRef);
            asyncTask = std::make_unique<NapiAsyncTask>(callbackRef, nullptr, nullptr);
        }

        if (asyncTask == nullptr) {
            TAG_LOGE(AAFwkTag::INTENT, "null asyncTask");
            return CreateJsUndefined(env);
        }
        auto client = std::make_shared<JsInsightIntentExecuteCallbackClient>(env, nativeDeferred, callbackRef);
        uint64_t key = InsightIntentHostClient::GetInstance()->AddInsightIntentExecute(client);
        auto err = AbilityManagerClient::GetInstance()->ExecuteIntent(key,
            InsightIntentHostClient::GetInstance(), param);
        if (err != 0) {
            asyncTask->Reject(env, CreateJsError(env, GetJsErrorCodeByNativeError(err)));
            InsightIntentHostClient::GetInstance()->RemoveInsightIntentExecute(key);
        }
        return result;
    }
    
    napi_value OnGetAllInsightIntentInfo(napi_env env, NapiCallbackInfo& info)
    {
        TAG_LOGI(AAFwkTag::INTENT, "OnGetAllInsightIntentInfo");
        if (info.argc < ARGC_ONE) {
            TAG_LOGE(AAFwkTag::INTENT, "invalid argc");
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }
        GetInsightIntentFlag flag;
        if (!ConvertFromJsValue(env, info.argv[INDEX_ZERO], flag) ||
            (flag != GetInsightIntentFlag::GET_FULL_INSIGHT_INTENT &&
            flag != GetInsightIntentFlag::GET_SUMMARY_INSIGHT_INTENT)) {
            TAG_LOGE(AAFwkTag::INTENT, "Parse flag failed");
            ThrowInvalidParamError(env, "Parse param flag failed, flag must be GetInsightIntentFlag.");
            return CreateJsUndefined(env);
        }
        auto innerErrorCode = std::make_shared<int32_t>(ERR_OK);
        auto infos = std::make_shared<std::vector<InsightIntentInfoForQuery>>();
        NapiAsyncTask::ExecuteCallback execute = [infos, flag, innerErrorCode]() {
            *innerErrorCode = AbilityManagerClient::GetInstance()->GetAllInsightIntentInfo(flag, *infos);
        };
        NapiAsyncTask::CompleteCallback complete =
            [innerErrorCode, infos](napi_env env, NapiAsyncTask &task, int32_t status) {
                if (*innerErrorCode == 0) {
                    task.ResolveWithNoError(env, CreateInsightIntentInfoForQueryArray(env, *infos));
                } else {
                    task.Reject(env, CreateJsError(env, GetJsErrorCodeByNativeError(*innerErrorCode)));
                }
            };
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JsInsightIntentDriver::OnGetAllInsightIntentInfo",
            env, CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnGetInsightIntentInfoByBundleName(napi_env env, NapiCallbackInfo& info)
    {
        TAG_LOGI(AAFwkTag::INTENT, "OnGetInsightIntentInfoByBundleName");
        if (info.argc < ARGC_TWO) {
            TAG_LOGE(AAFwkTag::INTENT, "invalid argc");
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }
        std::string bundleName;
        if (!ConvertFromJsValue(env, info.argv[INDEX_ZERO], bundleName)) {
            TAG_LOGE(AAFwkTag::INTENT, "Parse bundleName failed");
            ThrowInvalidParamError(env, "Parse param bundleName failed, bundleName must be string.");
            return CreateJsUndefined(env);
        }
        GetInsightIntentFlag flag;
        if (!ConvertFromJsValue(env, info.argv[INDEX_ONE], flag) ||
            (flag != GetInsightIntentFlag::GET_FULL_INSIGHT_INTENT &&
            flag != GetInsightIntentFlag::GET_SUMMARY_INSIGHT_INTENT)) {
            TAG_LOGE(AAFwkTag::INTENT, "Parse flag failed");
            ThrowInvalidParamError(env, "Parse param flag failed, flag must be GetInsightIntentFlag.");
            return CreateJsUndefined(env);
        }
        auto innerErrorCode = std::make_shared<int32_t>(ERR_OK);
        auto infos = std::make_shared<std::vector<InsightIntentInfoForQuery>>();
        NapiAsyncTask::ExecuteCallback execute = [infos, flag, bundleName, innerErrorCode]() {
            *innerErrorCode = AbilityManagerClient::GetInstance()->GetInsightIntentInfoByBundleName(
                flag, bundleName, *infos);
        };
        NapiAsyncTask::CompleteCallback complete =
            [innerErrorCode, infos](napi_env env, NapiAsyncTask &task, int32_t status) {
                if (*innerErrorCode == 0) {
                    task.ResolveWithNoError(env, CreateInsightIntentInfoForQueryArray(env, *infos));
                } else {
                    task.Reject(env, CreateJsError(env, GetJsErrorCodeByNativeError(*innerErrorCode)));
                }
            };
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JsInsightIntentDriver::OnGetInsightIntentInfoByBundleName",
            env, CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnGetInsightIntentInfoByIntentName(napi_env env, NapiCallbackInfo& info)
    {
        TAG_LOGI(AAFwkTag::INTENT, "OnGetInsightIntentInfoByIntentName");
        if (info.argc < ARGC_FOUR) {
            TAG_LOGE(AAFwkTag::INTENT, "invalid argc");
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }
        std::string bundleName;
        if (!ConvertFromJsValue(env, info.argv[INDEX_ZERO], bundleName)) {
            TAG_LOGE(AAFwkTag::INTENT, "Parse bundleName failed");
            ThrowInvalidParamError(env, "Parse param bundleName failed, bundleName must be string.");
            return CreateJsUndefined(env);
        }
        std::string moduleName;
        if (!ConvertFromJsValue(env, info.argv[INDEX_ONE], moduleName)) {
            TAG_LOGE(AAFwkTag::INTENT, "Parse intentName failed");
            ThrowInvalidParamError(env, "Parse param moduleName failed, moduleName must be string.");
            return CreateJsUndefined(env);
        }
        std::string intentName;
        if (!ConvertFromJsValue(env, info.argv[INDEX_TWO], intentName)) {
            TAG_LOGE(AAFwkTag::INTENT, "Parse intentName failed");
            ThrowInvalidParamError(env, "Parse param intentName failed, intentName must be string.");
            return CreateJsUndefined(env);
        }
        GetInsightIntentFlag flag;
        if (!ConvertFromJsValue(env, info.argv[INDEX_THREE], flag) ||
            (flag != GetInsightIntentFlag::GET_FULL_INSIGHT_INTENT &&
            flag != GetInsightIntentFlag::GET_SUMMARY_INSIGHT_INTENT)) {
            TAG_LOGE(AAFwkTag::INTENT, "Parse flag failed");
            ThrowInvalidParamError(env, "Parse param flag failed, flag must be GetInsightIntentFlag.");
            return CreateJsUndefined(env);
        }
        auto innerErrorCode = std::make_shared<int32_t>(ERR_OK);
        auto intentInfo = std::make_shared<InsightIntentInfoForQuery>();
        NapiAsyncTask::ExecuteCallback execute =
            [intentInfo, flag, bundleName, moduleName, intentName, innerErrorCode]() {
                *innerErrorCode = AbilityManagerClient::GetInstance()->GetInsightIntentInfoByIntentName(
                    flag, bundleName, moduleName, intentName, *intentInfo);
            };
        NapiAsyncTask::CompleteCallback complete =
            [innerErrorCode, intentInfo](napi_env env, NapiAsyncTask &task, int32_t status) {
                if (*innerErrorCode == 0) {
                    task.ResolveWithNoError(env, CreateInsightIntentInfoForQuery(env, *intentInfo));
                } else {
                    task.Reject(env, CreateJsError(env, GetJsErrorCodeByNativeError(*innerErrorCode)));
                }
            };
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JsInsightIntentDriver::OnGetInsightIntentInfoByIntentName",
            env, CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), &result));
        return result;
    }
};

static napi_status SetEnumItem(napi_env env, napi_value napiObject, const char* name, int32_t value)
{
    napi_status status;
    napi_value itemName;
    napi_value itemValue;

    NAPI_CALL_BASE(env, status = napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &itemName), status);
    NAPI_CALL_BASE(env, status = napi_create_int32(env, value, &itemValue), status);

    NAPI_CALL_BASE(env, status = napi_set_property(env, napiObject, itemName, itemValue), status);
    NAPI_CALL_BASE(env, status = napi_set_property(env, napiObject, itemValue, itemName), status);

    return napi_ok;
}

static napi_status SetEnumItem(napi_env env, napi_value napiObject, const char* name, const char* value)
{
    napi_status status;
    napi_value itemName;
    napi_value itemValue;

    NAPI_CALL_BASE(env, status = napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &itemName), status);
    NAPI_CALL_BASE(env, status = napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &itemValue), status);

    NAPI_CALL_BASE(env, status = napi_set_property(env, napiObject, itemName, itemValue), status);
    NAPI_CALL_BASE(env, status = napi_set_property(env, napiObject, itemValue, itemName), status);

    return napi_ok;
}

static napi_value InitGetInsightIntentFlagObject(napi_env env)
{
    napi_value napiObject;
    NAPI_CALL(env, napi_create_object(env, &napiObject));

    NAPI_CALL(env, SetEnumItem(
        env, napiObject, "GET_FULL_INSIGHT_INTENT", GetInsightIntentFlag::GET_FULL_INSIGHT_INTENT));
    NAPI_CALL(env, SetEnumItem(
        env, napiObject, "GET_SUMMARY_INSIGHT_INTENT", GetInsightIntentFlag::GET_SUMMARY_INSIGHT_INTENT));

    return napiObject;
}

static napi_value InitInsightIntentTypeObject(napi_env env)
{
    napi_value napiObject;
    NAPI_CALL(env, napi_create_object(env, &napiObject));

    NAPI_CALL(env, SetEnumItem(env, napiObject, "LINK", "@InsightIntentLink"));
    NAPI_CALL(env, SetEnumItem(env, napiObject, "PAGE", "@InsightIntentPage"));
    NAPI_CALL(env, SetEnumItem(env, napiObject, "ENTRY", "@InsightIntentEntry"));
    NAPI_CALL(env, SetEnumItem(env, napiObject, "FUNCTION", "@InsightIntentFunctionMethod"));
    NAPI_CALL(env, SetEnumItem(env, napiObject, "FORM", "@InsightIntentForm"));

    return napiObject;
}

napi_value JsInsightIntentDriverInit(napi_env env, napi_value exportObj)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    if (env == nullptr || exportObj == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env or exportObj");
        return nullptr;
    }

    std::unique_ptr<JsInsightIntentDriver> jsIntentDriver = std::make_unique<JsInsightIntentDriver>();
    napi_wrap(env, exportObj, jsIntentDriver.release(), JsInsightIntentDriver::Finalizer, nullptr, nullptr);

    const char *moduleName = "JsInsightIntentDriver";
    BindNativeFunction(env, exportObj, "execute", moduleName, JsInsightIntentDriver::Execute);
    BindNativeFunction(env, exportObj,
        "getAllInsightIntentInfo", moduleName, JsInsightIntentDriver::GetAllInsightIntentInfo);
    BindNativeFunction(env, exportObj,
        "getInsightIntentInfoByBundleName", moduleName, JsInsightIntentDriver::GetInsightIntentInfoByBundleName);
    BindNativeFunction(env, exportObj,
        "getInsightIntentInfoByIntentName", moduleName, JsInsightIntentDriver::GetInsightIntentInfoByIntentName);
    napi_value getInsightIntentFlag = InitGetInsightIntentFlagObject(env);
    NAPI_ASSERT(env, getInsightIntentFlag != nullptr, "failed to create getInsightIntent flag object");
    napi_value insightIntentType = InitInsightIntentTypeObject(env);
    NAPI_ASSERT(env, insightIntentType != nullptr, "failed to create insightIntent type object");

    napi_property_descriptor exportObjs[] = {
        DECLARE_NAPI_PROPERTY("GetInsightIntentFlag", getInsightIntentFlag),
        DECLARE_NAPI_PROPERTY("InsightIntentType", insightIntentType),
    };
    napi_status status = napi_define_properties(env, exportObj, sizeof(exportObjs) / sizeof(exportObjs[0]), exportObjs);
    NAPI_ASSERT(env, status == napi_ok, "failed to define properties for exportObj");
    return CreateJsUndefined(env);
}
} // namespace AbilityRuntime
} // namespace OHOS
