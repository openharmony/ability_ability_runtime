/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "js_insight_intent_driver_utils.h"

#include <cstdint>

#include "ability_state.h"
#include "napi_common_want.h"
#include "napi_remote_object.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
napi_value CreateJsExecuteResult(napi_env env, const AppExecFwk::InsightIntentExecuteResult &result)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);

    napi_set_named_property(env, objValue, "code", CreateJsValue(env, result.code));
    if (result.result != nullptr) {
        napi_set_named_property(env, objValue, "result",
            OHOS::AppExecFwk::CreateJsWantParams(env, *result.result));
    }
    if (result.uris.size() > 0) {
        napi_set_named_property(env, objValue, "uris", CreateNativeArray(env, result.uris));
    }
    napi_set_named_property(env, objValue, "flags", CreateJsValue(env, result.flags));
    return objValue;
}

napi_value CreateLinkInfoForQuery(napi_env env, const LinkInfoForQuery &info)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    napi_set_named_property(env, objValue, "uri", CreateJsValue(env, info.uri));
    return objValue;
}

napi_value CreatePageInfoForQuery(napi_env env, const PageInfoForQuery &info)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    napi_set_named_property(env, objValue, "uiAbility", CreateJsValue(env, info.uiAbility));
    napi_set_named_property(env, objValue, "pagePath", CreateJsValue(env, info.pagePath));
    napi_set_named_property(env, objValue, "navigationId", CreateJsValue(env, info.navigationId));
    napi_set_named_property(env, objValue, "navDestinationName", CreateJsValue(env, info.navDestinationName));
    return objValue;
}

napi_value CreateEntryInfoForQuery(napi_env env, const EntryInfoForQuery &info)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    napi_set_named_property(env, objValue, "abilityName", CreateJsValue(env, info.abilityName));
    napi_set_named_property(env, objValue, "executeMode", CreateNativeArray(env, info.executeMode));
    return objValue;
}

napi_value CreateFunctionInfoForQuery(napi_env env, const FunctionInfoForQuery &info)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    return objValue;
}

napi_value CreateFormInfoForQuery(napi_env env, const FormInfoForQuery &info)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    return objValue;
}

napi_value CreateInsightIntentInfoWithJson(napi_env env, const nlohmann::json &jsonObject)
{
    if (jsonObject.is_object()) {
        napi_value objValue = nullptr;
        napi_create_object(env, &objValue);
        for (const auto &it: jsonObject.items()) {
            if (it.value().is_object() || it.value().is_array()) {
                napi_set_named_property(
                    env, objValue, it.key().c_str(), CreateInsightIntentInfoWithJson(env, it.value()));
            } else if (it.value().is_string()) {
                napi_set_named_property(
                    env, objValue, it.key().c_str(), CreateJsValue(env, it.value().get<std::string>()));
            } else if (it.value().is_boolean()) {
                napi_set_named_property(
                    env, objValue, it.key().c_str(), CreateJsValue(env, it.value().get<bool>()));
            } else if (it.value().is_number()) {
                napi_set_named_property(
                    env, objValue, it.key().c_str(), CreateJsValue(env, it.value().get<double>()));
            }
        }
        return objValue;
    } else if (jsonObject.is_array()) {
        napi_value arrayValue = nullptr;
        napi_create_array_with_length(env, jsonObject.size(), &arrayValue);
        uint32_t index = 0;
        for (const auto &it: jsonObject) {
            if (it.is_object() || it.is_array()) {
                napi_set_element(env, arrayValue, index++, CreateInsightIntentInfoWithJson(env, it));
            } else if (it.is_string()) {
                napi_set_element(env, arrayValue, index++, CreateJsValue(env, it.get<std::string>()));
            } else if (it.is_boolean()) {
                napi_set_element(env, arrayValue, index++, CreateJsValue(env, it.get<bool>()));
            } else if (it.is_number()) {
                napi_set_element(env, arrayValue, index++, CreateJsValue(env, it.get<double>()));
            }
        }
        return arrayValue;
    }
    TAG_LOGE(AAFwkTag::INTENT, "Creat js param fail");
    return nullptr;
}

napi_value CreateInsightIntentInfoParam(napi_env env, const std::string &paramStr)
{
    if (paramStr.empty()) {
        TAG_LOGD(AAFwkTag::INTENT, "paramStr empty");
        return nullptr;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(paramStr, nullptr, false);
    if (jsonObject.is_discarded()) {
        TAG_LOGE(AAFwkTag::INTENT, "Parse param str fail");
        return nullptr;
    }
    return CreateInsightIntentInfoWithJson(env, jsonObject);
}

napi_value CreateInsightIntentInfoResult(napi_env env, const std::string &resultStr)
{
    if (resultStr.empty()) {
        TAG_LOGD(AAFwkTag::INTENT, "resultStr empty");
        return nullptr;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(resultStr, nullptr, false);
    if (jsonObject.is_discarded()) {
        TAG_LOGE(AAFwkTag::INTENT, "Parse result str fail");
        return nullptr;
    }
    return CreateInsightIntentInfoWithJson(env, jsonObject);
}

napi_value CreateInsightIntentInfoForQuery(napi_env env, const InsightIntentInfoForQuery &info)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    napi_set_named_property(env, objValue, "bundleName", CreateJsValue(env, info.bundleName));
    napi_set_named_property(env, objValue, "moduleName", CreateJsValue(env, info.moduleName));
    napi_set_named_property(env, objValue, "intentName", CreateJsValue(env, info.intentName));
    napi_set_named_property(env, objValue, "domain", CreateJsValue(env, info.domain));
    napi_set_named_property(env, objValue, "intentVersion", CreateJsValue(env, info.intentVersion));
    napi_set_named_property(env, objValue, "displayName", CreateJsValue(env, info.displayName));
    napi_set_named_property(env, objValue, "displayDescription", CreateJsValue(env, info.displayDescription));
    napi_set_named_property(env, objValue, "schema", CreateJsValue(env, info.schema));
    napi_set_named_property(env, objValue, "icon", CreateJsValue(env, info.icon));
    napi_set_named_property(env, objValue, "llmDescription", CreateJsValue(env, info.llmDescription));
    napi_set_named_property(env, objValue, "intentType", CreateJsValue(env, info.intentType));
    napi_set_named_property(env, objValue, "parameters", CreateInsightIntentInfoParam(env, info.parameters));
    napi_set_named_property(env, objValue, "result", CreateInsightIntentInfoResult(env, info.result));
    napi_set_named_property(env, objValue, "keywords", CreateNativeArray(env, info.keywords));
    if (info.intentType == INSIGHT_INTENTS_TYPE_LINK) {
        napi_set_named_property(env, objValue, "subIntentInfo", CreateLinkInfoForQuery(env, info.linkInfo));
    } else if (info.intentType == INSIGHT_INTENTS_TYPE_PAGE) {
        napi_set_named_property(env, objValue, "subIntentInfo", CreatePageInfoForQuery(env, info.pageInfo));
    } else if (info.intentType == INSIGHT_INTENTS_TYPE_ENTRY) {
        napi_set_named_property(env, objValue, "subIntentInfo", CreateEntryInfoForQuery(env, info.entryInfo));
    } else if (info.intentType == INSIGHT_INTENTS_TYPE_FUNCTION) {
        napi_set_named_property(env, objValue, "subIntentInfo", CreateFunctionInfoForQuery(env, info.functionInfo));
    } else if (info.intentType == INSIGHT_INTENTS_TYPE_FORM) {
        napi_set_named_property(env, objValue, "subIntentInfo", CreateFormInfoForQuery(env, info.formInfo));
    } else {
        napi_value objVal = nullptr;
        napi_create_object(env, &objValue);
        napi_set_named_property(env, objValue, "subIntentInfo", objVal);
    }
    return objValue;
}

napi_value CreateInsightIntentInfoForQueryArray(napi_env env, const std::vector<InsightIntentInfoForQuery> &infos)
{
    napi_value arrayValue = nullptr;
    napi_create_array_with_length(env, infos.size(), &arrayValue);
    uint32_t index = 0;
    for (const auto &info : infos) {
        napi_set_element(env, arrayValue, index++, CreateInsightIntentInfoForQuery(env, info));
    }
    return arrayValue;
}
} // namespace AbilityRuntime
} // namespace OHOS
