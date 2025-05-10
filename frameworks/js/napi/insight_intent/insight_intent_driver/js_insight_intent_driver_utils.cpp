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

napi_value CreateLinkInfoForBack(napi_env env, const LinkInfoForBack &info)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    napi_set_named_property(env, objValue, "uri", CreateJsValue(env, info.uri));
    return objValue;
}

napi_value CreatePageInfoForBack(napi_env env, const PageInfoForBack &info)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    napi_set_named_property(env, objValue, "uiAbility", CreateJsValue(env, info.uiAbility));
    napi_set_named_property(env, objValue, "pageRouterName", CreateJsValue(env, info.pageRouterName));
    napi_set_named_property(env, objValue, "navigationId", CreateJsValue(env, info.navigationId));
    napi_set_named_property(env, objValue, "navDestination", CreateJsValue(env, info.navDestination));
    return objValue;
}

napi_value CreateEntryInfoForBack(napi_env env, const EntryInfoForBack &info)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    napi_set_named_property(env, objValue, "abilityName", CreateJsValue(env, info.abilityName));
    napi_set_named_property(env, objValue, "executeMode", CreateNativeArray(env, info.executeMode));
    return objValue;
}

napi_value CreateFunctionInfoForBack(napi_env env, const FunctionInfoForBack &info)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    return objValue;
}

napi_value CreateFormInfoForBack(napi_env env, const FormInfoForBack &info)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    return objValue;
}

napi_value CreateInsightIntentInfoParamWithJson(napi_env env, const nlohmann::json &jsonObject)
{
    if (jsonObject.is_object()) {
        napi_value objValue = nullptr;
        napi_create_object(env, &objValue);
        for (const auto &it: jsonObject.items()) {
            if (it.value().is_object() || it.value().is_array()) {
                napi_set_named_property(
                    env, objValue, it.key().c_str(), CreateInsightIntentInfoParamWithJson(env, it.value()));
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
                napi_set_element(env, arrayValue, index++, CreateInsightIntentInfoParamWithJson(env, it));
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
    nlohmann::json jsonObject = nlohmann::json::parse(paramStr, nullptr, false);
    if (jsonObject.is_discarded()) {
        TAG_LOGE(AAFwkTag::INTENT, "Parse param str fail");
        return nullptr;
    }
    return CreateInsightIntentInfoParamWithJson(env, jsonObject);
}

napi_value CreateInsightIntentInfoForBack(napi_env env, const InsightIntentInfoForBack &info)
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
    napi_set_named_property(env, objValue, "keywords", CreateNativeArray(env, info.keywords));
    if (info.intentType == INSIGHT_INTENTS_TYPE_LINK) {
        napi_set_named_property(env, objValue, "subIntentInfo", CreateLinkInfoForBack(env, info.linkInfo));
    } else if (info.intentType == INSIGHT_INTENTS_TYPE_PAGE) {
        napi_set_named_property(env, objValue, "subIntentInfo", CreatePageInfoForBack(env, info.pageInfo));
    } else if (info.intentType == INSIGHT_INTENTS_TYPE_ENTRY) {
        napi_set_named_property(env, objValue, "subIntentInfo", CreateEntryInfoForBack(env, info.entryInfo));
    } else if (info.intentType == INSIGHT_INTENTS_TYPE_FUNCTION) {
        napi_set_named_property(env, objValue, "subIntentInfo", CreateFunctionInfoForBack(env, info.functionInfo));
    } else if (info.intentType == INSIGHT_INTENTS_TYPE_FORM) {
        napi_set_named_property(env, objValue, "subIntentInfo", CreateFormInfoForBack(env, info.formInfo));
    } else {
        napi_value objVal = nullptr;
        napi_create_object(env, &objValue);
        napi_set_named_property(env, objValue, "subIntentInfo", objVal);
    }
    return objValue;
}

napi_value CreateInsightIntentInfoForBackArray(napi_env env, const std::vector<InsightIntentInfoForBack> &infos)
{
    napi_value arrayValue = nullptr;
    napi_create_array_with_length(env, infos.size(), &arrayValue);
    uint32_t index = 0;
    for (const auto &info : infos) {
        napi_set_element(env, arrayValue, index++, CreateInsightIntentInfoForBack(env, info));
    }
    return arrayValue;
}
} // namespace AbilityRuntime
} // namespace OHOS
