/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "hilog_tag_wrapper.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi_common_want.h"
#include "napi_remote_object.h"

namespace OHOS {
namespace AbilityRuntime {
napi_value CreateJsExecuteResult(napi_env env, const AppExecFwk::InsightIntentExecuteResult &result)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    if (result.isDecorator) {
        return result.result ? OHOS::AppExecFwk::CreateJsWantParams(env, *result.result) : objValue;
    }

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
    napi_set_named_property(env, objValue, "abilityName", CreateJsValue(env, info.abilityName));
    napi_set_named_property(env, objValue, "formName", CreateJsValue(env, info.formName));
    return objValue;
}

napi_value CreateEntityInfoForArray(napi_env env, const std::vector<EntityInfoForQuery> &infos)
{
    napi_value arrayValue = nullptr;
    napi_status status = napi_create_array_with_length(env, infos.size(), &arrayValue);
    if (status != napi_ok) {
        return nullptr;
    }
    uint32_t index = 0;
    for (const auto &info : infos) {
        napi_value entityInfoObj = CreateJsEntityInfo(env, info);
        NAPI_CALL(env, napi_set_element(env, arrayValue, index++, entityInfoObj));
    }

    return arrayValue;
}

napi_value CreateJsEntityInfo(napi_env env, const EntityInfoForQuery &info)
{
    napi_value objValue = nullptr;
    NAPI_CALL(env, napi_create_object(env, &objValue));
    if (objValue == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null obj");
        return nullptr;
    }

    napi_set_named_property(env, objValue, "className", CreateJsValue(env, info.className));
    napi_set_named_property(env, objValue, "entityId", CreateJsValue(env, info.entityId));
    napi_set_named_property(env, objValue, "entityCategory", CreateJsValue(env, info.entityCategory));
    napi_set_named_property(env, objValue, "parameters", CreateInsightIntentInfoParam(env, info.parameters));
    napi_set_named_property(env, objValue, "parentClassName", CreateJsValue(env, info.parentClassName));

    return objValue;
}

napi_value CreateInsightIntentInfoWithJson(napi_env env, const cJSON *jsonObject)
{
    if (cJSON_IsObject(jsonObject)) {
        napi_value objValue = nullptr;
        napi_create_object(env, &objValue);
        cJSON *childItem = jsonObject->child;
        while (childItem != nullptr) {
            std::string key = childItem->string == nullptr ? "" : childItem->string;
            if (cJSON_IsObject(childItem) || cJSON_IsArray(childItem)) {
                napi_set_named_property(
                    env, objValue, key.c_str(), CreateInsightIntentInfoWithJson(env, childItem));
            } else if (cJSON_IsString(childItem)) {
                std::string value = childItem->valuestring;
                napi_set_named_property(env, objValue, key.c_str(), CreateJsValue(env, value));
            } else if (cJSON_IsBool(childItem)) {
                bool value = childItem->type == cJSON_True;
                napi_set_named_property(env, objValue, key.c_str(), CreateJsValue(env, value));
            } else if (cJSON_IsNumber(childItem)) {
                napi_set_named_property(env, objValue, key.c_str(), CreateJsValue(env, childItem->valuedouble));
            }
            childItem = childItem->next;
        }
        return objValue;
    } else if (cJSON_IsArray(jsonObject)) {
        napi_value arrayValue = nullptr;
        int size = cJSON_GetArraySize(jsonObject);
        napi_create_array_with_length(env, size, &arrayValue);
        uint32_t index = 0;
        for (int i = 0; i < size; i++) {
            cJSON *item = cJSON_GetArrayItem(jsonObject, i);
            if (item == nullptr) {
                continue;
            }
            if (cJSON_IsObject(item) || cJSON_IsArray(item)) {
                napi_set_element(env, arrayValue, index++, CreateInsightIntentInfoWithJson(env, item));
            } else if (cJSON_IsString(item)) {
                std::string value = item->valuestring;
                napi_set_element(env, arrayValue, index++, CreateJsValue(env, value));
            } else if (cJSON_IsBool(item)) {
                bool value = item->type == cJSON_True;
                napi_set_element(env, arrayValue, index++, CreateJsValue(env, value));
            } else if (cJSON_IsNumber(item)) {
                napi_set_element(env, arrayValue, index++, CreateJsValue(env, item->valuedouble));
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
    cJSON *jsonObject = cJSON_Parse(paramStr.c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "Parse param str fail");
        return nullptr;
    }
    napi_value result = CreateInsightIntentInfoWithJson(env, jsonObject);
    cJSON_Delete(jsonObject);
    return result;
}

napi_value CreateInsightIntentInfoResult(napi_env env, const std::string &resultStr)
{
    if (resultStr.empty()) {
        TAG_LOGD(AAFwkTag::INTENT, "resultStr empty");
        return nullptr;
    }
    cJSON *jsonObject = cJSON_Parse(resultStr.c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "Parse result str fail");
        return nullptr;
    }
    napi_value result = CreateInsightIntentInfoWithJson(env, jsonObject);
    cJSON_Delete(jsonObject);
    return result;
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
    napi_set_named_property(env, objValue, "entities", CreateEntityInfoForArray(env, info.entities));
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
