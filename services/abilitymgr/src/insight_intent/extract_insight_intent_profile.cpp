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

#include "extract_insight_intent_profile.h"

#include "hilog_tag_wrapper.h"
#include "insight_intent_json_util.h"
#include "json_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
int32_t g_extraParseResult = ERR_OK;
std::mutex g_extraMutex;

const std::string INSIGHT_INTENTS = "extractInsightIntents";
const std::string INSIGHT_INTENT_NAME = "intentName";
const std::string INSIGHT_INTENT_DOMAIN = "domain";
const std::string INSIGHT_INTENT_VERSION = "intentVersion";
const std::string INSIGHT_INTENT_EXECUTE_MODE = "executeMode";
const std::string INSIGHT_INTENT_DECORETOR_FILE = "decoratorFile";
const std::string INSIGHT_INTENT_DECORETOR_CLASS = "decoratorClass";
const std::string INSIGHT_INTENT_DECORETOR_TYPE = "decoratorType";
const std::string INSIGHT_INTENT_BUNDLE_NAME = "bundleName";
const std::string INSIGHT_INTENT_MODULE_NAME = "moduleName";
const std::string INSIGHT_INTENT_DISPLAY_NAME = "displayName";
const std::string INSIGHT_INTENT_DISPLAY_DESCRIPTION = "displayDescription";
const std::string INSIGHT_INTENT_SCHEMA = "schema";
const std::string INSIGHT_INTENT_ICON = "icon";
const std::string INSIGHT_INTENT_LLM_DESCRIPTION = "llmDescription";
const std::string INSIGHT_INTENT_KEYWORDS = "keywords";
const std::string INSIGHT_INTENT_PARAMETERS = "parameters";
const std::string INSIGHT_INTENT_URI = "uri";
const std::string INSIGHT_INTENT_PARAM_MAPPING = "paramMappings";
const std::string INSIGHT_INTENT_UI_ABILITY = "uiAbility";
const std::string INSIGHT_INTENT_PAGE_ROUTE_NAME = "pagePath";
const std::string INSIGHT_INTENT_NAVIGATION_ID = "navigationId";
const std::string INSIGHT_INTENT_NAV_DESTINATION_NAME = "navDestinationName";
const std::string INSIGHT_INTENT_ABILITY_NAME = "abilityName";
const std::string INSIGHT_INTENT_FUNCTION_NAME = "functionName";
const std::string INSIGHT_INTENT_FUNCTION_PARAMS = "functionParamList";
const std::string INSIGHT_INTENT_PARAM_NAME = "paramName";
const std::string INSIGHT_INTENT_PARAM_MAPPING_NAME = "paramMappingName";
const std::string INSIGHT_INTENT_PARAM_CATEGORY = "paramCategory";
const std::string INSIGHT_INTENT_RESULT = "result";
const std::string INSIGHT_INTENT_EXAMPLE = "example";
const std::string INSIGHT_INTENT_FORM_NAME = "formName";
const std::string INSIGHT_INTENT_ENTITES = "entities";
const std::string INSIGHT_INTENT_ENTITY_DECORETOR_FILE = "decoratorFile";
const std::string INSIGHT_INTENT_ENTITY_CLASS_NAME = "className";
const std::string INSIGHT_INTENT_ENTITY_DECORETOR_TYPE = "decoratorType";
const std::string INSIGHT_INTENT_ENTITY_ID = "entityId";
const std::string INSIGHT_INTENT_ENTITY_CATEGORY = "entityCategory";
const std::string INSIGHT_INTENT_ENTITY_PARENT_CLASS_NAME = "parentClassName";
const std::string INSIGHT_INTENT_ENTITY_PARAMETERS = "parameters";

enum DecoratorType {
    DECORATOR_LINK = 0,
    DECORATOR_PAGE,
    DECORATOR_ENTRY,
    DECORATOR_FUNCTION,
    DECORATOR_FORM,
    DECORATOR_UNKNOWN
};

DecoratorType StringToEnum(const std::string& input)
{
    static const std::unordered_map<std::string, DecoratorType> mapping = {
        {AbilityRuntime::INSIGHT_INTENTS_DECORATOR_TYPE_LINK, DecoratorType::DECORATOR_LINK},
        {AbilityRuntime::INSIGHT_INTENTS_DECORATOR_TYPE_PAGE, DecoratorType::DECORATOR_PAGE},
        {AbilityRuntime::INSIGHT_INTENTS_DECORATOR_TYPE_ENTRY, DecoratorType::DECORATOR_ENTRY},
        {AbilityRuntime::INSIGHT_INTENTS_DECORATOR_TYPE_FUNCTION, DecoratorType::DECORATOR_FUNCTION},
        {AbilityRuntime::INSIGHT_INTENTS_DECORATOR_TYPE_FORM, DecoratorType::DECORATOR_FORM}
    };
    auto it = mapping.find(input);
    return (it != mapping.end()) ? it->second : DecoratorType::DECORATOR_UNKNOWN;
}

const std::map<std::string, ExecuteMode> executeModeMap = {
    {"foreground", ExecuteMode::UI_ABILITY_FOREGROUND},
    {"background", ExecuteMode::UI_ABILITY_BACKGROUND},
    {"uiextension", ExecuteMode::UI_EXTENSION_ABILITY},
    {"serviceextension", ExecuteMode::SERVICE_EXTENSION_ABILITY}
};
} // namespace

void from_json(const cJSON *jsonObject, LinkIntentParamProfileMapping &paramMapping)
{
    TAG_LOGD(AAFwkTag::INTENT, "LinkIntentParamProfileMapping from json");
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_PARAM_NAME, paramMapping.paramName, true, g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_PARAM_MAPPING_NAME, paramMapping.paramMappingName, false,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_PARAM_CATEGORY, paramMapping.paramCategory, false,
        g_extraParseResult);
}

void from_json(const cJSON *jsonObject, InsightIntentEntityInfo &entityInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "InsightIntentEntityInfo from json");
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ENTITY_DECORETOR_FILE, entityInfo.decoratorFile, true,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ENTITY_CLASS_NAME, entityInfo.className, true,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ENTITY_DECORETOR_TYPE, entityInfo.decoratorType, true,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ENTITY_ID, entityInfo.entityId, true, g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ENTITY_CATEGORY, entityInfo.entityCategory, true,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ENTITY_PARENT_CLASS_NAME, entityInfo.parentClassName, false,
        g_extraParseResult);
    
    cJSON *entityParametersItem = cJSON_GetObjectItem(jsonObject, INSIGHT_INTENT_ENTITY_PARAMETERS.c_str());
    if (entityParametersItem != nullptr) {
        if (cJSON_IsObject(entityParametersItem)) {
            entityInfo.parameters =  AAFwk::JsonUtils::GetInstance().ToString(entityParametersItem);
        } else {
            TAG_LOGE(AAFwkTag::INTENT, "type error: entity parameters not object");
            g_extraParseResult = ERR_INVALID_VALUE;
        }
    }
}

void from_json(const cJSON *jsonObject, ExtractInsightIntentProfileInfo &insightIntentInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "ExtractInsightIntentProfileInfo from json");
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_DECORETOR_FILE, insightIntentInfo.decoratorFile, true,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_DECORETOR_CLASS, insightIntentInfo.decoratorClass, true,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_DECORETOR_TYPE, insightIntentInfo.decoratorType, true,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_BUNDLE_NAME, insightIntentInfo.bundleName, true,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_MODULE_NAME, insightIntentInfo.moduleName, true,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_NAME, insightIntentInfo.intentName, true, g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_DOMAIN, insightIntentInfo.domain, true, g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_VERSION, insightIntentInfo.intentVersion, true,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_DISPLAY_NAME, insightIntentInfo.displayName, true,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_DISPLAY_DESCRIPTION, insightIntentInfo.displayDescription, false,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_SCHEMA, insightIntentInfo.schema, false, g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ICON, insightIntentInfo.icon, false, g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_LLM_DESCRIPTION, insightIntentInfo.llmDescription, false,
        g_extraParseResult);
    GetStringValuesIfFindKey(jsonObject, INSIGHT_INTENT_KEYWORDS, insightIntentInfo.keywords, false,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_EXAMPLE, insightIntentInfo.example, false, g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_URI, insightIntentInfo.uri, false, g_extraParseResult);
    GetObjectValuesIfFindKey(jsonObject, INSIGHT_INTENT_PARAM_MAPPING, insightIntentInfo.paramMapping, false,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_UI_ABILITY, insightIntentInfo.uiAbility, false,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_PAGE_ROUTE_NAME, insightIntentInfo.pagePath, false,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_NAVIGATION_ID, insightIntentInfo.navigationId, false,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_NAV_DESTINATION_NAME, insightIntentInfo.navDestinationName,
        false, g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ABILITY_NAME, insightIntentInfo.abilityName, false,
        g_extraParseResult);
    GetStringValuesIfFindKey(jsonObject, INSIGHT_INTENT_EXECUTE_MODE, insightIntentInfo.executeMode, false,
        g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_FUNCTION_NAME, insightIntentInfo.functionName, false,
        g_extraParseResult);
    GetStringValuesIfFindKey(jsonObject, INSIGHT_INTENT_FUNCTION_PARAMS, insightIntentInfo.functionParams, false,
        g_extraParseResult);
    GetObjectValuesIfFindKey(jsonObject, INSIGHT_INTENT_ENTITES, insightIntentInfo.entities, false, g_extraParseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_FORM_NAME, insightIntentInfo.formName, false,
        g_extraParseResult);

    cJSON *insightIntentParametersItem = cJSON_GetObjectItem(jsonObject, INSIGHT_INTENT_PARAMETERS.c_str());
    if (insightIntentParametersItem != nullptr) {
        if (cJSON_IsObject(insightIntentParametersItem)) {
            insightIntentInfo.parameters = AAFwk::JsonUtils::GetInstance().ToString(insightIntentParametersItem);
        } else {
            TAG_LOGE(AAFwkTag::INTENT, "type error: parameters not object");
            g_extraParseResult = ERR_INVALID_VALUE;
        }
    }

    cJSON *insightIntentResultItem = cJSON_GetObjectItem(jsonObject, INSIGHT_INTENT_RESULT.c_str());
    if (insightIntentResultItem != nullptr) {
        if (cJSON_IsObject(insightIntentResultItem)) {
            insightIntentInfo.result =  AAFwk::JsonUtils::GetInstance().ToString(insightIntentResultItem);
        } else {
            TAG_LOGE(AAFwkTag::INTENT, "type error: result not object");
            g_extraParseResult = ERR_INVALID_VALUE;
        }
    }
}

void from_json(const cJSON *jsonObject, ExtractInsightIntentProfileInfoVec &infos)
{
    GetObjectValuesIfFindKey(jsonObject, INSIGHT_INTENTS, infos.insightIntents, false, g_extraParseResult);
}

bool to_json(cJSON *&jsonObject, const LinkIntentParamProfileMapping &info)
{
    TAG_LOGI(AAFwkTag::INTENT, "call to link mapping");
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGI(AAFwkTag::INTENT, "create jsonObject failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_PARAM_NAME.c_str(), info.paramName.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_PARAM_MAPPING_NAME.c_str(), info.paramMappingName.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_PARAM_CATEGORY.c_str(), info.paramCategory.c_str());
    return true;
}

bool to_json(cJSON *&jsonObject, const InsightIntentEntityInfo &info)
{
    TAG_LOGI(AAFwkTag::INTENT, "InsightIntentEntityInfo to json");
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGI(AAFwkTag::INTENT, "create jsonObject failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ENTITY_DECORETOR_FILE.c_str(), info.decoratorFile.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ENTITY_CLASS_NAME.c_str(), info.className.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ENTITY_DECORETOR_TYPE.c_str(), info.decoratorType.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ENTITY_ID.c_str(), info.entityId.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ENTITY_CATEGORY.c_str(), info.entityCategory.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ENTITY_PARENT_CLASS_NAME.c_str(), info.parentClassName.c_str());

    if (!info.parameters.empty()) {
        cJSON *parametersItem = cJSON_Parse(info.parameters.c_str());
        if (parametersItem == nullptr) {
            TAG_LOGE(AAFwkTag::INTENT, "parse entity parameters failed");
            cJSON_Delete(jsonObject);
            return false;
        }
        cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_ENTITY_PARAMETERS.c_str(), parametersItem);
    }
    return true;
}

bool to_json(cJSON *&jsonObject, const ExtractInsightIntentProfileInfo& info)
{
    TAG_LOGI(AAFwkTag::INTENT, "ExtractInsightIntentProfileInfo to json");
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGI(AAFwkTag::INTENT, "create jsonObject failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_DECORETOR_FILE.c_str(), info.decoratorFile.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_DECORETOR_CLASS.c_str(), info.decoratorClass.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_DECORETOR_TYPE.c_str(), info.decoratorType.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_BUNDLE_NAME.c_str(), info.bundleName.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_MODULE_NAME.c_str(), info.moduleName.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_NAME.c_str(), info.intentName.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_DOMAIN.c_str(), info.domain.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_VERSION.c_str(), info.intentVersion.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_DISPLAY_NAME.c_str(), info.displayName.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_DISPLAY_DESCRIPTION.c_str(), info.displayDescription.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_SCHEMA.c_str(), info.schema.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ICON.c_str(), info.icon.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_LLM_DESCRIPTION.c_str(), info.llmDescription.c_str());

    cJSON *keywordsItem = nullptr;
    if (!to_json(keywordsItem, info.keywords)) {
        TAG_LOGI(AAFwkTag::INTENT, "to_json keywords failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_KEYWORDS.c_str(), keywordsItem);

    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_EXAMPLE.c_str(), info.example.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_URI.c_str(), info.uri.c_str());

    cJSON *paramMappingItem = nullptr;
    if (!to_json(paramMappingItem, info.paramMapping)) {
        TAG_LOGI(AAFwkTag::INTENT, "to_json paramMapping failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_PARAM_MAPPING.c_str(), paramMappingItem);

    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_UI_ABILITY.c_str(), info.uiAbility.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_PAGE_ROUTE_NAME.c_str(), info.pagePath.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_NAVIGATION_ID.c_str(), info.navigationId.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_NAV_DESTINATION_NAME.c_str(), info.navDestinationName.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ABILITY_NAME.c_str(), info.abilityName.c_str());
    
    cJSON *executeModeItem = nullptr;
    if (!to_json(executeModeItem, info.executeMode)) {
        TAG_LOGI(AAFwkTag::INTENT, "to_json executeMode failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_EXECUTE_MODE.c_str(), executeModeItem);

    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_FUNCTION_NAME.c_str(), info.functionName.c_str());

    cJSON *functionParamsItem = nullptr;
    if (!to_json(functionParamsItem, info.functionParams)) {
        TAG_LOGI(AAFwkTag::INTENT, "to_json functionParams failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_FUNCTION_PARAMS.c_str(), functionParamsItem);

    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_FORM_NAME.c_str(), info.formName.c_str());

    cJSON *entitiesItem = nullptr;
    if (!to_json(entitiesItem, info.entities)) {
        TAG_LOGI(AAFwkTag::INTENT, "to_json entities failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_ENTITES.c_str(), entitiesItem);

    if (!info.parameters.empty()) {
        cJSON *parametersItem = cJSON_Parse(info.parameters.c_str());
        if (parametersItem == nullptr) {
            TAG_LOGE(AAFwkTag::INTENT, "parameters error");
            cJSON_Delete(jsonObject);
            return false;
        }
        cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_PARAMETERS.c_str(), parametersItem);
    }

    if (!info.result.empty()) {
        cJSON *resultItem = cJSON_Parse(info.result.c_str());
        if (resultItem == nullptr) {
            TAG_LOGE(AAFwkTag::INTENT, "result error");
            cJSON_Delete(jsonObject);
            return false;
        }
        cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_RESULT.c_str(), resultItem);
    }

    return true;
}

bool CheckProfileSubIntentInfo(const ExtractInsightIntentProfileInfo &insightIntent)
{
    switch (StringToEnum(insightIntent.decoratorType)) {
        case DecoratorType::DECORATOR_LINK:
            if (insightIntent.uri.empty()) {
                TAG_LOGE(AAFwkTag::INTENT, "empty uri, intentName: %{public}s", insightIntent.intentName.c_str());
                return false;
            }
            for (const auto &paramMapping: insightIntent.paramMapping) {
                if (paramMapping.paramName.empty()) {
                    TAG_LOGE(AAFwkTag::INTENT, "empty paramName, intentName: %{public}s",
                             insightIntent.intentName.c_str());
                    return false;
                }
            }
            break;
        case DecoratorType::DECORATOR_PAGE:
            if (insightIntent.pagePath.empty()) {
                TAG_LOGE(AAFwkTag::INTENT, "empty pagePath, intentName: %{public}s",
                         insightIntent.intentName.c_str());
                return false;
            }
            break;
        case DecoratorType::DECORATOR_ENTRY:
            if (insightIntent.abilityName.empty()) {
                TAG_LOGE(AAFwkTag::INTENT, "empty abilityName, intentName: %{public}s",
                         insightIntent.intentName.c_str());
                return false;
            }
            break;
        case DecoratorType::DECORATOR_FUNCTION:
            if (insightIntent.functionName.empty()) {
                TAG_LOGE(AAFwkTag::INTENT, "empty functionName, intentName: %{public}s",
                         insightIntent.intentName.c_str());
                return false;
            }
            break;
        case DecoratorType::DECORATOR_FORM:
            if (insightIntent.formName.empty() || insightIntent.abilityName.empty()) {
                TAG_LOGE(AAFwkTag::INTENT, "empty formName or abilityName, intentName: %{public}s, "
                    "abilityName: %{public}s", insightIntent.intentName.c_str(), insightIntent.abilityName.c_str());
                return false;
            }
            break;
        default:
            TAG_LOGE(AAFwkTag::INTENT, "invalid decoratorType: %{public}s", insightIntent.decoratorType.c_str());
            return false;
    }

    return true;
}

bool CheckProfileInfo(const ExtractInsightIntentProfileInfo &insightIntent)
{
    if (insightIntent.decoratorFile.empty() || insightIntent.decoratorClass.empty() ||
        insightIntent.decoratorType.empty() || insightIntent.bundleName.empty() ||
        insightIntent.moduleName.empty() || insightIntent.intentName.empty() || insightIntent.domain.empty() ||
        insightIntent.intentVersion.empty() || insightIntent.displayName.empty()) {
        TAG_LOGE(AAFwkTag::INTENT, "exist empty param, decoratorFile: %{public}s, decoratorClass: %{public}s, "
            "decoratorType: %{public}s, bundleName: %{public}s, moduleName: %{public}s, intentName: %{public}s, "
            "domain: %{public}s, intentVersion: %{public}s, displayName: %{public}s",
            insightIntent.decoratorFile.c_str(), insightIntent.decoratorClass.c_str(),
            insightIntent.decoratorType.c_str(), insightIntent.bundleName.c_str(), insightIntent.moduleName.c_str(),
            insightIntent.intentName.c_str(), insightIntent.domain.c_str(), insightIntent.intentVersion.c_str(),
            insightIntent.displayName.c_str());
        return false;
    }

    for (const auto &entity: insightIntent.entities) {
        if (entity.className.empty() || entity.entityId.empty()) {
            TAG_LOGE(AAFwkTag::INTENT, "entity exist empty param, intentName: %{public}s, "
                "className: %{public}s, entityId: %{public}s",
                insightIntent.intentName.c_str(), entity.className.c_str(), entity.entityId.c_str());
            return false;
        }
    }

    return CheckProfileSubIntentInfo(insightIntent);
}

bool TransformToLinkInfo(const ExtractInsightIntentProfileInfo &insightIntent, InsightIntentLinkInfo &info)
{
    info.uri = insightIntent.uri;
    TAG_LOGD(AAFwkTag::INTENT, "uri: %{public}s", info.uri.c_str());
    for (std::vector<LinkIntentParamProfileMapping>::const_iterator iter = insightIntent.paramMapping.begin();
        iter != insightIntent.paramMapping.end(); iter++) {
        LinkIntentParamMapping paramMapping;
        paramMapping.paramName = (*iter).paramName;
        TAG_LOGD(AAFwkTag::INTENT, "paramName: %{public}s", paramMapping.paramName.c_str());
        paramMapping.paramMappingName = (*iter).paramMappingName;
        TAG_LOGD(AAFwkTag::INTENT, "paramMappingName: %{public}s", paramMapping.paramMappingName.c_str());
        paramMapping.paramCategory = (*iter).paramCategory;
        TAG_LOGD(AAFwkTag::INTENT, "paramCategory: %{public}s", paramMapping.paramCategory.c_str());

        info.paramMapping.push_back(paramMapping);
    }
    info.parameters = insightIntent.parameters;
    TAG_LOGD(AAFwkTag::INTENT, "link parameters: %{public}s", info.parameters.c_str());
    return true;
}

bool TransformToPageInfo(const ExtractInsightIntentProfileInfo &insightIntent, InsightIntentPageInfo &info)
{
    info.uiAbility = insightIntent.uiAbility;
    TAG_LOGD(AAFwkTag::INTENT, "uiAbility: %{public}s", info.uiAbility.c_str());
    info.pagePath = insightIntent.pagePath;
    TAG_LOGD(AAFwkTag::INTENT, "pagePath: %{public}s", info.pagePath.c_str());
    info.navigationId = insightIntent.navigationId;
    TAG_LOGD(AAFwkTag::INTENT, "navigationId: %{public}s", info.navigationId.c_str());
    info.navDestinationName = insightIntent.navDestinationName;
    TAG_LOGD(AAFwkTag::INTENT, "navDestinationName: %{public}s", info.navDestinationName.c_str());
    info.parameters = insightIntent.parameters;
    TAG_LOGD(AAFwkTag::INTENT, "page parameters: %{public}s", info.parameters.c_str());
    return true;
}

bool TransformToEntryInfo(const ExtractInsightIntentProfileInfo &insightIntent, InsightIntentEntryInfo &info)
{
    info.abilityName = insightIntent.abilityName;
    for (const auto &executeMode: insightIntent.executeMode) {
        auto mode = std::find_if(std::begin(executeModeMap), std::end(executeModeMap),
            [&executeMode](const auto &item) {
                return item.first == executeMode;
            });
        if (mode == executeModeMap.end()) {
            TAG_LOGW(AAFwkTag::INTENT, "not support execute mode: %{public}s", executeMode.c_str());
            continue;
        }
        info.executeMode.emplace_back(mode->second);
        TAG_LOGI(AAFwkTag::INTENT, "mode: %{public}s", mode->first.c_str());
    }
    info.parameters = insightIntent.parameters;
    TAG_LOGD(AAFwkTag::INTENT, "entry parameters: %{public}s", info.parameters.c_str());
    return true;
}

bool TransformToFunctionInfo(const ExtractInsightIntentProfileInfo &insightIntent, InsightIntentFunctionInfo &info)
{
    info.functionName = insightIntent.functionName;
    TAG_LOGD(AAFwkTag::INTENT, "functionName: %{public}s", info.functionName.c_str());
    info.functionParams.assign(insightIntent.functionParams.begin(), insightIntent.functionParams.end());
    for (size_t i = 0; i < info.functionParams.size(); i++) {
        TAG_LOGD(AAFwkTag::INTENT, "functionParams[%{public}zu]: %{public}s", i, info.functionParams[i].c_str());
    }
    info.parameters = insightIntent.parameters;
    TAG_LOGD(AAFwkTag::INTENT, "function parameters: %{public}s", info.parameters.c_str());
    return true;
}

bool TransformToFormInfo(const ExtractInsightIntentProfileInfo &insightIntent, InsightIntentFormInfo &info)
{
    info.abilityName = insightIntent.abilityName;
    info.formName = insightIntent.formName;
    info.parameters = insightIntent.parameters;
    TAG_LOGD(AAFwkTag::INTENT, "form parameters: %{public}s", info.parameters.c_str());
    return true;
}

bool ExtractInsightIntentProfile::TransformTo(const std::string &profileStr,
    ExtractInsightIntentProfileInfoVec &intentInfos)
{
    TAG_LOGD(AAFwkTag::INTENT, "transform profileStr: %{public}s", profileStr.c_str());
    cJSON *jsonObject = cJSON_Parse(profileStr.c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "parse jsonObject failed, profileStr: %{public}s", profileStr.c_str());
        return false;
    }

    std::lock_guard<std::mutex> lock(g_extraMutex);
    g_extraParseResult = ERR_OK;
    from_json(jsonObject, intentInfos);
    cJSON_Delete(jsonObject);
    if (g_extraParseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "parse result: %{public}d, profileStr: %{public}s",
            g_extraParseResult, profileStr.c_str());
        g_extraParseResult = ERR_OK;
        return false;
    }

    for (const auto &insightIntent : intentInfos.insightIntents) {
        if (!CheckProfileInfo(insightIntent)) {
            return false;
        }
    }

    TAG_LOGI(AAFwkTag::INTENT, "transform success, size: %{public}zu", intentInfos.insightIntents.size());
    return true;
}

bool ExtractInsightIntentProfile::ToJson(const ExtractInsightIntentProfileInfo &info, cJSON *&jsonObject)
{
    TAG_LOGD(AAFwkTag::INTENT, "to json");
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGD(AAFwkTag::INTENT, "create json object failed");
        return false;
    }
    cJSON *subJsonObject = nullptr;
    if (!to_json(subJsonObject, info)) {
        TAG_LOGD(AAFwkTag::INTENT, "to_json extractInsightIntentProfileInfo failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON *jsonArray = cJSON_CreateArray();
    if (jsonArray == nullptr) {
        cJSON_Delete(subJsonObject);
        cJSON_Delete(jsonObject);
        jsonObject = nullptr;
        return false;
    }
    cJSON_AddItemToArray(jsonArray, subJsonObject);
    cJSON_AddItemToObject(jsonObject, INSIGHT_INTENTS.c_str(), jsonArray);

    std::string jsonStr = AAFwk::JsonUtils::GetInstance().ToString(jsonObject);
    TAG_LOGD(AAFwkTag::INTENT, "to json string: %{public}s", jsonStr.c_str());
    return true;
}

bool ExtractInsightIntentProfile::ProfileInfoFormat(const ExtractInsightIntentProfileInfo &insightIntent,
    ExtractInsightIntentInfo &info)
{
    bool ret = false;
    if (!CheckProfileInfo(insightIntent)) {
        return false;
    }

    info.decoratorFile = insightIntent.decoratorFile;
    info.decoratorClass = insightIntent.decoratorClass;
    info.displayDescription = insightIntent.displayDescription;
    info.domain = insightIntent.domain;
    info.intentVersion = insightIntent.intentVersion;
    info.schema = insightIntent.schema;
    info.icon = insightIntent.icon;
    info.llmDescription = insightIntent.llmDescription;
    info.example = insightIntent.example;
    info.result = insightIntent.result;
    info.keywords.assign(insightIntent.keywords.begin(), insightIntent.keywords.end());
    info.entities = insightIntent.entities;
    TAG_LOGD(AAFwkTag::INTENT, "entities size: %{public}zu", info.entities.size());
    for (auto iter = info.entities.begin(); iter != info.entities.end(); iter++) {
        TAG_LOGD(AAFwkTag::INTENT, "entity decoratorFile: %{public}s, className: %{public}s, "
            "decoratorType: %{public}s, entityId: %{public}s, entityCategory: %{public}s, "
            "parentClassName: %{public}s, parameters: %{public}s",
            (*iter).decoratorFile.c_str(), (*iter).className.c_str(), (*iter).decoratorType.c_str(),
            (*iter).entityId.c_str(), (*iter).entityCategory.c_str(), (*iter).parentClassName.c_str(),
            (*iter).parameters.c_str());
    }

    info.genericInfo.bundleName = insightIntent.bundleName;
    TAG_LOGD(AAFwkTag::INTENT, "bundleName: %{public}s", info.genericInfo.bundleName.c_str());
    info.genericInfo.moduleName = insightIntent.moduleName;
    TAG_LOGD(AAFwkTag::INTENT, "moduleName: %{public}s", info.genericInfo.moduleName.c_str());
    info.genericInfo.intentName = insightIntent.intentName;
    TAG_LOGD(AAFwkTag::INTENT, "intentName: %{public}s", info.genericInfo.intentName.c_str());
    info.genericInfo.displayName = insightIntent.displayName;
    TAG_LOGD(AAFwkTag::INTENT, "displayName: %{public}s", info.genericInfo.displayName.c_str());
    info.genericInfo.decoratorType = insightIntent.decoratorType;
    TAG_LOGD(AAFwkTag::INTENT, "decoratorType: %{public}s", info.genericInfo.decoratorType.c_str());

    switch (StringToEnum(insightIntent.decoratorType)) {
        case DecoratorType::DECORATOR_LINK:
            ret = TransformToLinkInfo(insightIntent, info.genericInfo.get<InsightIntentLinkInfo>());
            break;
        case DecoratorType::DECORATOR_PAGE:
            ret = TransformToPageInfo(insightIntent, info.genericInfo.get<InsightIntentPageInfo>());
            break;
        case DecoratorType::DECORATOR_ENTRY:
            ret = TransformToEntryInfo(insightIntent, info.genericInfo.get<InsightIntentEntryInfo>());
            break;
        case DecoratorType::DECORATOR_FUNCTION:
            ret = TransformToFunctionInfo(insightIntent, info.genericInfo.get<InsightIntentFunctionInfo>());
            break;
        case DecoratorType::DECORATOR_FORM:
            ret = TransformToFormInfo(insightIntent, info.genericInfo.get<InsightIntentFormInfo>());
            break;
        default:
            TAG_LOGE(AAFwkTag::INTENT, "invalid decoratorType: %{public}s", insightIntent.decoratorType.c_str());
            return false;
    }

    return ret;
}
} // namespace AbilityRuntime
} // namespace OHOS
