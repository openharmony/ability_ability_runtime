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

#include "insight_intent_info_for_query.h"

#include "hilog_tag_wrapper.h"
#include "insight_intent_json_util.h"
#include "json_utils.h"
#include "string_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
int32_t g_parseResult = ERR_OK;
std::mutex g_extraMutex;

const std::map<AppExecFwk::ExecuteMode, std::string> EXECUTE_MODE_STRING_MAP = {
    {AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND, "UI_ABILITY_FOREGROUND"},
    {AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND, "UI_ABILITY_BACKGROUND"},
    {AppExecFwk::ExecuteMode::UI_EXTENSION_ABILITY, "UI_EXTENSION_ABILITY"},
    {AppExecFwk::ExecuteMode::SERVICE_EXTENSION_ABILITY, "SERVICE_EXTENSION_ABILITY"}
};
const std::map<std::string, AppExecFwk::ExecuteMode> STRING_EXECUTE_MODE_MAP = {
    {"UI_ABILITY_FOREGROUND", AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND},
    {"UI_ABILITY_BACKGROUND", AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND},
    {"UI_EXTENSION_ABILITY", AppExecFwk::ExecuteMode::UI_EXTENSION_ABILITY},
    {"SERVICE_EXTENSION_ABILITY", AppExecFwk::ExecuteMode::SERVICE_EXTENSION_ABILITY}
};
}

void from_json(const cJSON *jsonObject, LinkInfoForQuery &linkInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "LinkInfoForQuery from json");
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENTS_URI, linkInfo.uri, true, g_parseResult);
}

bool to_json(cJSON *&jsonObject, const LinkInfoForQuery &info)
{
    TAG_LOGD(AAFwkTag::INTENT, "LinkInfoForQuery to json");
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENTS_URI, info.uri.c_str());
    return true;
}

void from_json(const cJSON *jsonObject, PageInfoForQuery &pageInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "PageInfoForQuery from json");
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_UI_ABILITY, pageInfo.uiAbility, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_PAGE_PATH, pageInfo.pagePath, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_NAVIGATION_ID, pageInfo.navigationId, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_NAV_DESTINATION_NAME, pageInfo.navDestinationName, true,
        g_parseResult);
}

bool to_json(cJSON *&jsonObject, const PageInfoForQuery &info)
{
    TAG_LOGD(AAFwkTag::INTENT, "PageInfoForQuery to json");
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_UI_ABILITY, info.uiAbility.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_PAGE_PATH, info.pagePath.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_NAVIGATION_ID, info.navigationId.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_NAV_DESTINATION_NAME, info.navDestinationName.c_str());
    return true;
}

void GetExecuteModesFromJson(const cJSON *jsonObject, std::vector<AppExecFwk::ExecuteMode> executeModes)
{
    if (jsonObject == nullptr || !cJSON_IsArray(jsonObject)) {
        return;
    }
    int size = cJSON_GetArraySize(jsonObject);
    for (int i = 0; i < size; i++) {
        cJSON *modeItem = cJSON_GetArrayItem(jsonObject, i);
        if (modeItem != nullptr && cJSON_IsString(modeItem)) {
            std::string modeStr = modeItem->valuestring;
            auto it = STRING_EXECUTE_MODE_MAP.find(modeStr);
            if (it != STRING_EXECUTE_MODE_MAP.end()) {
                executeModes.push_back(it->second);
            } else {
                TAG_LOGW(AAFwkTag::INTENT, "Unknown ExecuteMode: %{public}s", modeStr.c_str());
            }
        } else {
            TAG_LOGW(AAFwkTag::INTENT, "ExecuteMode is null or not string type");
        }
    }
}

void from_json(const cJSON *jsonObject, EntryInfoForQuery &entryInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "EntryInfoForQuery from json");
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ABILITY_NAME, entryInfo.abilityName, true, g_parseResult);
    cJSON *executeModeItem = cJSON_GetObjectItem(jsonObject, INSIGHT_INTENT_EXECUTE_MODE);
    if (executeModeItem != nullptr && cJSON_IsArray(executeModeItem)) {
        GetExecuteModesFromJson(executeModeItem, entryInfo.executeMode);
    }
}

bool to_json(cJSON *&jsonObject, const EntryInfoForQuery &info)
{
    TAG_LOGD(AAFwkTag::INTENT, "EntryInfoForQuery to json");
    std::vector<std::string> modeStrings;
    for (const auto &mode : info.executeMode) {
        auto it = EXECUTE_MODE_STRING_MAP.find(mode);
        if (it != EXECUTE_MODE_STRING_MAP.end()) {
            modeStrings.push_back(it->second);
        } else {
            modeStrings.push_back("UNKNOWN");
        }
    }
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ABILITY_NAME, info.abilityName.c_str());
    cJSON *modeItem = nullptr;
    if (!to_json(modeItem, modeStrings)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_EXECUTE_MODE, modeItem);
    return true;
}

void from_json(const cJSON *jsonObject, FormInfoForQuery &formInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "FormInfoForQuery from json");
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ABILITY_NAME, formInfo.abilityName, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_FORM_NAME, formInfo.formName, true, g_parseResult);
}

bool to_json(cJSON *&jsonObject, const FormInfoForQuery &info)
{
    TAG_LOGD(AAFwkTag::INTENT, "FormInfoForQuery to json");
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ABILITY_NAME, info.abilityName.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_FORM_NAME, info.formName.c_str());
    return true;
}

void from_json(const cJSON *jsonObject, EntityInfoForQuery &entityInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "EntityInfoForQuery from json");
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ENTITY_CLASS_NAME, entityInfo.className, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ENTITY_ID, entityInfo.entityId, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ENTITY_CATEGORY, entityInfo.entityCategory, false,
        g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ENTITY_PARAMETERS, entityInfo.parameters, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ENTITY_PARENT_CLASS_NAME, entityInfo.parentClassName, false,
        g_parseResult);
}

bool to_json(cJSON *&jsonObject, const EntityInfoForQuery &info)
{
    TAG_LOGD(AAFwkTag::INTENT, "EntityInfoForQuery to json");
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ENTITY_CLASS_NAME, info.className.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ENTITY_ID, info.entityId.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ENTITY_CATEGORY, info.entityCategory.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_PARAMETERS, info.parameters.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ENTITY_PARENT_CLASS_NAME, info.parentClassName.c_str());
    return true;
}

void from_json(const cJSON *jsonObject, InsightIntentInfoForQuery &insightIntentInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "InsightIntentInfoForQuery from json");
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_BUNDLE_NAME, insightIntentInfo.bundleName, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_MODULE_NAME, insightIntentInfo.moduleName, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_INTENT_NAME, insightIntentInfo.intentName, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_DOMAIN, insightIntentInfo.domain, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_INTENT_VERSION, insightIntentInfo.intentVersion, true,
        g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_DISPLAY_NAME, insightIntentInfo.displayName, true,
        g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_DISPLAY_DESCRIPTION, insightIntentInfo.displayDescription, false,
        g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_SCHEMA, insightIntentInfo.schema, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_ICON, insightIntentInfo.icon, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_LLM_DESCRIPTION, insightIntentInfo.llmDescription, false,
        g_parseResult);
    GetObjectValuesIfFindKey(jsonObject, INSIGHT_INTENT_ENTITY_INFO, insightIntentInfo.entities, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_INTENT_TYPE, insightIntentInfo.intentType, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_PARAMETERS, insightIntentInfo.parameters, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, INSIGHT_INTENT_RESULT, insightIntentInfo.result, false, g_parseResult);
    GetStringValuesIfFindKey(jsonObject, INSIGHT_INTENT_KEYWORDS, insightIntentInfo.keywords, false, g_parseResult);

    if (insightIntentInfo.intentType == INSIGHT_INTENTS_TYPE_LINK) {
        GetObjectValueIfFindKey(jsonObject, INSIGHT_INTENT_LINK_INFO, insightIntentInfo.linkInfo, false, g_parseResult);
    } else if (insightIntentInfo.intentType == INSIGHT_INTENTS_TYPE_PAGE) {
        GetObjectValueIfFindKey(jsonObject, INSIGHT_INTENT_PAGE_INFO, insightIntentInfo.pageInfo, false, g_parseResult);
    } else if (insightIntentInfo.intentType == INSIGHT_INTENTS_TYPE_ENTRY) {
        GetObjectValueIfFindKey(jsonObject, INSIGHT_INTENT_ENTRY_INFO, insightIntentInfo.entryInfo, false,
            g_parseResult);
    } else if (insightIntentInfo.intentType == INSIGHT_INTENT_FORM_INFO) {
        GetObjectValueIfFindKey(jsonObject, INSIGHT_INTENT_FORM_INFO, insightIntentInfo.formInfo, false, g_parseResult);
    }
}

bool to_json(cJSON *&jsonObject, const InsightIntentInfoForQuery &info)
{
    TAG_LOGD(AAFwkTag::INTENT, "InsightIntentInfoForQuery to json");
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_BUNDLE_NAME, info.bundleName.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_MODULE_NAME, info.moduleName.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_INTENT_NAME, info.intentName.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_DOMAIN, info.domain.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_INTENT_VERSION, info.intentVersion.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_DISPLAY_NAME, info.displayName.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_DISPLAY_DESCRIPTION, info.displayDescription.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_SCHEMA, info.schema.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_ICON, info.icon.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_LLM_DESCRIPTION, info.llmDescription.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_INTENT_TYPE, info.intentType.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_PARAMETERS, info.parameters.c_str());
    cJSON_AddStringToObject(jsonObject, INSIGHT_INTENT_RESULT, info.result.c_str());

    cJSON *keywordsItem = nullptr;
    if (!to_json(keywordsItem, info.keywords)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json keywords failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_KEYWORDS, keywordsItem);

    cJSON *linkInfoItem = nullptr;
    if (!to_json(linkInfoItem, info.linkInfo)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json linkInfo failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_LINK_INFO, linkInfoItem);

    cJSON *pageInfoItem = nullptr;
    if (!to_json(pageInfoItem, info.pageInfo)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json pageInfo failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_PAGE_INFO, pageInfoItem);

    cJSON *entryInfoItem = nullptr;
    if (!to_json(entryInfoItem, info.entryInfo)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json entryInfo failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_ENTRY_INFO, entryInfoItem);

    cJSON *formInfoItem = nullptr;
    if (!to_json(formInfoItem, info.formInfo)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json formInfo failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_FORM_INFO, formInfoItem);

    cJSON *entitiesItem = nullptr;
    if (!to_json(entitiesItem, info.entities)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json entities failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, INSIGHT_INTENT_ENTITY_INFO, entitiesItem);
    return true;
}

bool InsightIntentInfoForQuery::ReadFromParcel(Parcel &parcel)
{
    MessageParcel *messageParcel = reinterpret_cast<MessageParcel *>(&parcel);
    if (!messageParcel) {
        TAG_LOGE(AAFwkTag::INTENT, "Type conversion failed");
        return false;
    }
    uint32_t length = messageParcel->ReadUint32();
    if (length == 0) {
        TAG_LOGE(AAFwkTag::INTENT, "Invalid data length");
        return false;
    }
    const char *data = reinterpret_cast<const char *>(messageParcel->ReadRawData(length));
    TAG_LOGD(AAFwkTag::INTENT, "ReadFromParcel data: %{public}s", data);
    if (!data) {
        TAG_LOGE(AAFwkTag::INTENT, "Fail read raw length = %{public}d", length);
        return false;
    }
    cJSON *jsonObject = cJSON_Parse(data);
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "failed to parse BundleInfo");
        return false;
    }
    std::lock_guard<std::mutex> lock(g_extraMutex);
    g_parseResult = ERR_OK;
    from_json(jsonObject, *this);
    cJSON_Delete(jsonObject);
    if (g_parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "parse result: %{public}d", g_parseResult);
        g_parseResult = ERR_OK;
        return false;
    }
    return true;
}

bool InsightIntentInfoForQuery::Marshalling(Parcel &parcel) const
{
    MessageParcel *messageParcel = reinterpret_cast<MessageParcel *>(&parcel);
    if (!messageParcel) {
        TAG_LOGE(AAFwkTag::INTENT, "Conversion failed");
        return false;
    }
    cJSON *jsonObject = nullptr;
    if (!to_json(jsonObject, *this)) {
        TAG_LOGE(AAFwkTag::INTENT, "to_json insightIntentInfoForQuery failed");
        return false;
    }
    std::string str = AAFwk::JsonUtils::GetInstance().ToString(jsonObject);
    cJSON_Delete(jsonObject);
    TAG_LOGD(AAFwkTag::INTENT, "Marshalling str: %{public}s", str.c_str());
    if (!messageParcel->WriteUint32(str.size() + 1)) {
        TAG_LOGE(AAFwkTag::INTENT, "Write intent info size failed");
        return false;
    }
    if (!messageParcel->WriteRawData(str.c_str(), str.size() + 1)) {
        TAG_LOGE(AAFwkTag::INTENT, "Write intent info failed");
        return false;
    }
    return true;
}

InsightIntentInfoForQuery *InsightIntentInfoForQuery::Unmarshalling(Parcel &parcel)
{
    InsightIntentInfoForQuery *info = new (std::nothrow) InsightIntentInfoForQuery();
    if (info == nullptr) {
        return nullptr;
    }

    if (!info->ReadFromParcel(parcel)) {
        delete info;
        info = nullptr;
    }
    return info;
}
} // namespace AbilityRuntime
} // namespace OHOS
