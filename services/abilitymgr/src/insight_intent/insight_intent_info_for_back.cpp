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

#include "insight_intent_info_for_back.h"

#include "string_wrapper.h"
#include "hilog_tag_wrapper.h"
#include "json_util.h"

namespace OHOS {
namespace AbilityRuntime {
using JsonType = AppExecFwk::JsonType;
using ArrayType = AppExecFwk::ArrayType;
namespace {
int32_t g_parseResult = ERR_OK;

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

void from_json(const nlohmann::json &jsonObject, LinkInfoForBack &linkInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "LinkInfoForBack from json");
    const auto &jsonObjectEnd = jsonObject.end();
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENTS_URI,
        linkInfo.uri,
        true,
        g_parseResult);
}

void to_json(nlohmann::json& jsonObject, const LinkInfoForBack &info)
{
    TAG_LOGD(AAFwkTag::INTENT, "LinkInfoForBack to json");
    jsonObject = nlohmann::json {
        {INSIGHT_INTENTS_URI, info.uri}
    };
}

void from_json(const nlohmann::json &jsonObject, PageInfoForBack &pageInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "PageInfoForBack from json");
    const auto &jsonObjectEnd = jsonObject.end();
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_UI_ABILITY,
        pageInfo.uiAbility,
        true,
        g_parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_PAGE_ROUTER_NAME,
        pageInfo.pageRouterName,
        true,
        g_parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_NAVIGATION_ID,
        pageInfo.navigationId,
        true,
        g_parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_NAV_DESTINATION,
        pageInfo.navDestination,
        true,
        g_parseResult);
}

void to_json(nlohmann::json& jsonObject, const PageInfoForBack &info)
{
    TAG_LOGD(AAFwkTag::INTENT, "PageInfoForBack to json");
    jsonObject = nlohmann::json {
        {INSIGHT_INTENT_UI_ABILITY, info.uiAbility},
        {INSIGHT_INTENT_PAGE_ROUTER_NAME, info.pageRouterName},
        {INSIGHT_INTENT_NAVIGATION_ID, info.navigationId},
        {INSIGHT_INTENT_NAV_DESTINATION, info.navDestination}
    };
}

void from_json(const nlohmann::json &jsonObject, EntryInfoForBack &entryInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "EntryInfoForBack from json");
    const auto &jsonObjectEnd = jsonObject.end();
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_ABILITY_NAME,
        entryInfo.abilityName,
        true,
        g_parseResult);
    if (jsonObject.find(INSIGHT_INTENT_EXECUTE_MODE) != jsonObjectEnd) {
        const auto &modeArray = jsonObject[INSIGHT_INTENT_EXECUTE_MODE];
        for (const auto &modeStr : modeArray) {
            auto it = STRING_EXECUTE_MODE_MAP.find(modeStr.get<std::string>());
            if (it != STRING_EXECUTE_MODE_MAP.end()) {
                entryInfo.executeMode.push_back(it->second);
            } else {
                TAG_LOGW(AAFwkTag::INTENT, "Unknown ExecuteMode: %{public}s", modeStr.dump().c_str());
            }
        }
    }
}

void to_json(nlohmann::json& jsonObject, const EntryInfoForBack &info)
{
    TAG_LOGD(AAFwkTag::INTENT, "EntryInfoForBack to json");
    std::vector<std::string> modeStrings;
    for (const auto &mode : info.executeMode) {
        auto it = EXECUTE_MODE_STRING_MAP.find(mode);
        if (it != EXECUTE_MODE_STRING_MAP.end()) {
            modeStrings.push_back(it->second);
        } else {
            modeStrings.push_back("UNKNOWN");
        }
    }
    jsonObject = nlohmann::json {
        {INSIGHT_INTENT_ABILITY_NAME, info.abilityName},
        {INSIGHT_INTENT_EXECUTE_MODE, info.executeMode}
    };
}

void from_json(const nlohmann::json &jsonObject, FunctionInfoForBack &functionInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "FunctionInfoForBack from json");
}

void to_json(nlohmann::json& jsonObject, const FunctionInfoForBack &info)
{
    TAG_LOGD(AAFwkTag::INTENT, "FunctionInfoForBack to json");
    jsonObject = nlohmann::json {};
}

void from_json(const nlohmann::json &jsonObject, FormInfoForBack &formInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "FormInfoForBack from json");
}

void to_json(nlohmann::json& jsonObject, const FormInfoForBack &info)
{
    TAG_LOGD(AAFwkTag::INTENT, "FormInfoForBack to json");
    jsonObject = nlohmann::json {};
}

void from_json(const nlohmann::json &jsonObject, InsightIntentInfoForBack &insightIntentInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "InsightIntentInfoForBack from json");
    const auto &jsonObjectEnd = jsonObject.end();
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_BUNDLE_NAME,
        insightIntentInfo.bundleName,
        true,
        g_parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_MODULE_NAME,
        insightIntentInfo.moduleName,
        true,
        g_parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_INTENT_NAME,
        insightIntentInfo.intentName,
        true,
        g_parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_DOMAIN,
        insightIntentInfo.domain,
        true,
        g_parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_INTENT_VERSION,
        insightIntentInfo.intentVersion,
        true,
        g_parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_DISPLAY_NAME,
        insightIntentInfo.displayName,
        true,
        g_parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_DISPLAY_DESCRIPTION,
        insightIntentInfo.displayDescription,
        true,
        g_parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_SCHEMA,
        insightIntentInfo.schema,
        true,
        g_parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_ICON,
        insightIntentInfo.icon,
        true,
        g_parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_LLM_DESCRIPTION,
        insightIntentInfo.llmDescription,
        true,
        g_parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_INTENT_TYPE,
        insightIntentInfo.intentType,
        true,
        g_parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_PARAMETERS,
        insightIntentInfo.parameters,
        true,
        g_parseResult);
    AppExecFwk::GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_KEYWORDS,
        insightIntentInfo.keywords,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::STRING);
    AppExecFwk::GetValueIfFindKey<LinkInfoForBack>(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_LINK_INFO,
        insightIntentInfo.linkInfo,
        JsonType::OBJECT,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    AppExecFwk::GetValueIfFindKey<PageInfoForBack>(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_PAGE_INFO,
        insightIntentInfo.pageInfo,
        JsonType::OBJECT,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    AppExecFwk::GetValueIfFindKey<EntryInfoForBack>(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_ENTRY_INFO,
        insightIntentInfo.entryInfo,
        JsonType::OBJECT,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    AppExecFwk::GetValueIfFindKey<FunctionInfoForBack>(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_FUNCTION_INFO,
        insightIntentInfo.functionInfo,
        JsonType::OBJECT,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    AppExecFwk::GetValueIfFindKey<FormInfoForBack>(jsonObject,
        jsonObjectEnd,
        INSIGHT_INTENT_FORM_INFO,
        insightIntentInfo.formInfo,
        JsonType::OBJECT,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
}

void to_json(nlohmann::json& jsonObject, const InsightIntentInfoForBack &info)
{
    TAG_LOGD(AAFwkTag::INTENT, "EntryInfoForBack to json");
    jsonObject = nlohmann::json {
        {INSIGHT_INTENT_BUNDLE_NAME, info.bundleName},
        {INSIGHT_INTENT_MODULE_NAME, info.moduleName},
        {INSIGHT_INTENT_INTENT_NAME, info.intentName},
        {INSIGHT_INTENT_DOMAIN, info.domain},
        {INSIGHT_INTENT_INTENT_VERSION, info.intentVersion},
        {INSIGHT_INTENT_DISPLAY_NAME, info.displayName},
        {INSIGHT_INTENT_DISPLAY_DESCRIPTION, info.displayDescription},
        {INSIGHT_INTENT_SCHEMA, info.schema},
        {INSIGHT_INTENT_ICON, info.icon},
        {INSIGHT_INTENT_LLM_DESCRIPTION, info.llmDescription},
        {INSIGHT_INTENT_INTENT_TYPE, info.intentType},
        {INSIGHT_INTENT_PARAMETERS, info.parameters},
        {INSIGHT_INTENT_KEYWORDS, info.keywords},
        {INSIGHT_INTENT_LINK_INFO, info.linkInfo},
        {INSIGHT_INTENT_PAGE_INFO, info.pageInfo},
        {INSIGHT_INTENT_ENTRY_INFO, info.entryInfo},
        {INSIGHT_INTENT_FUNCTION_INFO, info.functionInfo},
        {INSIGHT_INTENT_FORM_INFO, info.formInfo}
    };
}

bool InsightIntentInfoForBack::ReadFromParcel(Parcel &parcel)
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
    if (!data) {
        TAG_LOGE(AAFwkTag::INTENT, "Fail read raw length = %{public}d", length);
        return false;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(data, nullptr, false);
    if (jsonObject.is_discarded()) {
        TAG_LOGE(AAFwkTag::INTENT, "failed to parse BundleInfo");
        return false;
    }
    *this = jsonObject.get<InsightIntentInfoForBack>();
    return true;
}

bool InsightIntentInfoForBack::Marshalling(Parcel &parcel) const
{
    MessageParcel *messageParcel = reinterpret_cast<MessageParcel *>(&parcel);
    if (!messageParcel) {
        TAG_LOGE(AAFwkTag::INTENT, "Conversion failed");
        return false;
    }
    nlohmann::json jsonObject = *this;
    std::string str = jsonObject.dump();
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

InsightIntentInfoForBack *InsightIntentInfoForBack::Unmarshalling(Parcel &parcel)
{
    InsightIntentInfoForBack *info = new (std::nothrow) InsightIntentInfoForBack();
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
 