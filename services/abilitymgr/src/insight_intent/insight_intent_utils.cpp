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

#include "insight_intent_utils.h"

#include "ability_manager_errors.h"
#include "bundle_mgr_helper.h"
#include "hilog_tag_wrapper.h"
#include "in_process_call_wrapper.h"
#include "insight_intent_profile.h"
#include "os_account_manager_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
bool CheckAbilityName(const InsightIntentInfo &info, const std::string &abilityName,
    const AppExecFwk::ExecuteMode &executeMode)
{
    bool matched = false;
    switch (executeMode) {
        case AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND:
        case AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND:
            matched = info.uiAbilityIntentInfo.abilityName == abilityName;
            break;
        case AppExecFwk::ExecuteMode::UI_EXTENSION_ABILITY:
            matched = info.uiExtensionIntentInfo.abilityName == abilityName;
            break;
        case AppExecFwk::ExecuteMode::SERVICE_EXTENSION_ABILITY:
            matched = info.serviceExtensionIntentInfo.abilityName == abilityName;
            break;
        default:
            break;
    }
    if (!matched) {
        TAG_LOGW(AAFwkTag::INTENT, "ability name mismatch");
    }
    return matched;
}
} // namespace

uint32_t InsightIntentUtils::GetSrcEntry(const AppExecFwk::ElementName &elementName, const std::string &intentName,
    const AppExecFwk::ExecuteMode &executeMode, std::string &srcEntry)
{
    TAG_LOGD(AAFwkTag::INTENT, "get srcEntry, elementName: %{public}s, intentName: %{public}s, mode: %{public}d",
        elementName.GetURI().c_str(), intentName.c_str(), executeMode);
    auto bundleName = elementName.GetBundleName();
    auto moduleName = elementName.GetModuleName();
    auto abilityName = elementName.GetAbilityName();
    if (bundleName.empty() || moduleName.empty() || abilityName.empty() || intentName.empty()) {
        TAG_LOGE(AAFwkTag::INTENT, "input param empty");
        return ERR_INVALID_VALUE;
    }

    auto bundleMgrHelper = DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance();
    if (bundleMgrHelper == nullptr) {
        return ERR_NULL_OBJECT;
    }

    // Get json profile firstly
    std::string profile;
    auto ret = IN_PROCESS_CALL(bundleMgrHelper->GetJsonProfile(AppExecFwk::INTENT_PROFILE, bundleName, moduleName,
        profile, AppExecFwk::OsAccountManagerWrapper::GetCurrentActiveAccountId()));
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "failed code: %{public}d", ret);
        return AAFwk::ERR_INSIGHT_INTENT_GET_PROFILE_FAILED;
    }

    // Transform json string
    std::vector<InsightIntentInfo> infos;
    if (!InsightIntentProfile::TransformTo(profile, infos)) {
        TAG_LOGE(AAFwkTag::INTENT, "transform profile failed");
        return ERR_INVALID_VALUE;
    }

    // Get srcEntry when intentName matched
    for (const auto &info: infos) {
        if (info.intentName == intentName && CheckAbilityName(info, abilityName, executeMode)) {
            srcEntry = info.srcEntry;
            TAG_LOGD(AAFwkTag::INTENT, "srcEntry: %{public}s", srcEntry.c_str());
            return ERR_OK;
        }
    }

    TAG_LOGE(AAFwkTag::INTENT, "get srcEntry failed");
    return AAFwk::ERR_INSIGHT_INTENT_START_INVALID_COMPONENT;
}
uint32_t InsightIntentUtils::ConvertExtractInsightIntentGenericInfo(
    ExtractInsightIntentGenericInfo &genericInfo, InsightIntentInfoForQuery &queryInfo)
{
    queryInfo.bundleName = genericInfo.bundleName;
    queryInfo.moduleName = genericInfo.moduleName;
    queryInfo.intentName = genericInfo.intentName;
    queryInfo.displayName = genericInfo.displayName;
    queryInfo.intentType = genericInfo.decoratorType;
    if (genericInfo.decoratorType == INSIGHT_INTENTS_DECORATOR_TYPE_LINK) {
        auto linkInfo = genericInfo.get<InsightIntentLinkInfo>();
        queryInfo.linkInfo.uri = linkInfo.uri;
        queryInfo.parameters = linkInfo.parameters;
    } else if (genericInfo.decoratorType == INSIGHT_INTENTS_DECORATOR_TYPE_PAGE) {
        auto pageInfo = genericInfo.get<InsightIntentPageInfo>();
        queryInfo.pageInfo.uiAbility = pageInfo.uiAbility;
        queryInfo.pageInfo.pagePath = pageInfo.pagePath;
        queryInfo.pageInfo.navigationId = pageInfo.navigationId;
        queryInfo.pageInfo.navDestinationName = pageInfo.navDestinationName;
        queryInfo.parameters = pageInfo.parameters;
    } else if (genericInfo.decoratorType == INSIGHT_INTENTS_DECORATOR_TYPE_ENTRY) {
        auto entryInfo = genericInfo.get<InsightIntentEntryInfo>();
        queryInfo.entryInfo.abilityName = entryInfo.abilityName;
        for (auto mode : entryInfo.executeMode) {
            queryInfo.entryInfo.executeMode.emplace_back(mode);
        }
        queryInfo.parameters = entryInfo.parameters;
    } else if (genericInfo.decoratorType == INSIGHT_INTENTS_DECORATOR_TYPE_FUNCTION) {
        auto functionInfo = genericInfo.get<InsightIntentFunctionInfo>();
        queryInfo.parameters = functionInfo.parameters;
    } else if (genericInfo.decoratorType == INSIGHT_INTENTS_DECORATOR_TYPE_FORM) {
        auto formInfo = genericInfo.get<InsightIntentFormInfo>();
        queryInfo.parameters = formInfo.parameters;
    } else {
        TAG_LOGE(AAFwkTag::INTENT, "invalid decoratorType:%{public}s", genericInfo.decoratorType.c_str());
        return ERR_INVALID_VALUE;
    }
    return ERR_OK;
}

uint32_t InsightIntentUtils::ConvertExtractInsightIntentInfo(
    ExtractInsightIntentInfo &intentInfo, InsightIntentInfoForQuery &queryInfo)
{
    ConvertExtractInsightIntentGenericInfo(intentInfo.genericInfo, queryInfo);
    queryInfo.domain = intentInfo.domain;
    queryInfo.intentVersion = intentInfo.intentVersion;
    queryInfo.displayDescription = intentInfo.displayDescription;
    queryInfo.schema = intentInfo.schema;
    queryInfo.icon = intentInfo.icon;
    queryInfo.llmDescription = intentInfo.llmDescription;
    queryInfo.result = intentInfo.result;

    for (auto &keyword : intentInfo.keywords) {
        queryInfo.keywords.emplace_back(keyword);
    }
    return ERR_OK;
}
} // namespace AbilityRuntime
} // namespace OHOS
