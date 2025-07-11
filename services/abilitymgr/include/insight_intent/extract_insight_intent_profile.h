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

#ifndef OHOS_ABILITY_RUNTIME_EXTRACT_INSIGHT_INTENT_PROFILE_H
#define OHOS_ABILITY_RUNTIME_EXTRACT_INSIGHT_INTENT_PROFILE_H

#include <string>
#include <vector>

#include "insight_intent_execute_param.h"

namespace OHOS {
namespace AbilityRuntime {
using ExecuteMode = AppExecFwk::ExecuteMode;

const std::string INSIGHT_INTENTS_DECORATOR_TYPE_LINK = "@InsightIntentLink";
const std::string INSIGHT_INTENTS_DECORATOR_TYPE_PAGE = "@InsightIntentPage";
const std::string INSIGHT_INTENTS_DECORATOR_TYPE_ENTRY = "@InsightIntentEntry";
const std::string INSIGHT_INTENTS_DECORATOR_TYPE_FUNCTION = "@InsightIntentFunctionMethod";
const std::string INSIGHT_INTENTS_DECORATOR_TYPE_FORM = "@InsightIntentForm";

struct InsightIntentParam {
    std::string paramName;
    bool isRequired = false;
    std::string paramSchema;

    InsightIntentParam() = default;
};

struct LinkIntentParamMapping {
    std::string paramName;
    std::string paramMappingName;
    std::string paramCategory;

    LinkIntentParamMapping() = default;
};

struct InsightIntentLinkInfo {
    std::string uri;
    std::vector<LinkIntentParamMapping> paramMapping {};
    std::string parameters;

    InsightIntentLinkInfo() = default;
};

struct InsightIntentPageInfo {
    std::string uiAbility;
    std::string pagePath;
    std::string navigationId;
    std::string navDestinationName;
    std::string parameters;

    InsightIntentPageInfo() = default;
};

struct InsightIntentEntryInfo {
    std::string abilityName;
    std::vector<ExecuteMode> executeMode {};
    std::string parameters;

    InsightIntentEntryInfo() = default;
};

struct InsightIntentFunctionInfo {
    std::string functionName;
    std::vector<std::string> functionParams;
    std::string parameters;

    InsightIntentFunctionInfo() = default;
};

struct InsightIntentFormInfo {
    std::string abilityName;
    std::string formName;
    std::string parameters;

    InsightIntentFormInfo() = default;
};

enum class InfoType: uint8_t {
    Link,
    Page,
    Entry,
    Function,
    Form,
    None
};

struct ExtractInsightIntentGenericInfo {
    std::string bundleName;
    std::string moduleName;
    std::string intentName;
    std::string displayName;
    std::string decoratorType;

    std::variant<
        InsightIntentLinkInfo,
        InsightIntentPageInfo,
        InsightIntentEntryInfo,
        InsightIntentFunctionInfo,
        InsightIntentFormInfo,
        std::monostate
    > data;

    InfoType currentType = InfoType::None;

    ExtractInsightIntentGenericInfo() : data(std::monostate{}) {}

    template<typename T>
    void set()
    {
        data = T{};
        currentType = TypeInfo<T>();
    }

    template<typename T>
    T& get()
    {
        if (!std::holds_alternative<T>(data)) {
            data = T{};
            currentType = TypeInfo<T>();
        }
        return std::get<T>(data);
    }

private:
    template<typename T>
    static InfoType TypeInfo()
    {
        if constexpr (std::is_same_v<T, InsightIntentLinkInfo>) return InfoType::Link;
        if constexpr (std::is_same_v<T, InsightIntentPageInfo>) return InfoType::Page;
        if constexpr (std::is_same_v<T, InsightIntentEntryInfo>) return InfoType::Entry;
        if constexpr (std::is_same_v<T, InsightIntentFunctionInfo>) return InfoType::Function;
        if constexpr (std::is_same_v<T, InsightIntentFormInfo>) return InfoType::Form;
        return InfoType::None;
    }
};

struct InsightIntentEntityInfo {
    std::string decoratorFile;
    std::string className;
    std::string decoratorType;
    std::string entityId;
    std::string entityCategory;
    std::string parameters;
    std::string parentClassName;

    InsightIntentEntityInfo() = default;
};

// 全量信息
struct ExtractInsightIntentInfo {
    std::string decoratorFile;
    std::string decoratorClass;
    std::string displayDescription;
    std::string domain;
    std::string intentVersion;
    std::string schema;
    std::string icon;
    std::string llmDescription;
    std::string result;
    std::string example;
    std::vector<std::string> keywords;
    std::vector<InsightIntentEntityInfo> entities {};
    ExtractInsightIntentGenericInfo genericInfo;

    ExtractInsightIntentInfo() = default;
};

struct LinkIntentParamProfileMapping {
    std::string paramName;
    std::string paramMappingName;
    std::string paramCategory;
};

struct ExtractInsightIntentProfileInfo {
    std::string decoratorFile;
    std::string decoratorClass;
    std::string decoratorType;
    std::string bundleName;
    std::string moduleName;
    std::string intentName;
    std::string domain;
    std::string intentVersion;
    std::string displayName;
    std::string displayDescription;
    std::string schema;
    std::string icon;
    std::string llmDescription;
    std::vector<std::string> keywords;
    std::string parameters;
    std::string result;
    std::string example;
    std::string uri;
    std::vector<LinkIntentParamProfileMapping> paramMapping {};
    std::string uiAbility;
    std::string pagePath;
    std::string navigationId;
    std::string navDestinationName;
    std::string abilityName;
    std::vector<std::string> executeMode {};
    std::string functionName;
    std::vector<std::string> functionParams;
    std::string formName;
    std::vector<InsightIntentEntityInfo> entities {};
};

struct ExtractInsightIntentProfileInfoVec {
    std::vector<ExtractInsightIntentProfileInfo> insightIntents {};
};

class ExtractInsightIntentProfile {
public:
    static bool TransformTo(const std::string &profileStr, ExtractInsightIntentProfileInfoVec &infos);
    static bool ToJson(const ExtractInsightIntentProfileInfo &info, nlohmann::json &jsonObject);
    static bool ProfileInfoFormat(const ExtractInsightIntentProfileInfo &insightIntent, ExtractInsightIntentInfo &info);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_EXTRACT_INSIGHT_INTENT_PROFILE_H
