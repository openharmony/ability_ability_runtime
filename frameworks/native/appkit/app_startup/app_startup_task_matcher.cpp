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

#include "app_startup_task_matcher.h"

#include <string>

#include "insight_intent_execute_param.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
ModuleStartStartupTaskMatcher::ModuleStartStartupTaskMatcher(const std::string &moduleName) : moduleName_(moduleName)
{}

bool ModuleStartStartupTaskMatcher::Match(const AppStartupTask &task) const
{
    return task.GetModuleName() == moduleName_ || task.GetModuleType() == AppExecFwk::ModuleType::SHARED;
}

ExcludeFromAutoStartStartupTaskMatcher::ExcludeFromAutoStartStartupTaskMatcher() {}

bool ExcludeFromAutoStartStartupTaskMatcher::Match(const AppStartupTask &task) const
{
    return !task.GetIsExcludeFromAutoStart();
}

UriStartupTaskMatcher::UriStartupTaskMatcher(std::shared_ptr<AAFwk::Want> want)
{
    if (!want) {
        TAG_LOGW(AAFwkTag::STARTUP, "want is null");
        return;
    }
    uri_ = std::make_shared<Uri>(want->GetUri());
}

UriStartupTaskMatcher::UriStartupTaskMatcher(std::shared_ptr<Uri> uri) : uri_(uri) {}

bool UriStartupTaskMatcher::Match(const AppStartupTask &task) const
{
    if (!uri_) {
        TAG_LOGW(AAFwkTag::STARTUP, "uri_ is null");
        return false;
    }

    TAG_LOGD(AAFwkTag::STARTUP, "task:%{public}s, uri:%{public}s", task.GetName().c_str(), uri_->ToString().c_str());
    if (uri_->ToString().empty()) {
        return false;
    }

    const std::string scheme = uri_->GetScheme();
    const std::string host = uri_->GetHost();
    const std::string path = uri_->GetPath();
    std::string uriToMatch = scheme + "://" + host + path;

    const auto &matchRules = task.GetUriMatchRules();
    return std::any_of(matchRules.begin(), matchRules.end(), [&uriToMatch](const std::string &rule) {
        return uriToMatch == rule;
    });
}

InsightIntentStartupTaskMatcher::InsightIntentStartupTaskMatcher(std::shared_ptr<AAFwk::Want> want)
{
    if (!want) {
        TAG_LOGW(AAFwkTag::STARTUP, "want is null");
        return;
    }

    const AppExecFwk::WantParams &wantParams = want->GetParams();
    if (!wantParams.HasParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_NAME)) {
        return;
    }
    insightIntentName_ = wantParams.GetStringParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_NAME);
}

InsightIntentStartupTaskMatcher::InsightIntentStartupTaskMatcher(const std::string &insightIntentName)
    : insightIntentName_(insightIntentName) {}

bool InsightIntentStartupTaskMatcher::Match(const AppStartupTask &task) const
{
    TAG_LOGD(AAFwkTag::STARTUP, "task:%{public}s, insightIntentName:%{public}s", task.GetName().c_str(),
        insightIntentName_.c_str());
    if (insightIntentName_.empty()) {
        return false;
    }

    const auto &matchRules = task.GetInsightIntentMatchRules();
    return std::any_of(matchRules.begin(), matchRules.end(), [&name = insightIntentName_](const std::string &rule) {
        return name == rule;
    });
}

ActionStartupTaskMatcher::ActionStartupTaskMatcher(std::shared_ptr<AAFwk::Want> want)
{
    if (!want) {
        TAG_LOGW(AAFwkTag::STARTUP, "want is null");
        return;
    }
    action_ = want->GetAction();
}

ActionStartupTaskMatcher::ActionStartupTaskMatcher(const std::string &action) : action_(action) {}

bool ActionStartupTaskMatcher::Match(const AppStartupTask &task) const
{
    TAG_LOGD(AAFwkTag::STARTUP, "task:%{public}s, action:%{public}s", task.GetName().c_str(), action_.c_str());
    if (action_.empty()) {
        return false;
    }

    const auto &matchRules = task.GetActionMatchRules();
    return std::any_of(matchRules.begin(), matchRules.end(), [&action = action_](const std::string &rule) {
        return action == rule;
    });
}

CustomizationStartupTaskMatcher::CustomizationStartupTaskMatcher(const std::string &customization)
    : customization_(customization) {}

bool CustomizationStartupTaskMatcher::Match(const AppStartupTask &task) const
{
    TAG_LOGD(AAFwkTag::STARTUP, "task:%{public}s, customization_:%{public}s", task.GetName().c_str(),
        customization_.c_str());
    if (customization_.empty()) {
        return false;
    }
    
    const auto &matchRules = task.GetCustomizationMatchRules();
    return std::any_of(matchRules.begin(), matchRules.end(), [&custom = customization_](const std::string &rule) {
        return custom == rule;
    });
}


MatchRulesStartupTaskMatcher::MatchRulesStartupTaskMatcher(std::shared_ptr<AAFwk::Want> want)
{
    auto uriMatcher = std::make_shared<UriStartupTaskMatcher>(want);
    auto actionMatcher = std::make_shared<ActionStartupTaskMatcher>(want);
    auto insightIntentMatcher = std::make_shared<InsightIntentStartupTaskMatcher>(want);
    matchers_.emplace_back(uriMatcher);
    matchers_.emplace_back(actionMatcher);
    matchers_.emplace_back(insightIntentMatcher);
}

MatchRulesStartupTaskMatcher::MatchRulesStartupTaskMatcher(const std::string &uri, const std::string &action,
    const std::string &insightIntentName)
{
    auto uriMatcher = std::make_shared<UriStartupTaskMatcher>(std::make_shared<Uri>(uri));
    auto actionMatcher = std::make_shared<ActionStartupTaskMatcher>(action);
    auto insightIntentMatcher = std::make_shared<InsightIntentStartupTaskMatcher>(insightIntentName);
    matchers_.emplace_back(uriMatcher);
    matchers_.emplace_back(actionMatcher);
    matchers_.emplace_back(insightIntentMatcher);
}

bool MatchRulesStartupTaskMatcher::Match(const AppStartupTask &task) const
{
    if (moduleMatcher_ && !moduleMatcher_->Match(task)) {
        return false;
    }
    for (const auto &matcher : matchers_) {
        if (!matcher) {
            TAG_LOGW(AAFwkTag::STARTUP, "matcher is null");
            continue;
        }
        if (matcher->Match(task)) {
            return true;
        }
    }
    if (customizationMatcher_) {
        return customizationMatcher_->Match(task);
    }
    return false;
}

void MatchRulesStartupTaskMatcher::SetModuleMatcher(std::shared_ptr<ModuleStartStartupTaskMatcher> matcher)
{
    moduleMatcher_ = matcher;
}

void MatchRulesStartupTaskMatcher::SetCustomizationMatcher(std::shared_ptr<CustomizationStartupTaskMatcher> matcher)
{
    customizationMatcher_ = matcher;
}

DefaultStartupTaskMatcher::DefaultStartupTaskMatcher(const std::string &moduleName) : moduleMatcher_(moduleName)
{}

bool DefaultStartupTaskMatcher::Match(const AppStartupTask &task) const
{
    if (!moduleMatcher_.Match(task)) {
        return false;
    }
    return excludeMatcher_.Match(task);
}
} // namespace AbilityRuntime
} // namespace OHOS
