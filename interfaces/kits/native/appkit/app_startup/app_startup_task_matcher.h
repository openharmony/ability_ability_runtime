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

#ifndef  OHOS_ABILITY_RUNTIME_APP_STARTUP_TASK_MATCHER_H
#define  OHOS_ABILITY_RUNTIME_APP_STARTUP_TASK_MATCHER_H

#include "app_startup_task.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
class AppStartupTaskMatcher {
public:
    virtual bool Match(const AppStartupTask &task) const = 0;
    virtual ~AppStartupTaskMatcher() = default;
};

class ModuleStartStartupTaskMatcher : public AppStartupTaskMatcher {
public:
    ModuleStartStartupTaskMatcher(const std::string &moduleName);

    bool Match(const AppStartupTask &task) const override;

private:
    std::string moduleName_;
};

class ExcludeFromAutoStartStartupTaskMatcher : public AppStartupTaskMatcher {
public:
    ExcludeFromAutoStartStartupTaskMatcher();

    bool Match(const AppStartupTask &task) const override;
};

class UriStartupTaskMatcher : public AppStartupTaskMatcher {
public:
    UriStartupTaskMatcher(std::shared_ptr<AAFwk::Want> want);
    UriStartupTaskMatcher(std::shared_ptr<Uri> uri);

    bool Match(const AppStartupTask &task) const override;

private:
    std::shared_ptr<Uri> uri_ = nullptr;
};

class InsightIntentStartupTaskMatcher : public AppStartupTaskMatcher {
public:
    InsightIntentStartupTaskMatcher(std::shared_ptr<AAFwk::Want> want);
    InsightIntentStartupTaskMatcher(const std::string &insightIntentName);

    bool Match(const AppStartupTask &task) const override;

private:
    std::string insightIntentName_;
};

class ActionStartupTaskMatcher : public AppStartupTaskMatcher {
public:
    ActionStartupTaskMatcher(std::shared_ptr<AAFwk::Want> want);
    ActionStartupTaskMatcher(const std::string &action);

    bool Match(const AppStartupTask &task) const override;

private:
    std::string action_;
};

class CustomizationStartupTaskMatcher : public AppStartupTaskMatcher {
public:
    CustomizationStartupTaskMatcher(const std::string &customization);

    bool Match(const AppStartupTask &task) const override;
    
private:
    std::string customization_;
};

class MatchRulesStartupTaskMatcher : public AppStartupTaskMatcher {
public:
    MatchRulesStartupTaskMatcher(std::shared_ptr<AAFwk::Want> want);
    MatchRulesStartupTaskMatcher(const std::string &uri, const std::string &action,
        const std::string &insightIntentName);

    bool Match(const AppStartupTask &task) const override;

    void SetModuleMatcher(std::shared_ptr<ModuleStartStartupTaskMatcher> matcher);
    void SetCustomizationMatcher(std::shared_ptr<CustomizationStartupTaskMatcher> matcher);

private:
    std::vector<std::shared_ptr<AppStartupTaskMatcher>> matchers_;
    std::shared_ptr<ModuleStartStartupTaskMatcher> moduleMatcher_ = nullptr;
    std::shared_ptr<CustomizationStartupTaskMatcher> customizationMatcher_ = nullptr;
};

class DefaultStartupTaskMatcher : public AppStartupTaskMatcher {
public:
    DefaultStartupTaskMatcher(const std::string &moduleName);

    bool Match(const AppStartupTask &task) const override;

private:
    ModuleStartStartupTaskMatcher moduleMatcher_;
    ExcludeFromAutoStartStartupTaskMatcher excludeMatcher_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_APP_STARTUP_TASK_MATCHER_H
