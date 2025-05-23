/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "app_startup_task.h"

namespace OHOS {
namespace AbilityRuntime {
AppStartupTask::AppStartupTask(const std::string& name) : StartupTask(name)
{
}

AppStartupTask::~AppStartupTask() = default;

bool AppStartupTask::GetIsExcludeFromAutoStart() const
{
    return isExcludeFromAutoStart_;
}

void AppStartupTask::SetIsExcludeFromAutoStart(bool excludeFromAutoStart)
{
    isExcludeFromAutoStart_ = excludeFromAutoStart;
}

void AppStartupTask::SetModuleName(const std::string &moduleName)
{
    moduleName_ = moduleName;
}

const std::string& AppStartupTask::GetModuleName() const
{
    return moduleName_;
}

void AppStartupTask::SetModuleType(AppExecFwk::ModuleType moduleType)
{
    moduleType_ = moduleType;
}

AppExecFwk::ModuleType AppStartupTask::GetModuleType() const
{
    return moduleType_;
}

void AppStartupTask::SetMatchRules(StartupTaskMatchRules matchRules)
{
    matchRules_ = std::move(matchRules);
}

const std::vector<std::string> &AppStartupTask::GetUriMatchRules() const
{
    return matchRules_.uris;
}

const std::vector<std::string> &AppStartupTask::GetInsightIntentMatchRules() const
{
    return matchRules_.insightIntents;
}

const std::vector<std::string> &AppStartupTask::GetActionMatchRules() const
{
    return matchRules_.actions;
}

const std::vector<std::string> &AppStartupTask::GetCustomizationMatchRules() const
{
    return matchRules_.customization;
}
} // namespace AbilityRuntime
} // namespace OHOS
