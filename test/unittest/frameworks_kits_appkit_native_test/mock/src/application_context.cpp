/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     htp://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "application_context.h"

#include "mock_my_status.h"

namespace OHOS {
namespace AbilityRuntime {
std::shared_ptr<ApplicationContext> ApplicationContext::GetInstance()
{
    static std::shared_ptr<ApplicationContext> instance = std::make_shared<ApplicationContext>();
    return instance;
}
std::string ApplicationContext::GetBaseDir()
{
    return AppExecFwk::MyStatus::GetInstance().tmpDir_;
}
std::shared_ptr<AppExecFwk::ApplicationInfo> ApplicationContext::GetApplicationInfo()
{
    if (AppExecFwk::MyStatus::GetInstance().applicationContextStatus_) {
        return std::make_shared<AppExecFwk::ApplicationInfo>();
    }
    return nullptr;
}
void ApplicationContext::GetAllTempBase(std::vector<std::string> &tempPaths)
{
    tempPaths.emplace_back(AppExecFwk::MyStatus::GetInstance().tmpDir_);
}
} // namespace AbilityRuntime
} // namespace OHOS