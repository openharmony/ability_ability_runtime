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

#ifndef MOCK_APPLICATION_CONTEXT_H
#define MOCK_APPLICATION_CONTEXT_H

#include <memory>
#include <string>
#include <vector>

#include "application_info.h"

namespace OHOS {
namespace AbilityRuntime {
class ApplicationContext {
public:
    static std::shared_ptr<ApplicationContext> GetInstance();
    std::string GetBaseDir();
    std::shared_ptr<AppExecFwk::ApplicationInfo> GetApplicationInfo();
    void GetAllTempDir(std::vector<std::string> &tempPaths);
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif // MOCK_APPLICATION_CONTEXT_H