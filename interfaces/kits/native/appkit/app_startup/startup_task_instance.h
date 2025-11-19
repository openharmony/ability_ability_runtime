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

#ifndef OHOS_ABILITY_RUNTIME_STARTUP_TASK_INSTANCE_H
#define OHOS_ABILITY_RUNTIME_STARTUP_TASK_INSTANCE_H

#include <memory>
#include <string>

#include "app_startup_task.h"
#include "runtime.h"

namespace OHOS {
namespace AbilityRuntime {
struct StartupTaskInfo;

class StartupTaskInstance {
public:
    static const std::unique_ptr<Runtime> &GetSpecifiedRuntime(const std::unique_ptr<Runtime> &runtime,
        const std::string &arkTSMode);

    static std::shared_ptr<AppStartupTask> CreateStartupTask(const std::unique_ptr<Runtime> &runtime,
        const std::string &arkTSMode, const StartupTaskInfo &info, bool lazyLoad);

private:
    static std::shared_ptr<AppStartupTask> CreateJsStartupTask(const std::unique_ptr<Runtime> &runtime,
        const StartupTaskInfo &info, bool lazyLoad);

    static std::shared_ptr<AppStartupTask> CreateEtsStartupTask(const std::unique_ptr<Runtime> &runtime,
        const StartupTaskInfo &info, bool lazyLoad);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_STARTUP_TASK_INSTANCE_H
