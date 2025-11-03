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

#ifndef OHOS_ABILITY_RUNTIME_STARTUP_TASK_UTILS_H
#define OHOS_ABILITY_RUNTIME_STARTUP_TASK_UTILS_H

#include <memory>
#include <string>

#include "app_startup_task.h"
#include "context.h"
#include "ets_native_reference.h"
#include "startup_task_result.h"

namespace OHOS {
namespace AbilityRuntime {
class StartupTaskUtils {
public:
    static void UpdateStartupTaskContextRef(napi_env env, std::shared_ptr<AppStartupTask> startupTask,
        std::shared_ptr<Context> context, ani_ref contextAniRef);

    static ani_ref GetDependencyResult(ani_env *env, std::shared_ptr<StartupTaskResult> result);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_STARTUP_TASK_UTILS_H