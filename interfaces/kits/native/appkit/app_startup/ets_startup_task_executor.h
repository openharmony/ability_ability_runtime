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

#ifndef ETS_STARTUP_TASK_EXECUTOR_H
#define ETS_STARTUP_TASK_EXECUTOR_H

#include <functional>

#include "ani.h"
#include "event_handler.h"
#include "startup_task_result.h"

namespace OHOS {
namespace AbilityRuntime {
class ETSStartupTaskExecutor {
public:
    static int32_t RunOnMainThread(ani_env *env, ani_ref startupTask, ani_ref context,
        std::shared_ptr<StartupTaskResultCallback> callback);
    static int32_t RunOnTaskPool(ani_env *env, ani_ref startupTask, ani_ref context,
        std::shared_ptr<StartupTaskResultCallback> callback);
    static void NativeOnTaskSuccess(ani_env *env, ani_object obj, ani_long callbackLong, ani_object result);
    static void NativeOnTaskFailure(ani_env *env, ani_object obj, ani_long callbackLong, ani_string errorMessage);
    static void PostMainThreadTask(std::function<void()> task);
};

void ETSStartupTaskExecutorInit(ani_env *env);
} // namespace AbilityRuntime
} // namespace OHOS

#endif // ETS_STARTUP_TASK_EXECUTOR_H