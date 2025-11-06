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
 
#ifndef OHOS_ABILITY_RUNTIME_ETS_STARTUP_MANAGER_H
#define OHOS_ABILITY_RUNTIME_ETS_STARTUP_MANAGER_H

#include "ani.h"
#include "ets_runtime.h"
#include "ets_startup_task_result.h"
#include "startup_config.h"
#include "startup_manager.h"
 
namespace OHOS {
namespace AbilityRuntime {
class ETSStartupManager {
public:
    ETSStartupManager() = default;
    ~ETSStartupManager() = default;

    ETSStartupManager(const ETSStartupManager &) = delete;
    ETSStartupManager(ETSStartupManager&&) = delete;
    ETSStartupManager &operator=(const ETSStartupManager&) = delete;
    ETSStartupManager &operator=(ETSStartupManager&&) = delete;

    static int32_t NativeCreateStartupTaskManager(ani_env *env, ani_object startupTasks,
        ani_boolean isDefaultContext, ani_object startupConfig, ani_object abilityStageContext);
    
    /**
     * Native method to run startup tasks asynchronously
     *
     * @param env The ANI environment
     * @param startupTasks Array of startup tasks to run
     * @param isDefaultContext IsDefaultContext for ability stage context
     * @param callback Callback for async operation completion
     * @param startupConfig Configuration for startup tasks
     * @param abilityStageContext The ability stage context
     */
    static void NativeRun(ani_env *env, ani_int startupTaskManagerId, ani_object callback);

    /**
     * Native method to get the result of a specific startup task
     *
     * @param env The ANI environment
     * @param startupTask The name of the startup task
     * @return The result object of the startup task, or nullptr if failed
     */
    static ani_object NativeGetStartupTaskResult(ani_env *env, ani_string startupTask);

    /**
     * Native method to check if a startup task is initialized
     *
     * @param env The ANI environment
     * @param startupTask The name of the startup task
     * @return true if the startup task is initialized, false otherwise
     */
    static bool NativeIsStartupTaskInitialized(ani_env *env, ani_string startupTask);

    /**
     * Native method to remove the result of a specific startup task
     *
     * @param env The ANI environment
     * @param startupTask The name of the startup task
     */
    static void NativeRemoveStartupTaskResult(ani_env *env, ani_string startupTask);

    /**
     * Native method to remove all startup task results
     *
     * @param env The ANI environment
     */
    static void NativeRemoveAllStartupTaskResults(ani_env *env);

private:
    /**
     * Run startup tasks with the given configuration
     *
     * @param env The ANI environment
     * @param startupTasks Array of startup tasks
     * @param isDefaultContext IsDefaultContext for ability stage context
     * @param startupConfig Configuration for startup tasks
     * @param abilityStageContext The ability stage context
     * @param startupTaskManager Output parameter for the created startup task manager
     * @return Error code indicating success or failure
     */
    static int32_t RunStartupTask(ani_env *env, ani_object startupTasks, ani_boolean isDefaultContext,
        ani_object startupConfig, ani_object abilityStageContext,
        std::shared_ptr<StartupTaskManager> &startupTaskManager);

    /**
     * Get startup configuration from the given object
     *
     * @param env The ANI environment
     * @param configObj The configuration object
     * @param config Output parameter for the parsed configuration
     * @return Error code indicating success or failure
     */
    static int32_t GetConfig(ani_env *env, ani_object configObj, std::shared_ptr<StartupConfig> &config);

    /**
     * Update startup tasks context reference
     *
     * @param env The ANI environment
     * @param tasks The startup tasks to update
     * @param stageContextRef The ability stage context reference
     */
    static void UpdateStartupTasks(ani_env *env, std::map<std::string, std::shared_ptr<StartupTask>> &tasks,
        ani_ref stageContextRef);
};

/**
 * Initialize the ETS startup manager
 *
 * @param env The ANI environment
 */
void ETSStartupManagerInit(ani_env *env);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_STARTUP_MANAGER_H