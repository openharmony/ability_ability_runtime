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

#ifndef OHOS_ABILITY_RUNTIME_STARTUP_MANAGER_H
#define OHOS_ABILITY_RUNTIME_STARTUP_MANAGER_H

#include <map>
#include <memory>
#include <string>

#include "singleton.h"
#include "startup_config.h"
#include "startup_task.h"
#include "startup_task_manager.h"
#include "startup_utils.h"
#include "hap_module_info.h"
#include "native_engine/native_value.h"
#include "js_runtime.h"

namespace OHOS {
namespace AbilityRuntime {

struct AppPreloadHintStartupTask {
    std::string name;
    std::string srcEntry;
    std::vector<std::string> dependencies;
    bool excludeFromAutoStart;
    std::string runOnThread;
    std::string ohmurl;
    std::string moduleType;
    std::string taskType;
};

class StartupManager : public std::enable_shared_from_this<StartupManager> {
DECLARE_DELAYED_SINGLETON(StartupManager)

public:
    int32_t RegisterStartupTask(const std::string &name, const std::shared_ptr<StartupTask> &startupTask);

    int32_t BuildAutoStartupTaskManager(std::shared_ptr<StartupTaskManager> &startupTaskManager);

    int32_t BuildStartupTaskManager(const std::vector<std::string> &inputDependencies,
        std::shared_ptr<StartupTaskManager> &startupTaskManager);

    int32_t OnStartupTaskManagerComplete(uint32_t id);

    void SetDefaultConfig(const std::shared_ptr<StartupConfig> &config);

    const std::shared_ptr<StartupConfig>& GetDefaultConfig() const;

    int32_t RemoveAllResult();

    int32_t RemoveResult(const std::string &name);

    int32_t GetResult(const std::string &name, std::shared_ptr<StartupTaskResult> &result);

    int32_t IsInitialized(const std::string &name, bool &isInitialized);

    int32_t PostMainThreadTask(const std::function<void()> &task);
    
    int32_t GetStartupConfigString(const AppExecFwk::HapModuleInfo &info, std::string &config);

    bool AnalyzeStartupConfig(
        const std::string &startupConfig,
        AppExecFwk::ModuleType moduleType,
        JsRuntime &jsRuntime,
        std::unique_ptr<NativeReference> &startupJsRef,
        std::shared_ptr<NativeReference> &shellContextRef);

    bool LoadJsStartupConfig(const std::string &srcEntry);

    void LoadJsSrcEntry(const std::string &srcEntry);
    
    void LoadJsByOhmurl(const std::string &srcEntry);

private:
    uint32_t startupTaskManagerId = 0;
    std::map<uint32_t, std::shared_ptr<StartupTaskManager>> startupTaskManagerMap_;
    // read only after initialization
    std::map<std::string, std::shared_ptr<StartupTask>> startupTasks_;
    std::map<std::string, std::shared_ptr<AppPreloadHintStartupTask>> appPreloadHintStartupTask_;
    std::shared_ptr<StartupConfig> defaultConfig_;
    std::shared_ptr<AppExecFwk::EventHandler> mainHandler_;

    int32_t AddStartupTask(const std::string &name,
        std::map<std::string, std::shared_ptr<StartupTask>> &taskMap);

    bool AddStartupTask(
        nlohmann::json &startupConfigJson,
        AppExecFwk::ModuleType moduleType,
        JsRuntime &jsRuntime,
        std::unique_ptr<NativeReference> &startupJsRef,
        std::shared_ptr<NativeReference> &shellContextRef);
    
    bool AddPreloadHintStartupTask(nlohmann::json &startupConfigJson, AppExecFwk::ModuleType moduleType);

    std::shared_ptr<StartupTask> AnalyzeStartupTasks(
        const nlohmann::json &startupTaskJson,
        AppExecFwk::ModuleType moduleType,
        JsRuntime &jsRuntime,
        std::unique_ptr<NativeReference> &startupJsRef,
        std::shared_ptr<NativeReference> &shellContextRef);

    std::shared_ptr<AppPreloadHintStartupTask> AnalyzeAppPreloadHintStartupTasks(
        const nlohmann::json &preloadStartupTaskJson, AppExecFwk::ModuleType moduleType);

    void SetOptionalParameters(
        const nlohmann::json &module,
        std::shared_ptr<StartupTask> startupTask,
        AppExecFwk::ModuleType moduleType);

    void SetOptionalParameters(
        const nlohmann::json &module,
        std::shared_ptr<AppPreloadHintStartupTask> appPreloadHintStartupTask,
        AppExecFwk::ModuleType moduleType);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_STARTUP_MANAGER_H
