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

#include "startup_manager.h"

#include <set>
#include <nlohmann/json.hpp>

#include "hilog_tag_wrapper.h"
#include "extractor.h"
#include "hitrace_meter.h"
#include "js_startup_task.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* PROFILE_FILE_PREFIX = "$profile:";
constexpr const char* PROFILE_PATH = "resources/base/profile/";
constexpr const char* JSON_SUFFIX = ".json";
constexpr const char* STARTUP_TASKS = "startupTasks";
constexpr const char* PRELOAD_STARTUP_TASKS = "appPreloadHintStartupTasks";
constexpr const char* NAME = "name";
constexpr const char* SRC_ENTRY = "srcEntry";
constexpr const char* DEPENDENCIES = "dependencies";
constexpr const char* EXCLUDE_FROM_AUTO_START = "excludeFromAutoStart";
constexpr const char* RUN_ON_THREAD = "runOnThread";
constexpr const char* WAIT_ON_MAIN_THREAD = "waitOnMainThread";
constexpr const char* CONFIG_ENTRY = "configEntry";
constexpr const char* TASK_POOL = "taskPool";
constexpr const char* TASK_POOL_LOWER = "taskpool";
constexpr const char* MAIN_THREAD = "mainThread";
constexpr const char* OHMURL = "ohmurl";
}

StartupManager::StartupManager()
{
    mainHandler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
}

StartupManager::~StartupManager() = default;

int32_t StartupManager::RegisterStartupTask(const std::string &name, const std::shared_ptr<StartupTask> &startupTask)
{
    auto result = startupTasks_.emplace(name, startupTask);
    if (!result.second) {
        TAG_LOGE(AAFwkTag::STARTUP, "%{public}s exist", name.c_str());
        return ERR_STARTUP_INVALID_VALUE;
    }
    return ERR_OK;
}

int32_t StartupManager::BuildAutoStartupTaskManager(std::shared_ptr<StartupTaskManager> &startupTaskManager)
{
    std::map<std::string, std::shared_ptr<StartupTask>> autoStartupTasks;
    std::set<std::string> dependenciesSet;
    for (auto &iter : startupTasks_) {
        if (iter.second == nullptr) {
            TAG_LOGE(AAFwkTag::STARTUP, "startup task null");
            return ERR_STARTUP_INTERNAL_ERROR;
        }
        if (iter.second->GetIsExcludeFromAutoStart()) {
            continue;
        }
        autoStartupTasks.emplace(iter.first, iter.second);
        auto dependencies = iter.second->GetDependencies();
        for (auto &dep : dependencies) {
            dependenciesSet.insert(dep);
        }
    }
    for (auto &dep : dependenciesSet) {
        if (autoStartupTasks.find(dep) != autoStartupTasks.end()) {
            continue;
        }
        TAG_LOGI(AAFwkTag::STARTUP, "try to add excludeFromAutoStart task: %{public}s", dep.c_str());
        AddStartupTask(dep, autoStartupTasks);
    }

    TAG_LOGD(AAFwkTag::STARTUP, "autoStartupTasksManager build, id: %{public}u, tasks num: %{public}zu",
        startupTaskManagerId, autoStartupTasks.size());
    startupTaskManager = std::make_shared<StartupTaskManager>(startupTaskManagerId, autoStartupTasks);
    startupTaskManager->SetConfig(defaultConfig_);
    startupTaskManagerMap_.emplace(startupTaskManagerId, startupTaskManager);
    startupTaskManagerId++;
    return ERR_OK;
}

int32_t StartupManager::BuildStartupTaskManager(const std::vector<std::string> &inputDependencies,
    std::shared_ptr<StartupTaskManager> &startupTaskManager)
{
    std::map<std::string, std::shared_ptr<StartupTask>> currentStartupTasks;
    std::set<std::string> dependenciesSet;
    for (auto &iter : inputDependencies) {
        auto findResult = startupTasks_.find(iter);
        if (findResult == startupTasks_.end()) {
            TAG_LOGE(AAFwkTag::STARTUP, "startup task %{public}s not found", iter.c_str());
            return ERR_STARTUP_DEPENDENCY_NOT_FOUND;
        }
        if (findResult->second == nullptr) {
            TAG_LOGE(AAFwkTag::STARTUP, "%{public}s startup task null", iter.c_str());
            return ERR_STARTUP_INTERNAL_ERROR;
        }
        currentStartupTasks.emplace(iter, findResult->second);
        auto dependencies = findResult->second->GetDependencies();
        for (auto &dep : dependencies) {
            dependenciesSet.insert(dep);
        }
    }

    for (auto &dep : dependenciesSet) {
        if (currentStartupTasks.find(dep) != currentStartupTasks.end()) {
            continue;
        }
        AddStartupTask(dep, currentStartupTasks);
    }
    TAG_LOGD(AAFwkTag::STARTUP, "startupTasksManager build, id: %{public}u, tasks num: %{public}zu",
        startupTaskManagerId, currentStartupTasks.size());
    startupTaskManager = std::make_shared<StartupTaskManager>(startupTaskManagerId, currentStartupTasks);
    startupTaskManager->SetConfig(defaultConfig_);
    startupTaskManagerMap_.emplace(startupTaskManagerId, startupTaskManager);
    startupTaskManagerId++;
    return ERR_OK;
}

int32_t StartupManager::OnStartupTaskManagerComplete(uint32_t id)
{
    auto result = startupTaskManagerMap_.find(id);
    if (result == startupTaskManagerMap_.end()) {
        TAG_LOGE(AAFwkTag::STARTUP, "StartupTaskManager id: %{public}u not found", id);
        return ERR_STARTUP_INTERNAL_ERROR;
    }
    TAG_LOGD(AAFwkTag::STARTUP, "erase StartupTaskManager id: %{public}u", id);
    startupTaskManagerMap_.erase(result);
    return ERR_OK;
}

void StartupManager::SetDefaultConfig(const std::shared_ptr<StartupConfig> &config)
{
    defaultConfig_ = config;
}

const std::shared_ptr<StartupConfig>& StartupManager::GetDefaultConfig() const
{
    return defaultConfig_;
}

int32_t StartupManager::RemoveAllResult()
{
    TAG_LOGD(AAFwkTag::STARTUP, "called");
    for (auto &iter : startupTasks_) {
        if (iter.second != nullptr) {
            iter.second->RemoveResult();
        }
    }
    return ERR_OK;
}

int32_t StartupManager::RemoveResult(const std::string &name)
{
    TAG_LOGD(AAFwkTag::STARTUP, "called, name: %{public}s", name.c_str());
    auto findResult = startupTasks_.find(name);
    if (findResult == startupTasks_.end() || findResult->second == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "%{public}s not found", name.c_str());
        return ERR_STARTUP_INVALID_VALUE;
    }
    return findResult->second->RemoveResult();
}

int32_t StartupManager::GetResult(const std::string &name, std::shared_ptr<StartupTaskResult> &result)
{
    TAG_LOGD(AAFwkTag::STARTUP, "called, name: %{public}s", name.c_str());
    auto findResult = startupTasks_.find(name);
    if (findResult == startupTasks_.end() || findResult->second == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "%{public}s not found", name.c_str());
        return ERR_STARTUP_INVALID_VALUE;
    }
    StartupTask::State state = findResult->second->GetState();
    if (state != StartupTask::State::INITIALIZED) {
        TAG_LOGE(AAFwkTag::STARTUP, "%{public}s not initialized", name.c_str());
        return ERR_STARTUP_INVALID_VALUE;
    }
    result = findResult->second->GetResult();
    return ERR_OK;
}

int32_t StartupManager::IsInitialized(const std::string &name, bool &isInitialized)
{
    TAG_LOGD(AAFwkTag::STARTUP, "called, name: %{public}s", name.c_str());
    auto findResult = startupTasks_.find(name);
    if (findResult == startupTasks_.end() || findResult->second == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "%{public}s, not found", name.c_str());
        return ERR_STARTUP_INVALID_VALUE;
    }
    StartupTask::State state = findResult->second->GetState();
    isInitialized = state == StartupTask::State::INITIALIZED;
    return ERR_OK;
}

int32_t StartupManager::PostMainThreadTask(const std::function<void()> &task)
{
    if (mainHandler_ == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null mainHandler");
        return ERR_STARTUP_INTERNAL_ERROR;
    }
    mainHandler_->PostTask(task);
    return ERR_OK;
}

int32_t StartupManager::AddStartupTask(const std::string &name,
    std::map<std::string, std::shared_ptr<StartupTask>> &taskMap)
{
    auto isAdded = taskMap.find(name);
    if (isAdded != taskMap.end()) {
        // already added
        return ERR_OK;
    }
    std::stack<std::string> taskStack;
    taskStack.push(name);
    while (!taskStack.empty()) {
        auto taskName = taskStack.top();
        taskStack.pop();
        auto findResult = startupTasks_.find(taskName);
        if (findResult == startupTasks_.end()) {
            TAG_LOGE(AAFwkTag::STARTUP, "startup task not found %{public}s", taskName.c_str());
            return ERR_STARTUP_DEPENDENCY_NOT_FOUND;
        }
        taskMap.emplace(taskName, findResult->second);
        if (findResult->second == nullptr) {
            TAG_LOGE(AAFwkTag::STARTUP, "null task:%{public}s", taskName.c_str());
            return ERR_STARTUP_INTERNAL_ERROR;
        }
        auto dependencies = findResult->second->GetDependencies();
        for (auto &dep : dependencies) {
            if (taskMap.find(dep) == taskMap.end()) {
                taskStack.push(dep);
            }
        }
    }
    return ERR_OK;
}

int32_t StartupManager::GetStartupConfigString(
    const AppExecFwk::HapModuleInfo &hapModuleInfo, std::string &config)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::STARTUP, "start");
    std::string appStartup = hapModuleInfo.appStartup;
    if (appStartup.empty()) {
        TAG_LOGE(AAFwkTag::STARTUP, "appStartup invalid");
        return ERR_STARTUP_CONFIG_NOT_FOUND;
    }

    size_t pos = appStartup.rfind(PROFILE_FILE_PREFIX);
    if ((pos == std::string::npos) || (pos == appStartup.length() - strlen(PROFILE_FILE_PREFIX))) {
        TAG_LOGE(AAFwkTag::STARTUP, "appStartup %{public}s is invalid", appStartup.c_str());
        return ERR_STARTUP_CONFIG_PATH_ERROR;
    }
    std::string profileName = appStartup.substr(pos + strlen(PROFILE_FILE_PREFIX));
    std::string hapPath = hapModuleInfo.hapPath;
    std::unique_ptr<uint8_t[]> startupConfig = nullptr;
    size_t len = 0;
    std::string profilePath = PROFILE_PATH + profileName + JSON_SUFFIX;
    std::string loadPath = AbilityBase::ExtractorUtil::GetLoadFilePath(hapPath);
    bool newCreate = false;
    std::shared_ptr<AbilityBase::Extractor> extractor =
        AbilityBase::ExtractorUtil::GetExtractor(loadPath, newCreate);
    if (!extractor->ExtractToBufByName(profilePath, startupConfig, len)) {
        TAG_LOGE(AAFwkTag::STARTUP, "failed to get startup config, profilePath: %{private}s, hapPath: %{private}s",
            profilePath.c_str(), hapPath.c_str());
        return ERR_STARTUP_CONFIG_PATH_ERROR;
    }
    std::string configData(startupConfig.get(), startupConfig.get() + len);
    nlohmann::json profileJson = nlohmann::json::parse(configData, nullptr, false);
    if (profileJson.is_discarded()) {
        TAG_LOGE(AAFwkTag::STARTUP, "bad profile file");
        return ERR_STARTUP_CONFIG_PARSE_ERROR;
    }
    config = profileJson.dump();

    return ERR_OK;
}

bool StartupManager::AnalyzeStartupConfig(
    const std::string &startupConfig,
    AppExecFwk::ModuleType moduleType,
    JsRuntime &jsRuntime,
    std::unique_ptr<NativeReference> &startupJsRef,
    std::shared_ptr<NativeReference> &shellContextRef)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APPKIT, "start");
    if (startupConfig.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "startupConfig invalid");
        return false;
    }

    nlohmann::json startupConfigJson = nlohmann::json::parse(startupConfig, nullptr, false);
    if (startupConfigJson.is_discarded()) {
        TAG_LOGE(AAFwkTag::APPKIT, "Failed to parse json string");
        return false;
    }

    if (moduleType == AppExecFwk::ModuleType::ENTRY) {
        if (!(startupConfigJson.contains(CONFIG_ENTRY) && startupConfigJson[CONFIG_ENTRY].is_string())) {
            TAG_LOGE(AAFwkTag::APPKIT, "no config entry.");
            return false;
        }
        if (!LoadJsStartupConfig(startupConfigJson.at(CONFIG_ENTRY).get<std::string>())) {
            TAG_LOGE(AAFwkTag::APPKIT, "load config entry failed");
            return false;
        }
    }

    if (!AddStartupTask(startupConfigJson, moduleType, jsRuntime, startupJsRef, shellContextRef)) {
        return false;
    }
    if (!AddPreloadHintStartupTask(startupConfigJson, moduleType)) {
        return false;
    }
    return true;
}

bool StartupManager::AddStartupTask(
    nlohmann::json &startupConfigJson,
    AppExecFwk::ModuleType moduleType,
    JsRuntime &jsRuntime,
    std::unique_ptr<NativeReference> &startupJsRef,
    std::shared_ptr<NativeReference> &shellContextRef)
{
    if (startupConfigJson.contains(STARTUP_TASKS) && startupConfigJson[STARTUP_TASKS].is_array()) {
        for (const auto& module : startupConfigJson.at(STARTUP_TASKS).get<nlohmann::json>()) {
            if (!module.contains(SRC_ENTRY) || !module[SRC_ENTRY].is_string() ||
            !module.contains(NAME) || !module[NAME].is_string()) {
                TAG_LOGE(AAFwkTag::APPKIT, "Invalid module data");
                return false;
            }
            auto task = AnalyzeStartupTasks(module, moduleType, jsRuntime, startupJsRef, shellContextRef);
            if (task == nullptr) {
                return false;
            }
            startupTasks_.emplace(task->GetName(), task);
        }
        return true;
    }
    return false;
}

bool StartupManager::AddPreloadHintStartupTask(
    nlohmann::json &startupConfigJson, AppExecFwk::ModuleType moduleType)
{
    if (startupConfigJson.contains(PRELOAD_STARTUP_TASKS) && startupConfigJson[PRELOAD_STARTUP_TASKS].is_array()) {
        for (const auto& module : startupConfigJson.at(PRELOAD_STARTUP_TASKS).get<nlohmann::json>()) {
            if (!module.contains(SRC_ENTRY) || !module[SRC_ENTRY].is_string() ||
            !module.contains(NAME) || !module[NAME].is_string()) {
                TAG_LOGE(AAFwkTag::APPKIT, "Invalid module data");
                return false;
            }
            auto task = AnalyzeAppPreloadHintStartupTasks(module, moduleType);
            if (task == nullptr) {
                return false;
            }
            appPreloadHintStartupTask_.emplace(task->name, task);
        }
        return true;
    }
    return false;
}

std::shared_ptr<StartupTask> StartupManager::AnalyzeStartupTasks(
    const nlohmann::json &startupTaskJson,
    AppExecFwk::ModuleType moduleType,
    JsRuntime &jsRuntime,
    std::unique_ptr<NativeReference> &startupJsRef,
    std::shared_ptr<NativeReference> &shellContextRef)
{
    if (!startupTaskJson.contains(SRC_ENTRY) || !startupTaskJson[SRC_ENTRY].is_string() ||
        !startupTaskJson.contains(NAME) || !startupTaskJson[NAME].is_string()) {
        TAG_LOGE(AAFwkTag::APPKIT, "Invalid startupTaskJson data");
        return nullptr;
    }
    if (!startupTaskJson.contains(OHMURL) || !startupTaskJson[OHMURL].is_string()) {
        LoadJsByOhmurl(startupTaskJson.at(SRC_ENTRY).get<std::string>());
    } else {
        LoadJsSrcEntry(startupTaskJson.at(SRC_ENTRY).get<std::string>());
    }
    auto jsStartupTask = std::make_shared<JsStartupTask>(
        startupTaskJson.at(NAME).get<std::string>(), jsRuntime, startupJsRef, shellContextRef);
    if (moduleType == AppExecFwk::ModuleType::SHARED) {
        jsStartupTask->SetIsExcludeFromAutoStart(true);
    }
    SetOptionalParameters(startupTaskJson, jsStartupTask, moduleType);
    return jsStartupTask;
}

bool StartupManager::LoadJsStartupConfig(const std::string &srcEntry)
{
    LoadJsSrcEntry(srcEntry);
    return true;
}

void StartupManager::LoadJsSrcEntry(const std::string &srcEntry)
{
    TAG_LOGD(AAFwkTag::APPKIT, "call");
}

void StartupManager::LoadJsByOhmurl(const std::string &ohmurl)
{
    TAG_LOGD(AAFwkTag::APPKIT, "call");
}

std::shared_ptr<AppPreloadHintStartupTask> StartupManager::AnalyzeAppPreloadHintStartupTasks(
    const nlohmann::json &preloadStartupTaskJson, AppExecFwk::ModuleType moduleType)
{
    if (!preloadStartupTaskJson.contains(SRC_ENTRY) || !preloadStartupTaskJson[SRC_ENTRY].is_string() ||
    !preloadStartupTaskJson.contains(NAME) || !preloadStartupTaskJson[NAME].is_string()) {
        TAG_LOGE(AAFwkTag::APPKIT, "Invalid startupTaskJson data");
        return nullptr;
    }
    auto appPreloadHintStartupTask = std::make_shared<AppPreloadHintStartupTask>();
    appPreloadHintStartupTask->srcEntry = preloadStartupTaskJson.at(SRC_ENTRY).get<std::string>();
    appPreloadHintStartupTask->name = preloadStartupTaskJson.at(NAME).get<std::string>();
    appPreloadHintStartupTask->taskType = "AppPreloadHintStartupTask";
    if (moduleType == AppExecFwk::ModuleType::ENTRY) {
        appPreloadHintStartupTask->moduleType = "entry";
    } else if (moduleType == AppExecFwk::ModuleType::SHARED) {
        appPreloadHintStartupTask->moduleType = "shared";
        appPreloadHintStartupTask->excludeFromAutoStart = true;
    }
    SetOptionalParameters(preloadStartupTaskJson, appPreloadHintStartupTask, moduleType);
    return appPreloadHintStartupTask;
}

void StartupManager::SetOptionalParameters(
    const nlohmann::json &module,
    std::shared_ptr<StartupTask> startupTask,
    AppExecFwk::ModuleType moduleType)
{
    if (module.contains(DEPENDENCIES) && module[DEPENDENCIES].is_array()) {
        std::vector<std::string> dependencies;
        for (const auto& dependency : module.at(DEPENDENCIES)) {
            if (dependency.is_string()) {
                dependencies.push_back(dependency.get<std::string>());
            }
        }
        startupTask->SetDependencies(dependencies);
    }

    if (module.contains(RUN_ON_THREAD) && module[RUN_ON_THREAD].is_string()) {
        std::string profileName = module.at(RUN_ON_THREAD).get<std::string>();
        if (profileName == TASK_POOL || profileName == TASK_POOL_LOWER) {
            startupTask->SetCallCreateOnMainThread(false);
        } else {
            startupTask->SetCallCreateOnMainThread(true);
        }
    }

    if (module.contains(WAIT_ON_MAIN_THREAD) && module[WAIT_ON_MAIN_THREAD].is_boolean()) {
        startupTask->SetWaitOnMainThread(module.at(WAIT_ON_MAIN_THREAD).get<bool>());
    } else {
        startupTask->SetWaitOnMainThread(true);
    }

    if (moduleType != AppExecFwk::ModuleType::ENTRY) {
        return;
    }
    if (module.contains(EXCLUDE_FROM_AUTO_START) && module[EXCLUDE_FROM_AUTO_START].is_boolean()) {
        startupTask->SetIsExcludeFromAutoStart(module.at(EXCLUDE_FROM_AUTO_START).get<bool>());
    } else {
        startupTask->SetIsExcludeFromAutoStart(false);
    }
}

void StartupManager::SetOptionalParameters(
    const nlohmann::json &module,
    std::shared_ptr<AppPreloadHintStartupTask> appPreloadHintStartupTask,
    AppExecFwk::ModuleType moduleType)
{
    if (module.contains(DEPENDENCIES) && module[DEPENDENCIES].is_array()) {
        std::vector<std::string> dependencies;
        for (const auto& dependency : module.at(DEPENDENCIES)) {
            if (dependency.is_string()) {
                dependencies.push_back(dependency.get<std::string>());
            }
        }
        appPreloadHintStartupTask->dependencies = dependencies;
    }

    appPreloadHintStartupTask->runOnThread = TASK_POOL;
    if (module.contains(OHMURL) && module[OHMURL].is_string()) {
        appPreloadHintStartupTask->ohmurl = module.at(OHMURL).get<std::string>();
    }

    if (moduleType != AppExecFwk::ModuleType::ENTRY) {
        return;
    }
    if (module.contains(EXCLUDE_FROM_AUTO_START) && module[EXCLUDE_FROM_AUTO_START].is_boolean()) {
        appPreloadHintStartupTask->excludeFromAutoStart = module.at(EXCLUDE_FROM_AUTO_START).get<bool>();
    } else {
        appPreloadHintStartupTask->excludeFromAutoStart = false;
    }
}
} // namespace AbilityRuntime
} // namespace OHOS
