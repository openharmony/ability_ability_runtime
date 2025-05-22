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
#include <gtest/gtest.h>
#define private public
#define protected public
#include "startup_manager.h"
#include "extractor.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS::AbilityRuntime;
using Extractor = OHOS::AbilityBase::Extractor;
namespace OHOS {
namespace AppExecFwk {
class StartupManagerTest : public testing::Test {
public:
    StartupManagerTest()
    {}
    ~StartupManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void StartupManagerTest::SetUpTestCase(void)
{}

void StartupManagerTest::TearDownTestCase(void)
{}

void StartupManagerTest::SetUp(void)
{}

void StartupManagerTest::TearDown(void)
{}

/**
 * @tc.name: PreloadAppHintStartup_0100
 * @tc.type: FUNC
 * @tc.Function: PreloadAppHintStartup
 */
HWTEST_F(StartupManagerTest, PreloadAppHintStartup_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest PreloadAppHintStartup_0100 start";
    BundleInfo bundleInfo;
    HapModuleInfo entryInfo;
    std::string preloadModuleName;
    std::string appStartup = "appStartup";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    int32_t ret = startupManager->PreloadAppHintStartup(bundleInfo, entryInfo, preloadModuleName);
    EXPECT_EQ(ret, ERR_OK);
    entryInfo.appStartup = appStartup;
    std::string moduleName = "test_module_name";
    entryInfo.moduleName = moduleName;
    HapModuleInfo entryInfo2;
    HapModuleInfo entryInfo3;
    entryInfo3.moduleType = ModuleType::SHARED;
    entryInfo3.appStartup = appStartup;
    bundleInfo.hapModuleInfos.push_back(entryInfo2);
    bundleInfo.hapModuleInfos.push_back(entryInfo);
    bundleInfo.hapModuleInfos.push_back(entryInfo3);
    entryInfo.name = "test_name";
    ret = startupManager->PreloadAppHintStartup(bundleInfo, entryInfo, preloadModuleName);
    EXPECT_EQ(ret, ERR_OK);
    preloadModuleName = "test_name";
    ret = startupManager->PreloadAppHintStartup(bundleInfo, entryInfo, preloadModuleName);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest PreloadAppHintStartup_0100 end";
}

/**
 * @tc.name: BuildAutoAppStartupTaskManager_0100
 * @tc.type: FUNC
 * @tc.Function: BuildAutoAppStartupTaskManager
 */
HWTEST_F(StartupManagerTest, BuildAutoAppStartupTaskManager_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest BuildAutoAppStartupTaskManager_0100 start";
    std::string name = "test_name";
    std::string name1 = "test_name1";
    uint32_t startupTaskManagerId = 1;
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::shared_ptr<PreloadSoStartupTask> startupTask = std::make_shared<PreloadSoStartupTask>(name, "duri");
    EXPECT_TRUE(startupTask != nullptr);

    startupTask->SetIsExcludeFromAutoStart(true);
    std::shared_ptr<PreloadSoStartupTask> startupTask1 = std::make_shared<PreloadSoStartupTask>(name1, "duri1");
    EXPECT_TRUE(startupTask1 != nullptr);
    std::map<std::string, std::shared_ptr<StartupTask>> autoStartupTasks;
    autoStartupTasks.emplace(name1, startupTask1);
    std::shared_ptr<StartupTaskManager> startupTaskManager =
        std::make_shared<StartupTaskManager>(startupTaskManagerId, autoStartupTasks);
    EXPECT_TRUE(startupTaskManager != nullptr);
    startupManager->appStartupTasks_.emplace(name, nullptr);
    int32_t ret = startupManager->BuildAutoAppStartupTaskManager(startupTaskManager, "");
    EXPECT_EQ(ret, ERR_STARTUP_INTERNAL_ERROR);
    startupManager->appStartupTasks_.clear();
    startupManager->appStartupTasks_.emplace(name, startupTask);
    std::vector<std::string> dependencies;
    dependencies.emplace_back(name1);
    startupTask1->SetDependencies(dependencies);
    startupManager->appStartupTasks_.emplace(name1, startupTask1);
    ret = startupManager->BuildAutoAppStartupTaskManager(startupTaskManager, "");
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest BuildAutoAppStartupTaskManager_0100 end";
}

/**
 * @tc.name: LoadAppStartupTaskConfig_0100
 * @tc.type: FUNC
 * @tc.Function: LoadAppStartupTaskConfig
 */
HWTEST_F(StartupManagerTest, LoadAppStartupTaskConfig_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest LoadAppStartupTaskConfig_0100 start";
    bool needRunAutoStartupTask = false;
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    int32_t ret = startupManager->LoadAppStartupTaskConfig(needRunAutoStartupTask);
    EXPECT_NE(ret, ERR_OK);
    startupManager->isAppStartupConfigInited_ = true;
    ret = startupManager->LoadAppStartupTaskConfig(needRunAutoStartupTask);
    EXPECT_EQ(ret, ERR_OK);
    StartupTaskInfo startupTaskInfo;
    startupTaskInfo.name = "test_name";
    startupManager->pendingStartupTaskInfos_.emplace_back(startupTaskInfo);
    ret = startupManager->LoadAppStartupTaskConfig(needRunAutoStartupTask);
    EXPECT_EQ(ret, ERR_OK);
    startupManager->moduleStartupConfigInfos_.clear();
    ret = startupManager->LoadAppStartupTaskConfig(needRunAutoStartupTask);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest LoadAppStartupTaskConfig_0100 end";
}

/**
 * @tc.name: BuildAppStartupTaskManager_0100
 * @tc.type: FUNC
 * @tc.Function: BuildAppStartupTaskManager
 */
HWTEST_F(StartupManagerTest, BuildAppStartupTaskManager_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest BuildAppStartupTaskManager_0100 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string inputName = "test_name";
    std::string name = "test_name";
    std::vector<std::string> inputDependencies;
    inputDependencies.emplace_back(inputName);
    uint32_t startupTaskManagerId = 1;
    std::map<std::string, std::shared_ptr<StartupTask>> autoStartupTasks;
    std::shared_ptr<PreloadSoStartupTask> startupTask = std::make_shared<PreloadSoStartupTask>(name, "duri");
    EXPECT_TRUE(startupTask != nullptr);
    std::shared_ptr<StartupTaskManager> startupTaskManager =
        std::make_shared<StartupTaskManager>(startupTaskManagerId, autoStartupTasks);
    EXPECT_TRUE(startupTaskManager != nullptr);
    startupManager->appStartupTasks_.clear();
    int32_t ret = startupManager->BuildAppStartupTaskManager(inputDependencies, startupTaskManager, false);
    EXPECT_NE(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest BuildAppStartupTaskManager_0100 end";
}

/**
 * @tc.name: OnStartupTaskManagerComplete_0100
 * @tc.type: FUNC
 * @tc.Function: OnStartupTaskManagerComplete
 */
HWTEST_F(StartupManagerTest, OnStartupTaskManagerComplete_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest OnStartupTaskManagerComplete_0100 start";
    uint32_t id = 1;
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    startupManager->startupTaskManagerMap_.emplace(id, nullptr);
    int32_t ret = startupManager->OnStartupTaskManagerComplete(id);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest OnStartupTaskManagerComplete_0100 end";
}

/**
 * @tc.name: RemoveAllResult_0100
 * @tc.type: FUNC
 * @tc.Function: RemoveAllResult
 */
HWTEST_F(StartupManagerTest, RemoveAllResult_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest RemoveAllResult_0100 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string name = "test_name";
    std::shared_ptr<PreloadSoStartupTask> appStartupTask = std::make_shared<PreloadSoStartupTask>(name, "duri");
    startupManager->appStartupTasks_.emplace(name, appStartupTask);
    startupManager->preloadSoStartupTasks_.emplace(name, appStartupTask);
    int32_t ret = startupManager->RemoveAllResult();
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest RemoveAllResult_0100 end";
}

/**
 * @tc.name: RemoveResult_0100
 * @tc.type: FUNC
 * @tc.Function: RemoveResult
 */
HWTEST_F(StartupManagerTest, RemoveResult_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest RemoveResult_0100 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string name = "test_name";
    startupManager->appStartupTasks_.emplace(name, nullptr);
    startupManager->preloadSoStartupTasks_.emplace(name, nullptr);
    int32_t ret = startupManager->RemoveResult(name);
    EXPECT_NE(ret, ERR_OK);
    startupManager->appStartupTasks_.clear();
    ret = startupManager->RemoveResult(name);
    EXPECT_NE(ret, ERR_OK);
    startupManager->preloadSoStartupTasks_.clear();
    ret = startupManager->RemoveResult(name);
    EXPECT_NE(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest RemoveResult_0100 end";
}

/**
 * @tc.name: GetResult_0100
 * @tc.type: FUNC
 * @tc.Function: GetResult
 */
HWTEST_F(StartupManagerTest, GetResult_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest GetResult_0100 start";
    std::string name = "test_name";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::shared_ptr<PreloadSoStartupTask> appStartupTask = std::make_shared<PreloadSoStartupTask>(name, "duri");
    EXPECT_TRUE(appStartupTask != nullptr);
    std::shared_ptr<StartupTaskResult> result = nullptr;
    startupManager->appStartupTasks_.emplace(name, nullptr);
    startupManager->preloadSoStartupTasks_.emplace(name, nullptr);
    int32_t ret = startupManager->GetResult(name, result);
    EXPECT_NE(ret, ERR_OK);
    startupManager->preloadSoStartupTasks_.clear();
    startupManager->preloadSoStartupTasks_.emplace(name, appStartupTask);
    ret = startupManager->GetResult(name, result);
    EXPECT_NE(ret, ERR_OK);
    startupManager->appStartupTasks_.clear();
    startupManager->appStartupTasks_.emplace(name, appStartupTask);
    ret = startupManager->GetResult(name, result);
    EXPECT_NE(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest GetResult_0100 end";
}

/**
 * @tc.name: IsInitialized_0100
 * @tc.type: FUNC
 * @tc.Function: IsInitialized
 */
HWTEST_F(StartupManagerTest, IsInitialized_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest IsInitialized_0100 start";
    std::string name = "test_name";
    bool isInitialized = false;
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::shared_ptr<PreloadSoStartupTask> appStartupTask = std::make_shared<PreloadSoStartupTask>(name, "duri");
    EXPECT_TRUE(appStartupTask != nullptr);
    startupManager->appStartupTasks_.clear();
    startupManager->preloadSoStartupTasks_.clear();
    startupManager->appStartupTasks_.emplace(name, nullptr);
    startupManager->preloadSoStartupTasks_.emplace(name, nullptr);
    int32_t ret = startupManager->IsInitialized(name, isInitialized);
    EXPECT_NE(ret, ERR_OK);
    startupManager->preloadSoStartupTasks_.clear();
    startupManager->preloadSoStartupTasks_.emplace(name, appStartupTask);
    ret = startupManager->IsInitialized(name, isInitialized);
    EXPECT_EQ(ret, ERR_OK);
    startupManager->appStartupTasks_.clear();
    startupManager->appStartupTasks_.emplace(name, appStartupTask);
    ret = startupManager->IsInitialized(name, isInitialized);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest IsInitialized_0100 end";
}

/**
 * @tc.name: AddStartupTask_0100
 * @tc.type: FUNC
 * @tc.Function: AddStartupTask
 */
HWTEST_F(StartupManagerTest, AddStartupTask_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest AddStartupTask_0100 start";
    std::string name = "test_name";
    std::string name1 = "test_name1";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::shared_ptr<PreloadSoStartupTask> appStartupTask = std::make_shared<PreloadSoStartupTask>(name, "duri");
    EXPECT_TRUE(appStartupTask != nullptr);
    std::map<std::string, std::shared_ptr<StartupTask>> taskMap;
    std::map<std::string, std::shared_ptr<AppStartupTask>> allTasks;
    taskMap.emplace(name, appStartupTask);
    allTasks.emplace(name, appStartupTask);
    int32_t ret = startupManager->AddStartupTask(name, taskMap, allTasks);
    EXPECT_EQ(ret, ERR_OK);
    ret = startupManager->AddStartupTask(name1, taskMap, allTasks);
    EXPECT_NE(ret, ERR_OK);
    allTasks.clear();
    taskMap.clear();
    allTasks.emplace(name, nullptr);
    ret = startupManager->AddStartupTask(name, taskMap, allTasks);
    EXPECT_NE(ret, ERR_OK);
    allTasks.clear();
    taskMap.clear();
    std::vector<std::string> dependencies;
    dependencies.push_back(name);
    appStartupTask->SetDependencies(dependencies);
    allTasks.emplace(name, appStartupTask);
    ret = startupManager->AddStartupTask(name, taskMap, allTasks);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest AddStartupTask_0100 end";
}

/**
 * @tc.name: RegisterPreloadSoStartupTask_0100
 * @tc.type: FUNC
 * @tc.Function: RegisterPreloadSoStartupTask
 */
HWTEST_F(StartupManagerTest, RegisterPreloadSoStartupTask_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest RegisterPreloadSoStartupTask_0100 start";
    std::string name = "test_name";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::shared_ptr<PreloadSoStartupTask> appStartupTask = std::make_shared<PreloadSoStartupTask>(name, "duri");
    EXPECT_TRUE(appStartupTask != nullptr);
    int32_t ret = startupManager->RegisterPreloadSoStartupTask(name, appStartupTask);
    EXPECT_NE(ret, ERR_OK);
    startupManager->appStartupTasks_.clear();
    ret = startupManager->RegisterPreloadSoStartupTask(name, nullptr);
    EXPECT_NE(ret, ERR_OK);
    startupManager->preloadSoStartupTasks_.clear();
    ret = startupManager->RegisterPreloadSoStartupTask(name, appStartupTask);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest RegisterPreloadSoStartupTask_0100 end";
}

/**
 * @tc.name: RegisterAppStartupTask_0100
 * @tc.type: FUNC
 * @tc.Function: RegisterAppStartupTask
 */
HWTEST_F(StartupManagerTest, RegisterAppStartupTask_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest RegisterAppStartupTask_0100 start";
    std::string name = "test_name";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::shared_ptr<PreloadSoStartupTask> appStartupTask = std::make_shared<PreloadSoStartupTask>(name, "duri");
    EXPECT_TRUE(appStartupTask != nullptr);
    int32_t ret = startupManager->RegisterAppStartupTask(name, appStartupTask);
    EXPECT_NE(ret, ERR_OK);
    startupManager->preloadSoStartupTasks_.clear();
    ret = startupManager->RegisterAppStartupTask(name, nullptr);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest RegisterAppStartupTask_0100 end";
}

/**
 * @tc.name: BuildStartupTaskManager_0100
 * @tc.type: FUNC
 * @tc.Function: BuildStartupTaskManager
 */
HWTEST_F(StartupManagerTest, BuildStartupTaskManager_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest BuildStartupTaskManager_0100 start";
    uint32_t startupTaskManagerId = 1;
    std::string name = "test_name";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::map<std::string, std::shared_ptr<StartupTask>> tasks;
    std::map<std::string, std::shared_ptr<StartupTask>> autoStartupTasks;
    std::shared_ptr<PreloadSoStartupTask> startupTask = std::make_shared<PreloadSoStartupTask>(name, "duri");
    EXPECT_TRUE(startupTask != nullptr);
    autoStartupTasks.emplace(name, startupTask);
    std::shared_ptr<StartupTaskManager> startupTaskManager =
        std::make_shared<StartupTaskManager>(startupTaskManagerId, autoStartupTasks);
    EXPECT_TRUE(startupTaskManager != nullptr);
    int32_t ret = startupManager->BuildStartupTaskManager(tasks, startupTaskManager);
    EXPECT_NE(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest BuildStartupTaskManager_0100 end";
}

/**
 * @tc.name: AddAppPreloadSoTask_0100
 * @tc.type: FUNC
 * @tc.Function: AddAppPreloadSoTask
 */
HWTEST_F(StartupManagerTest, AddAppPreloadSoTask_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest AddAppPreloadSoTask_0100 start";
    std::string name = "test_name";
    std::vector<std::string> dependencies;
    dependencies.push_back(name);
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::shared_ptr<PreloadSoStartupTask> appStartupTask = std::make_shared<PreloadSoStartupTask>(name, "duri");
    EXPECT_TRUE(appStartupTask != nullptr);
    std::vector<std::string> preloadSoList;
    preloadSoList.push_back(name);
    startupManager->preloadSoStartupTasks_.emplace(name, nullptr);
    std::map<std::string, std::shared_ptr<StartupTask>> currentStartupTasks;
    int32_t ret = startupManager->AddAppPreloadSoTask(preloadSoList, currentStartupTasks);
    EXPECT_NE(ret, ERR_OK);
    startupManager->preloadSoStartupTasks_.clear();
    appStartupTask->SetDependencies(dependencies);
    startupManager->preloadSoStartupTasks_.emplace(name, appStartupTask);
    ret = startupManager->AddAppPreloadSoTask(preloadSoList, currentStartupTasks);
    EXPECT_EQ(ret, ERR_OK);
    preloadSoList.clear();
    currentStartupTasks.clear();
    ret = startupManager->AddAppPreloadSoTask(preloadSoList, currentStartupTasks);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest AddAppPreloadSoTask_0100 end";
}

/**
 * @tc.name: AddLoadAppStartupConfigTask_0100
 * @tc.type: FUNC
 * @tc.Function: AddLoadAppStartupConfigTask
 */
HWTEST_F(StartupManagerTest, AddLoadAppStartupConfigTask_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest AddLoadAppStartupConfigTask_0100 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::map<std::string, std::shared_ptr<StartupTask>> preloadAppHintTasks;
    auto ret = startupManager->AddLoadAppStartupConfigTask(preloadAppHintTasks);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest AddLoadAppStartupConfigTask_0100 end";
}

/**
 * @tc.name: RunLoadAppStartupConfigTask_0100
 * @tc.type: FUNC
 * @tc.Function: RunLoadAppStartupConfigTask
 */
HWTEST_F(StartupManagerTest, RunLoadAppStartupConfigTask_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest RunLoadAppStartupConfigTask_0100 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string name = "test_name";
    startupManager->isAppStartupConfigInited_ = false;
    ModuleStartupConfigInfo moduleStartupConfigInfo(name, "", "", AppExecFwk::ModuleType::UNKNOWN, false);
    startupManager->moduleStartupConfigInfos_.push_back(moduleStartupConfigInfo);
    auto ret = startupManager->RunLoadAppStartupConfigTask();
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest RunLoadAppStartupConfigTask_0100 end";
}

/**
 * @tc.name: AddAppAutoPreloadSoTask_0100
 * @tc.type: FUNC
 * @tc.Function: AddAppAutoPreloadSoTask
 */
HWTEST_F(StartupManagerTest, AddAppAutoPreloadSoTask_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest AddAppAutoPreloadSoTask_0100 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::map<std::string, std::shared_ptr<StartupTask>> preloadAppHintTasks;
    auto ret = startupManager->AddAppAutoPreloadSoTask(preloadAppHintTasks);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest AddAppAutoPreloadSoTask_0100 end";
}

/**
 * @tc.name: RunAppPreloadSoTask_0100
 * @tc.type: FUNC
 * @tc.Function: RunAppPreloadSoTask
 */
HWTEST_F(StartupManagerTest, RunAppPreloadSoTask_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest RunAppPreloadSoTask_0100 start";
    std::string name = "test_name";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::map<std::string, std::shared_ptr<StartupTask>> appPreloadSoTasks;
    std::shared_ptr<PreloadSoStartupTask> startupTask = std::make_shared<PreloadSoStartupTask>(name, "duri");
    EXPECT_TRUE(startupTask != nullptr);
    int32_t ret = startupManager->RunAppPreloadSoTask(appPreloadSoTasks);
    EXPECT_NE(ret, ERR_OK);
    appPreloadSoTasks.emplace(name, startupTask);
    ret = startupManager->RunAppPreloadSoTask(appPreloadSoTasks);
    EXPECT_EQ(ret, ERR_OK);
    startupManager->autoPreloadSoStopped_ = true;
    ret = startupManager->RunAppPreloadSoTask(appPreloadSoTasks);
    EXPECT_NE(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest RunAppPreloadSoTask_0100 end";
}

/**
 * @tc.name: GetAppAutoPreloadSoTasks_0100
 * @tc.type: FUNC
 * @tc.Function: GetAppAutoPreloadSoTasks
 */
HWTEST_F(StartupManagerTest, GetAppAutoPreloadSoTasks_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest GetAppAutoPreloadSoTasks_0100 start";
    std::string name = "test_name";
    std::string name1 = "test_name1";
    std::string name2 = "test_name2";
    std::vector<std::string> dependencies;
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::map<std::string, std::shared_ptr<StartupTask>> appAutoPreloadSoTasks;
    std::shared_ptr<PreloadSoStartupTask> startupTask = std::make_shared<PreloadSoStartupTask>(name1, "duri1");
    EXPECT_TRUE(startupTask != nullptr);
    std::shared_ptr<PreloadSoStartupTask> startupTask1 = std::make_shared<PreloadSoStartupTask>(name2, "duri2");
    EXPECT_TRUE(startupTask != nullptr);
    startupManager->preloadSoStartupTasks_.emplace(name, nullptr);
    startupTask->isExcludeFromAutoStart_ = true;
    startupManager->preloadSoStartupTasks_.emplace(name1, startupTask);
    dependencies.push_back(name2);
    startupTask1->SetDependencies(dependencies);
    startupManager->preloadSoStartupTasks_.emplace(name2, startupTask1);
    int32_t ret = startupManager->GetAppAutoPreloadSoTasks(appAutoPreloadSoTasks);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest GetAppAutoPreloadSoTasks_0100 end";
}

/**
 * @tc.name: RunAppPreloadSoTaskMainThread_0100
 * @tc.type: FUNC
 * @tc.Function: RunAppPreloadSoTaskMainThread
 */
HWTEST_F(StartupManagerTest, RunAppPreloadSoTaskMainThread_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest RunAppPreloadSoTaskMainThread_0100 start";
    std::string name = "test_name";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::map<std::string, std::shared_ptr<StartupTask>> appPreloadSoTasks;
    std::unique_ptr<StartupTaskResultCallback> callback = std::make_unique<StartupTaskResultCallback>();
    int32_t ret = startupManager->RunAppPreloadSoTaskMainThread(appPreloadSoTasks, std::move(callback));
    EXPECT_NE(ret, ERR_OK);
    std::shared_ptr<PreloadSoStartupTask> startupTask = std::make_shared<PreloadSoStartupTask>(name, "duri");
    EXPECT_TRUE(startupTask != nullptr);
    appPreloadSoTasks.emplace(name, startupTask);
    startupManager->preloadHandler_ = nullptr;
    ret = startupManager->RunAppPreloadSoTaskMainThread(appPreloadSoTasks, std::move(callback));
    EXPECT_NE(ret, ERR_OK);
    startupManager->preloadHandler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::Create());
    ret = startupManager->RunAppPreloadSoTaskMainThread(appPreloadSoTasks, std::move(callback));
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest RunAppPreloadSoTaskMainThread_0100 end";
}

/**
 * @tc.name: GetStartupConfigString_0100
 * @tc.type: FUNC
 * @tc.Function: GetStartupConfigString
 */
HWTEST_F(StartupManagerTest, GetStartupConfigString_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest GetStartupConfigString_0100 start";
    std::string name = "test_name";
    std::string config = "test_config";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    ModuleStartupConfigInfo info(name, "", "", AppExecFwk::ModuleType::UNKNOWN, false);
    int32_t ret = startupManager->GetStartupConfigString(info, config);
    EXPECT_NE(ret, ERR_OK);
    info.startupConfig_ = config;
    ret = startupManager->GetStartupConfigString(info, config);
    EXPECT_NE(ret, ERR_OK);
    GTEST_LOG_(INFO) << "StartupManagerTest GetStartupConfigString_0100 end";
}

/**
 * @tc.name: AnalyzeStartupConfig_0100
 * @tc.type: FUNC
 * @tc.Function: AnalyzeStartupConfig
 */
HWTEST_F(StartupManagerTest, AnalyzeStartupConfig_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzeStartupConfig_0100 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string name = "test_name";
    ModuleStartupConfigInfo info(name, "", "", AppExecFwk::ModuleType::UNKNOWN, false);
    std::string startupConfig;
    std::map<std::string, std::shared_ptr<AppStartupTask>> preloadSoStartupTasks;
    std::vector<StartupTaskInfo> pendingStartupTaskInfos;
    std::string pendingConfigEntry;
    bool ret = false;
    ret = startupManager->AnalyzeStartupConfig(info, startupConfig, preloadSoStartupTasks,
        pendingStartupTaskInfos, pendingConfigEntry);
    EXPECT_EQ(ret, false);
    startupConfig = "test_startupConfig";
    ret = startupManager->AnalyzeStartupConfig(info, startupConfig, preloadSoStartupTasks,
        pendingStartupTaskInfos, pendingConfigEntry);
    EXPECT_EQ(ret, false);
    const nlohmann::json startupConfig_json = R"(
        {
            "startupConfig" : [
                {
                    "srcEntry" : "test_entry",
                    "name" : "test_name"
                }
            ]
        }
    )"_json;
    startupConfig = startupConfig_json.dump();
    ret = startupManager->AnalyzeStartupConfig(info, startupConfig, preloadSoStartupTasks,
        pendingStartupTaskInfos, pendingConfigEntry);
    EXPECT_EQ(ret, true);

    info.moduleType_ = AppExecFwk::ModuleType::ENTRY;
    nlohmann::json startupConfigJson = {
        {"startupConfig", {
            {"configEntry", "test_configEntry"}
        }}
    };
    startupConfig = startupConfigJson.dump();
    ret = startupManager->AnalyzeStartupConfig(info, startupConfig, preloadSoStartupTasks,
        pendingStartupTaskInfos, pendingConfigEntry);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzeStartupConfig_0100 end";
}

/**
 * @tc.name: AnalyzeAppStartupTask_0100
 * @tc.type: FUNC
 * @tc.Function: AnalyzeAppStartupTask
 */
HWTEST_F(StartupManagerTest, AnalyzeAppStartupTask_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzeAppStartupTask_0100 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string name = "test_name";
    ModuleStartupConfigInfo info(name, "", "", AppExecFwk::ModuleType::UNKNOWN, false);
    std::vector<StartupTaskInfo> pendingStartupTaskInfos;
    nlohmann::json startupTasksJson = R"(
        {
        }
    )"_json;
    bool ret = startupManager->AnalyzeAppStartupTask(info, startupTasksJson, pendingStartupTaskInfos);
    EXPECT_EQ(ret, true);

    nlohmann::json startupTasksJson2 = R"(
        {
            "startupTasks": [
                {
                    "srcEntry": "test_entry",
                    "name": "test_name"
                }
            ]
        }
    )"_json;
    ret = startupManager->AnalyzeAppStartupTask(info, startupTasksJson2, pendingStartupTaskInfos);
    EXPECT_EQ(ret, true);

    nlohmann::json startupTasksJson3 = R"(
        {
            "startupTasks": [
                {
                    "srcEntry": []
                }
            ]
        }
    )"_json;
    ret = startupManager->AnalyzeAppStartupTask(info, startupTasksJson3, pendingStartupTaskInfos);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzeAppStartupTask_0100 end";
}

/**
 * @tc.name: AnalyzeAppStartupTask_0200
 * @tc.type: FUNC
 * @tc.Function: AnalyzeAppStartupTask
 */
HWTEST_F(StartupManagerTest, AnalyzeAppStartupTask_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzeAppStartupTask_0200 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string name = "test_name";
    ModuleStartupConfigInfo info(name, "", "", AppExecFwk::ModuleType::UNKNOWN, false);
    std::vector<StartupTaskInfo> pendingStartupTaskInfos;
    nlohmann::json startupTasksJson = R"(
        {
            "startupTasks": [
                {
                    "srcEntry": "test_entry"
                }
            ]
        }
    )"_json;
    bool ret = startupManager->AnalyzeAppStartupTask(info, startupTasksJson, pendingStartupTaskInfos);
    EXPECT_EQ(ret, false);

    nlohmann::json startupTasksJson2 = R"(
        {
            "startupTasks": [
                {
                    "srcEntry": "test_entry",
                    "name": []
                }
            ]
        }
    )"_json;
    ret = startupManager->AnalyzeAppStartupTask(info, startupTasksJson2, pendingStartupTaskInfos);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzeAppStartupTask_0200 end";
}

/**
 * @tc.name: AnalyzePreloadSoStartupTask_0100
 * @tc.type: FUNC
 * @tc.Function: AnalyzePreloadSoStartupTask
 */
HWTEST_F(StartupManagerTest, AnalyzePreloadSoStartupTask_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzePreloadSoStartupTask_0100 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string name = "test_name";
    ModuleStartupConfigInfo info(name, "", "", AppExecFwk::ModuleType::UNKNOWN, false);
    std::map<std::string, std::shared_ptr<AppStartupTask>> preloadSoStartupTasks;
    nlohmann::json preloadHintStartupTasksJson = R"(
        {
        }
    )"_json;
    bool ret = startupManager->AnalyzePreloadSoStartupTask(info, preloadHintStartupTasksJson, preloadSoStartupTasks);
    EXPECT_EQ(ret, true);

    nlohmann::json preloadHintStartupTasksJson2 = R"(
        {
            "appPreloadHintStartupTasks": [
                {
                    "srcEntry": "test_entry",
                    "name": "test_name"
                }
            ]
        }
    )"_json;
    ret = startupManager->AnalyzePreloadSoStartupTask(info, preloadHintStartupTasksJson2, preloadSoStartupTasks);
    EXPECT_EQ(ret, false);

    nlohmann::json preloadHintStartupTasksJson3 = R"(
        {
            "appPreloadHintStartupTasks": [
                {
                    "srcEntry": []
                }
            ]
        }
    )"_json;
    ret = startupManager->AnalyzePreloadSoStartupTask(info, preloadHintStartupTasksJson3, preloadSoStartupTasks);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzePreloadSoStartupTask_0100 end";
}

/**
 * @tc.name: AnalyzePreloadSoStartupTask_0200
 * @tc.type: FUNC
 * @tc.Function: AnalyzePreloadSoStartupTask
 */
HWTEST_F(StartupManagerTest, AnalyzePreloadSoStartupTask_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzePreloadSoStartupTask_0200 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string name = "test_name";
    ModuleStartupConfigInfo info(name, "", "", AppExecFwk::ModuleType::UNKNOWN, false);
    std::map<std::string, std::shared_ptr<AppStartupTask>> preloadSoStartupTasks;
    nlohmann::json preloadHintStartupTasksJson = R"(
        {
            "appPreloadHintStartupTasks": [
                {
                    "srcEntry": "test_entry"
                }
            ]
        }
    )"_json;
    bool ret = startupManager->AnalyzePreloadSoStartupTask(info, preloadHintStartupTasksJson, preloadSoStartupTasks);
    EXPECT_EQ(ret, false);

    nlohmann::json preloadHintStartupTasksJson2 = R"(
        {
            "appPreloadHintStartupTasks": [
                {
                    "srcEntry": "test_entry",
                    "name": []
                }
            ]
        }
    )"_json;
    ret = startupManager->AnalyzePreloadSoStartupTask(info, preloadHintStartupTasksJson2, preloadSoStartupTasks);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzePreloadSoStartupTask_0200 end";
}

/**
 * @tc.name: AnalyzeAppStartupTaskInner_0100
 * @tc.type: FUNC
 * @tc.Function: AnalyzeAppStartupTaskInner
 */
HWTEST_F(StartupManagerTest, AnalyzeAppStartupTaskInner_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzeAppStartupTaskInner_0100 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string name = "test_name";
    ModuleStartupConfigInfo info(name, "", "", AppExecFwk::ModuleType::UNKNOWN, false);
    std::vector<StartupTaskInfo> pendingStartupTaskInfos;
    nlohmann::json appStartupTaskInnerJson = R"(
        {
        }
    )"_json;
    bool ret = startupManager->AnalyzeAppStartupTaskInner(info, appStartupTaskInnerJson, pendingStartupTaskInfos);
    EXPECT_EQ(ret, false);

    nlohmann::json appStartupTaskInnerJson1 = R"(
        {
            "srcEntry": "test_entry",
            "name": "test_name"
        }
    )"_json;
    ret = startupManager->AnalyzeAppStartupTaskInner(info, appStartupTaskInnerJson1, pendingStartupTaskInfos);
    EXPECT_EQ(ret, true);

    nlohmann::json appStartupTaskInnerJson2 = R"(
        {
            "srcEntry": []
        }
    )"_json;
    ret = startupManager->AnalyzeAppStartupTaskInner(info, appStartupTaskInnerJson2, pendingStartupTaskInfos);
    EXPECT_EQ(ret, false);
    nlohmann::json appStartupTaskInnerJson3 = R"(
        {
            "srcEntry": "test_entry"
        }
    )"_json;
    ret = startupManager->AnalyzeAppStartupTaskInner(info, appStartupTaskInnerJson3, pendingStartupTaskInfos);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzeAppStartupTaskInner_0100 end";
}

/**
 * @tc.name: AnalyzeAppStartupTaskInner_0200
 * @tc.type: FUNC
 * @tc.Function: AnalyzeAppStartupTaskInner
 */
HWTEST_F(StartupManagerTest, AnalyzeAppStartupTaskInner_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzeAppStartupTaskInner_0200 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string name = "test_name";
    ModuleStartupConfigInfo info(name, "", "", AppExecFwk::ModuleType::UNKNOWN, false);
    std::vector<StartupTaskInfo> pendingStartupTaskInfos;
    nlohmann::json appStartupTaskInnerJson = R"(
        {
            "srcEntry": "test_entry",
            "name": []
        }
    )"_json;
    bool ret = startupManager->AnalyzeAppStartupTaskInner(info, appStartupTaskInnerJson, pendingStartupTaskInfos);
    EXPECT_EQ(ret, false);

    nlohmann::json appStartupTaskInnerJson2 = R"(
        {
            "srcEntry": "",
            "name": "test_name"
        }
    )"_json;
    ret = startupManager->AnalyzeAppStartupTaskInner(info, appStartupTaskInnerJson2, pendingStartupTaskInfos);
    EXPECT_EQ(ret, false);

    nlohmann::json appStartupTaskInnerJson3 = R"(
        {
            "srcEntry": "test_entry",
            "name": ""
        }
    )"_json;
    ret = startupManager->AnalyzeAppStartupTaskInner(info, appStartupTaskInnerJson3, pendingStartupTaskInfos);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzeAppStartupTaskInner_0200 end";
}

/**
 * @tc.name: AnalyzePreloadSoStartupTaskInner_0100
 * @tc.type: FUNC
 * @tc.Function: AnalyzePreloadSoStartupTaskInner
 */
HWTEST_F(StartupManagerTest, AnalyzePreloadSoStartupTaskInner_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzePreloadSoStartupTaskInner_0100 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string name = "test_name";
    ModuleStartupConfigInfo info(name, "", "", AppExecFwk::ModuleType::UNKNOWN, false);
    std::map<std::string, std::shared_ptr<AppStartupTask>> preloadSoStartupTasks;
    nlohmann::json preloadSoStartupTaskInnerJson = R"(
        {
        }
    )"_json;
    bool ret = startupManager->AnalyzePreloadSoStartupTaskInner(info, preloadSoStartupTaskInnerJson,
        preloadSoStartupTasks);
    EXPECT_EQ(ret, false);

    nlohmann::json preloadSoStartupTaskInnerJson1 = R"(
        {
            "ohmurl": "test_ohmurl",
            "name": "test_name"
        }
    )"_json;
    ret = startupManager->AnalyzePreloadSoStartupTaskInner(info, preloadSoStartupTaskInnerJson1,
        preloadSoStartupTasks);
    EXPECT_EQ(ret, true);

    nlohmann::json preloadSoStartupTaskInnerJson2 = R"(
        {
            "ohmurl": []
        }
    )"_json;
    ret = startupManager->AnalyzePreloadSoStartupTaskInner(info, preloadSoStartupTaskInnerJson2,
        preloadSoStartupTasks);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzePreloadSoStartupTaskInner_0100 end";
}

/**
 * @tc.name: AnalyzePreloadSoStartupTaskInner_0200
 * @tc.type: FUNC
 * @tc.Function: AnalyzePreloadSoStartupTaskInner
 */
HWTEST_F(StartupManagerTest, AnalyzePreloadSoStartupTaskInner_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzePreloadSoStartupTaskInner_0200 start";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string name = "test_name";
    ModuleStartupConfigInfo info(name, "", "", AppExecFwk::ModuleType::UNKNOWN, false);
    std::map<std::string, std::shared_ptr<AppStartupTask>> preloadSoStartupTasks;
    nlohmann::json preloadSoStartupTaskInnerJson = R"(
        {
            "ohmurl": "test_ohmurl"
        }
    )"_json;
    bool ret = startupManager->AnalyzePreloadSoStartupTaskInner(info, preloadSoStartupTaskInnerJson,
        preloadSoStartupTasks);
    EXPECT_EQ(ret, false);

    nlohmann::json preloadSoStartupTaskInnerJson2 = R"(
        {
            "ohmurl": "test_ohmurl",
            "name": []
        }
    )"_json;
    ret = startupManager->AnalyzePreloadSoStartupTaskInner(info, preloadSoStartupTaskInnerJson2,
        preloadSoStartupTasks);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "StartupManagerTest AnalyzePreloadSoStartupTaskInner_0200 end";
}

/**
 * @tc.name: GetModuleConfig_0100
 * @tc.type: FUNC
 * @tc.Function: GetModuleConfig
 */
HWTEST_F(StartupManagerTest, GetModuleConfig_0100, Function | MediumTest | Level1)
{
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string name = "test_name";
    std::shared_ptr<PreloadSoStartupTask> appStartupTask = std::make_shared<PreloadSoStartupTask>(name, "duri");
    startupManager->appStartupTasks_.emplace(name, appStartupTask);
    std::string moduleName = "application";
    startupManager->SetModuleConfig(nullptr, moduleName, false);
    EXPECT_EQ(startupManager->moduleConfigs_[moduleName], nullptr);
}

/**
 * @tc.name: RunLoadModuleStartupConfigTask_0100
 * @tc.type: FUNC
 * @tc.Function: RunLoadModuleStartupConfigTask
 */
HWTEST_F(StartupManagerTest, RunLoadModuleStartupConfigTask_0100, Function | MediumTest | Level1)
{
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::string name = "test_name";
    std::shared_ptr<PreloadSoStartupTask> appStartupTask = std::make_shared<PreloadSoStartupTask>(name, "duri");
    startupManager->appStartupTasks_.emplace(name, appStartupTask);
    std::string moduleName = "application";
    bool needRunAutoStartupTask = false;
    std::shared_ptr<AppExecFwk::HapModuleInfo> hapModuleInfo = std::make_shared<AppExecFwk::HapModuleInfo>();
    hapModuleInfo->name = moduleName;
    startupManager->isModuleStartupConfigInited_.emplace(moduleName);
    int32_t result = startupManager->RunLoadModuleStartupConfigTask(needRunAutoStartupTask, hapModuleInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: GetStartupConfigString_0200
 * @tc.type: FUNC
 * @tc.Function: GetStartupConfigString
 */
HWTEST_F(StartupManagerTest, GetStartupConfigString_0200, Function | MediumTest | Level1)
{
    std::string name = "test_name";
    std::string config = "test_config";
    std::string startupConfig = "$profile:test";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    std::shared_ptr<Extractor> extractorPtr = std::make_shared<Extractor>("test");
    AbilityBase::ExtractorUtil::extractorMap_.insert(std::make_pair("hap", extractorPtr));
    ModuleStartupConfigInfo info(name, startupConfig, "hap", AppExecFwk::ModuleType::UNKNOWN, false);
    int32_t ret = startupManager->GetStartupConfigString(info, config);
    EXPECT_EQ(ret, ERR_STARTUP_CONFIG_PATH_ERROR);
}

/**
 * @tc.name: PreloadSoStartupTask_0100
 * @tc.type: FUNC
 * @tc.Function: RunTaskInit
 */
HWTEST_F(StartupManagerTest, PreloadSoStartupTask_0100, Function | MediumTest | Level1)
{
    std::string name = "test_name";
    std::string ohmUrl = "@normalized:Y&&<bundleName>&<IMPORT_PATH>&<VERSION>";
    std::shared_ptr<PreloadSoStartupTask> startupTask = std::make_shared<PreloadSoStartupTask>(name, ohmUrl);
    auto ret = startupTask->RunTaskInit(nullptr);
    EXPECT_EQ(ret, ERR_STARTUP_INTERNAL_ERROR);
}

}
}