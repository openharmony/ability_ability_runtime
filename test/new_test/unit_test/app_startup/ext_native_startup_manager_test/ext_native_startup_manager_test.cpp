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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ext_native_startup_manager.h"

#include "startup_utils.h"

// mock
#include "ext_native_startup_task.h"
#include "startup_manager.h"
#include "startup_task.h"
#include "startup_task_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::AbilityRuntime {
namespace {
const std::string TEST_EXT_NATIVE_STARTUP_TASK_NAME = "TestExtNativeStartupTaskName";
};
class TestExtNativeStartupTask : public ExtNativeStartupTask {
public:
    explicit TestExtNativeStartupTask(const std::string &name) : ExtNativeStartupTask(name)
    {}

    MOCK_METHOD(int32_t, RunTask, (), (override));
};

class ExtNativeStartupManagerTest : public Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void ExtNativeStartupManagerTest::SetUpTestCase()
{
    ExtNativeStartupManager::LoadExtStartupTask();
}

void ExtNativeStartupManagerTest::TearDownTestCase()
{}

void ExtNativeStartupManagerTest::SetUp()
{}

void ExtNativeStartupManagerTest::TearDown()
{}

/**
 * @tc.name: BuildExtStartupTask_001
 * @tc.desc: Verify BuildExtStartupTask call.
 *           Branch extNativeStartupTask = nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ExtNativeStartupManagerTest, BuildExtStartupTask_001, TestSize.Level1)
{
    std::shared_ptr<StartupTask> startupTask;
    int32_t res = ExtNativeStartupManager::BuildExtStartupTask(nullptr, startupTask);
    EXPECT_EQ(res, ERR_STARTUP_INVALID_VALUE);
}

/**
 * @tc.name: BuildExtStartupTask_002
 * @tc.desc: Verify BuildExtStartupTask call.
 * @tc.type: FUNC
 */
HWTEST_F(ExtNativeStartupManagerTest, BuildExtStartupTask_002, TestSize.Level1)
{
    std::shared_ptr<StartupTask> startupTask;
    auto extTask = std::make_shared<TestExtNativeStartupTask>(TEST_EXT_NATIVE_STARTUP_TASK_NAME);
    EXPECT_CALL(*extTask, GetName()).Times(1).WillOnce(ReturnRef(TEST_EXT_NATIVE_STARTUP_TASK_NAME));
    StartupTaskInstanceMgr &mgr = StartupTaskInstanceMgr::GetInstance();
    auto check = [](StartupTask& task) {
        EXPECT_CALL(task, SetCallCreateOnMainThread(false)).Times(1);
        EXPECT_CALL(task, SetWaitOnMainThread(false)).Times(1);
    };
    EXPECT_CALL(mgr, Constructor(_)).Times(1).WillOnce(Invoke(check));

    int32_t res = ExtNativeStartupManager::BuildExtStartupTask(extTask, startupTask);
    EXPECT_EQ(res, ERR_OK);
    ASSERT_NE(startupTask, nullptr);
    EXPECT_STREQ(startupTask->name_.c_str(), TEST_EXT_NATIVE_STARTUP_TASK_NAME.c_str());
    EXPECT_STREQ(startupTask->GetType().c_str(), TEST_EXT_NATIVE_STARTUP_TASK_NAME.c_str());

    std::shared_ptr<StartupTaskResult> result;
    res = startupTask->RunTaskOnDependencyCompleted(TEST_EXT_NATIVE_STARTUP_TASK_NAME, result);
    EXPECT_EQ(res, ERR_OK);

    std::unique_ptr<StartupTaskResultCallback> callback;
    res = startupTask->RunTaskInit(std::move(callback));
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.name: RunNativeStartupTask_001
 * @tc.desc: Verify RunNativeStartupTask call.
 *           Branch Prepare failed
 * @tc.type: FUNC
 */
HWTEST_F(ExtNativeStartupManagerTest, RunNativeStartupTask_001, TestSize.Level1)
{
    std::map<std::string, std::shared_ptr<StartupTask>> nativeStartupTask;
    std::shared_ptr<StartupTaskManager> taskManager = std::make_shared<StartupTaskManager>();
    auto check = [nativeStartupTask, taskManager](
        const StartupTaskMap &input, std::shared_ptr<StartupTaskManager> &startupTaskManager) {
        EXPECT_EQ(input, nativeStartupTask);
        startupTaskManager = taskManager;
        return ERR_OK;
    };
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    ASSERT_NE(startupManager, nullptr);
    EXPECT_CALL(*startupManager, BuildStartupTaskManager(_, _)).Times(1).WillOnce(Invoke(check));

    EXPECT_CALL(*taskManager, Prepare()).Times(1).WillOnce(Return(ERR_STARTUP_DEPENDENCY_NOT_FOUND));
    int32_t res = ExtNativeStartupManager::RunNativeStartupTask(nativeStartupTask);
    EXPECT_EQ(res, ERR_STARTUP_DEPENDENCY_NOT_FOUND);
}

/**
 * @tc.name: RunNativeStartupTask_002
 * @tc.desc: Verify RunNativeStartupTask call.
 * @tc.type: FUNC
 */
HWTEST_F(ExtNativeStartupManagerTest, RunNativeStartupTask_002, TestSize.Level1)
{
    std::map<std::string, std::shared_ptr<StartupTask>> nativeStartupTask;
    std::shared_ptr<StartupTaskManager> taskManager = std::make_shared<StartupTaskManager>();
    auto check = [nativeStartupTask, taskManager](
        const StartupTaskMap &input, std::shared_ptr<StartupTaskManager> &startupTaskManager) {
        EXPECT_EQ(input, nativeStartupTask);
        startupTaskManager = taskManager;
        return ERR_OK;
    };
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    ASSERT_NE(startupManager, nullptr);
    EXPECT_CALL(*startupManager, BuildStartupTaskManager(_, _)).Times(1).WillOnce(Invoke(check));

    EXPECT_CALL(*taskManager, Prepare()).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*taskManager, Run(_)).Times(1).WillOnce(Return(ERR_OK));
    int32_t res = ExtNativeStartupManager::RunNativeStartupTask(nativeStartupTask);
    EXPECT_EQ(res, ERR_OK);
}
} // namespace OHOS::AbilityRuntime