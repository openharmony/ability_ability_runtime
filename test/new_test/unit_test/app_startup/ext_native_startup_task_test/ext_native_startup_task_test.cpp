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

#include "ext_native_startup_task.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::AbilityRuntime {
namespace {
const std::string TEST_EXT_NATIVE_STARTUP_TASK_NAME = "TestExtNativeStartupTaskName";
}
class TestExtNativeStartupTask : public ExtNativeStartupTask {
public:
    explicit TestExtNativeStartupTask(const std::string &name) : ExtNativeStartupTask(name)
    {}

    MOCK_METHOD(int32_t, RunTask, (), (override));
};

class ExtNativeStartupTaskTest : public Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void ExtNativeStartupTaskTest::SetUpTestCase()
{}

void ExtNativeStartupTaskTest::TearDownTestCase()
{}

void ExtNativeStartupTaskTest::SetUp()
{}

void ExtNativeStartupTaskTest::TearDown()
{}

/**
 * @tc.name: GetName_001
 * @tc.desc: Verify getName call.
 * @tc.type: FUNC
 */
HWTEST_F(ExtNativeStartupTaskTest, GetName_001, TestSize.Level1)
{
    std::shared_ptr<ExtNativeStartupTask> task1 = std::make_shared<TestExtNativeStartupTask>("");
    EXPECT_STREQ(task1->GetName().c_str(), "");

    std::shared_ptr<ExtNativeStartupTask> task2 =
        std::make_shared<TestExtNativeStartupTask>(TEST_EXT_NATIVE_STARTUP_TASK_NAME);
    EXPECT_STREQ(task2->GetName().c_str(), TEST_EXT_NATIVE_STARTUP_TASK_NAME.c_str());
}

/**
 * @tc.name: RunTask_001
 * @tc.desc: Verify RunTask call.
 * @tc.type: FUNC
 */
HWTEST_F(ExtNativeStartupTaskTest, RunTask_001, TestSize.Level1)
{
    std::shared_ptr<TestExtNativeStartupTask> task1 = std::make_shared<TestExtNativeStartupTask>("");
    std::shared_ptr<ExtNativeStartupTask> baseTask1 = task1;
    EXPECT_CALL(*task1, RunTask()).Times(1).WillOnce(Return(1));
    EXPECT_EQ(baseTask1->RunTask(), 1);

    std::shared_ptr<TestExtNativeStartupTask> task2 =
        std::make_shared<TestExtNativeStartupTask>(TEST_EXT_NATIVE_STARTUP_TASK_NAME);
    std::shared_ptr<ExtNativeStartupTask> baseTask2 = task2;
    EXPECT_CALL(*task2, RunTask()).Times(1).WillOnce(Return(0));
    EXPECT_EQ(baseTask2->RunTask(), 0);
}
} // namespace OHOS::AbilityRuntime