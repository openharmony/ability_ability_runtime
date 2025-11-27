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
#include "startup_task_result.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS::AbilityRuntime;
namespace OHOS {
namespace AppExecFwk {
class StartupTaskResultTest : public testing::Test {
public:
    StartupTaskResultTest() {}
    ~StartupTaskResultTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void StartupTaskResultTest::SetUpTestCase(void)
{}

void StartupTaskResultTest::TearDownTestCase(void)
{}

void StartupTaskResultTest::SetUp(void)
{}

void StartupTaskResultTest::TearDown(void)
{}

/**
 * @tc.name: OnCompletedCallback_Call_0100
 * @tc.type: FUNC
 * @tc.Function: OnCompletedCallback_Call
 */
HWTEST_F(StartupTaskResultTest, OnCompletedCallback_Call_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupTaskResultTest OnCompletedCallback_Call_0100 start";

    OnCompletedCallbackFunc func = nullptr;
    OnCompletedCallback callback(func);
    auto result = std::make_shared<StartupTaskResult>();
    callback.Call(result);
    EXPECT_EQ(callback.IsCalled(), false);

    GTEST_LOG_(INFO) << "StartupTaskResultTest OnCompletedCallback_Call_0100 end";
}

/**
 * @tc.name: OnCompletedCallback_Call_0200
 * @tc.type: FUNC
 * @tc.Function: OnCompletedCallback_Call
 */
HWTEST_F(StartupTaskResultTest, OnCompletedCallback_Call_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupTaskResultTest OnCompletedCallback_Call_0200 start";

    bool called = false;
    OnCompletedCallbackFunc func = [&called](const std::shared_ptr<StartupTaskResult> &result) {
        called = true;
    };
    OnCompletedCallback callback(func);
    auto result = std::make_shared<StartupTaskResult>();
    callback.Call(result);
    EXPECT_EQ(callback.IsCalled(), true);
    EXPECT_EQ(called, true);

    GTEST_LOG_(INFO) << "StartupTaskResultTest OnCompletedCallback_Call_0200 end";
}

/**
 * @tc.name: OnCompletedCallback_Call_0300
 * @tc.type: FUNC
 * @tc.Function: OnCompletedCallback_Call
 */
HWTEST_F(StartupTaskResultTest, OnCompletedCallback_Call_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "StartupTaskResultTest OnCompletedCallback_Call_0300 start";

    bool called = false;
    OnCompletedCallbackFunc func = [&called](const std::shared_ptr<StartupTaskResult> &result) {
        called = true;
    };
    OnCompletedCallback callback(func);
    auto result = std::make_shared<StartupTaskResult>();
    callback.isCalled_ = true;
    callback.Call(result);
    EXPECT_EQ(callback.IsCalled(), true);
    EXPECT_EQ(called, false);

    GTEST_LOG_(INFO) << "StartupTaskResultTest OnCompletedCallback_Call_0300 end";
}
}
}