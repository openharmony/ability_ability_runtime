/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <cstdarg>
#include <gtest/gtest.h>
#include <string>

#include "hilog_tag_wrapper.h"
#include "ohos_sts_environment_impl.h"
#include "sts_runtime.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class OHOSStsEnvironmentTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void OHOSStsEnvironmentTest::SetUpTestCase() {}

void OHOSStsEnvironmentTest::TearDownTestCase() {}

void OHOSStsEnvironmentTest::SetUp() {}

void OHOSStsEnvironmentTest::TearDown() {}

/**
 * @tc.name: PostTask_0100
 * @tc.desc: Sts environment post and remove task.
 * @tc.type: FUNC
 * @tc.require: issueI6KODF
 */
HWTEST_F(OHOSStsEnvironmentTest, PostTask_0100, TestSize.Level0)
{
    auto stsEnvImpl = std::make_shared<OHOSStsEnvironmentImpl>();
    ASSERT_NE(stsEnvImpl, nullptr);

    std::string taskName = "task001";
    auto task = [name = taskName]() { TAG_LOGI(AAFwkTag::TEST, "%{public}s called.", name.c_str()); };
    int64_t delayTime = 1000;
    stsEnvImpl->PostTask(task, taskName, delayTime);
    stsEnvImpl->RemoveTask(taskName);
}

/**
 * @tc.name: PostSyncTask_0100
 * @tc.desc: Sts environment post sync task.
 * @tc.type: FUNC
 * @tc.require: issueI7C87T
 */
HWTEST_F(OHOSStsEnvironmentTest, PostSyncTask_0100, TestSize.Level0)
{
    auto runner = AppExecFwk::EventRunner::Create("TASK_RUNNER");
    ASSERT_NE(runner, nullptr);
    auto stsEnvImpl = std::make_shared<OHOSStsEnvironmentImpl>(runner);
    ASSERT_NE(stsEnvImpl, nullptr);

    auto ret = stsEnvImpl->InitLoop(true);
    ASSERT_EQ(ret, true);

    std::string taskName = "syncTask001";
    bool taskExecuted = false;
    auto task = [taskName, &taskExecuted]() {
        TAG_LOGI(AAFwkTag::TEST, "%{public}s called.", taskName.c_str());
        taskExecuted = true;
    };
    stsEnvImpl->PostSyncTask(task, taskName);
    EXPECT_EQ(taskExecuted, true);
}

/**
 * @tc.name: PostSyncTask_0200
 * @tc.desc: Sts environment post sync task.
 * @tc.type: FUNC
 * @tc.require: issueI7C87T
 */
HWTEST_F(OHOSStsEnvironmentTest, PostSyncTask_0200, TestSize.Level0)
{
    auto runner = AppExecFwk::EventRunner::Create("TASK_RUNNER");
    ASSERT_NE(runner, nullptr);
    auto stsEnvImpl = std::make_shared<OHOSStsEnvironmentImpl>(runner);
    ASSERT_NE(stsEnvImpl, nullptr);

    auto ret = stsEnvImpl->InitLoop(true);
    ASSERT_EQ(ret, true);

    ret = false;
    stsEnvImpl->DeInitLoop();
    ret = stsEnvImpl->ReInitUVLoop();
    ASSERT_EQ(ret, true);

    std::string taskName = "syncTask001";
    bool taskExecuted = false;
    auto task = [taskName, &taskExecuted]() {
        TAG_LOGI(AAFwkTag::TEST, "%{public}s called.", taskName.c_str());
        taskExecuted = true;
    };
    stsEnvImpl->PostSyncTask(task, taskName);
    EXPECT_EQ(taskExecuted, true);
}
} // namespace AbilityRuntime
} // namespace OHOS