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
#include "load_ability_callback_impl.h"
#include "hilog_tag_wrapper.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
using namespace OHOS::AbilityRuntime;
namespace OHOS {
namespace AAFwk {
class LoadAbilityCallbackImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void LoadAbilityCallbackImplTest::SetUpTestCase(void) {}
void LoadAbilityCallbackImplTest::TearDownTestCase(void) {}
void LoadAbilityCallbackImplTest::TearDown() {}
void LoadAbilityCallbackImplTest::SetUp() {}

/**
 * @tc.name: LoadAbilityCallbackImplTest_OnFinish_0001
 * @tc.desc: Test the state of OnFinish
 * @tc.type: FUNC
 */
HWTEST_F(LoadAbilityCallbackImplTest, OnFinish_0001, TestSize.Level1)
{
    bool called = false;
    int32_t targetPid = -1;
    OnFinishTask task = [&called, &targetPid](int32_t pid) {
        targetPid = pid;
        called = true;
    };
    auto callbackImpl = std::make_shared<LoadAbilityCallbackImpl>(std::move(task));
    int32_t pid = 10000;
    callbackImpl->OnFinish(pid);
    EXPECT_NE(callbackImpl->task_, nullptr);
    EXPECT_TRUE(called);
    EXPECT_EQ(targetPid, pid);
}

/**
 * @tc.name: LoadAbilityCallbackImplTest_Cancel_0001
 * @tc.desc: Test the state of Cancel
 * @tc.type: FUNC
 */
HWTEST_F(LoadAbilityCallbackImplTest, Cancel_0001, TestSize.Level1)
{
    bool called = false;
    int32_t targetPid = -1;
    OnFinishTask task = [&called, &targetPid](int32_t pid) {
        targetPid = pid;
        called = true;
    };
    auto callbackImpl = std::make_shared<LoadAbilityCallbackImpl>(std::move(task));
    EXPECT_NE(callbackImpl->task_, nullptr);

    callbackImpl->Cancel();
    int32_t pid = 10000;
    callbackImpl->OnFinish(pid);
    EXPECT_EQ(callbackImpl->task_, nullptr);
    EXPECT_FALSE(called);
    EXPECT_NE(targetPid, pid);
}
} // namespace AAFwk
} // namespace OHOS
