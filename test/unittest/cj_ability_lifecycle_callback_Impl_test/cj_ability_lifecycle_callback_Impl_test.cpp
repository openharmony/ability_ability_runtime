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

#include <gtest/gtest.h>

#include "cj_ability_lifecycle_callback_impl.h"
#include "hilog_tag_wrapper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class CjAbilityLifecycleCallbackImplTest : public testing::Test {
public:
    CjAbilityLifecycleCallbackImplTest() {}
    ~CjAbilityLifecycleCallbackImplTest() {}
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void CjAbilityLifecycleCallbackImplTest::SetUpTestCase() {}

void CjAbilityLifecycleCallbackImplTest::TearDownTestCase() {}

void CjAbilityLifecycleCallbackImplTest::SetUp() {}

void CjAbilityLifecycleCallbackImplTest::TearDown() {}

void WindowStagePtrTest()
{
    return;
}

template<typename CallbackMap>
void RegisterCallback(CallbackMap& callbackMap, int32_t id, std::function<void(int64_t)> callback)
{
    callbackMap[id] = callback;
}

template<typename CallbackMap>
void RegisterCallback(CallbackMap& callbackMap, int32_t id, std::function<void(int64_t, WindowStagePtr)> callback)
{
    callbackMap[id] = callback;
}

/**
 * @tc.number: CjAbilityLifecycleCallbackImpl_OnNewWant_100
 * @tc.name: OnNewWant
 * @tc.desc: OnNewWant
 */
HWTEST_F(CjAbilityLifecycleCallbackImplTest, CjAbilityLifecycleCallbackImpl_OnNewWant_100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnNewWant_100 start");
    std::shared_ptr<CjAbilityLifecycleCallbackImpl> cjAbilityLifecycleCallbackImpl =
        std::make_shared<CjAbilityLifecycleCallbackImpl>();
    ASSERT_NE(cjAbilityLifecycleCallbackImpl, nullptr);

    int64_t testAbility = 1;
    bool callbackCalled = false;
    std::function<void(int64_t)> callback = [&callbackCalled](int64_t value) { callbackCalled = true; };
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onNewWantcallbacks_.size(), 0);
    RegisterCallback(cjAbilityLifecycleCallbackImpl->onNewWantcallbacks_, testAbility, callback);
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onNewWantcallbacks_.size(), 1);
    cjAbilityLifecycleCallbackImpl->OnNewWant(testAbility);
    EXPECT_TRUE(callbackCalled);

    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnNewWant_100 end");
}

/**
 * @tc.number: CjAbilityLifecycleCallbackImpl_OnWillNewWant_100
 * @tc.name: OnWillNewWant
 * @tc.desc: OnWillNewWant
 */
HWTEST_F(CjAbilityLifecycleCallbackImplTest, CjAbilityLifecycleCallbackImpl_OnWillNewWant_100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnWillNewWant_100 start");
    std::shared_ptr<CjAbilityLifecycleCallbackImpl> cjAbilityLifecycleCallbackImpl =
        std::make_shared<CjAbilityLifecycleCallbackImpl>();
    ASSERT_NE(cjAbilityLifecycleCallbackImpl, nullptr);

    int64_t testAbility = 1;
    bool callbackCalled = false;
    std::function<void(int64_t)> callback = [&callbackCalled](int64_t value) { callbackCalled = true; };
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onWillNewWantcallbacks_.size(), 0);
    RegisterCallback(cjAbilityLifecycleCallbackImpl->onWillNewWantcallbacks_, testAbility, callback);
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onWillNewWantcallbacks_.size(), 1);
    cjAbilityLifecycleCallbackImpl->OnWillNewWant(testAbility);
    EXPECT_TRUE(callbackCalled);

    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnWillNewWant_100 end");
}

/**
 * @tc.number: CjAbilityLifecycleCallbackImpl_OnAbilityWillCreate_100
 * @tc.name: OnAbilityWillCreate
 * @tc.desc: OnAbilityWillCreate
 */
HWTEST_F(CjAbilityLifecycleCallbackImplTest, CjAbilityLifecycleCallbackImpl_OnAbilityWillCreate_100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnAbilityWillCreate_100 start");
    std::shared_ptr<CjAbilityLifecycleCallbackImpl> cjAbilityLifecycleCallbackImpl =
        std::make_shared<CjAbilityLifecycleCallbackImpl>();
    ASSERT_NE(cjAbilityLifecycleCallbackImpl, nullptr);

    int64_t testAbility = 1;
    bool callbackCalled = false;
    std::function<void(int64_t)> callback = [&callbackCalled](int64_t value) { callbackCalled = true; };
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onAbilityWillCreatecallbacks_.size(), 0);
    RegisterCallback(cjAbilityLifecycleCallbackImpl->onAbilityWillCreatecallbacks_, testAbility, callback);
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onAbilityWillCreatecallbacks_.size(), 1);
    cjAbilityLifecycleCallbackImpl->OnAbilityWillCreate(testAbility);
    EXPECT_TRUE(callbackCalled);

    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnAbilityWillCreate_100 end");
}

/**
 * @tc.number: CjAbilityLifecycleCallbackImpl_OnAbilityWillDestroy_100
 * @tc.name: OnAbilityWillDestroy
 * @tc.desc: OnAbilityWillDestroy
 */
HWTEST_F(CjAbilityLifecycleCallbackImplTest, CjAbilityLifecycleCallbackImpl_OnAbilityWillDestroy_100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnAbilityWillDestroy_100 start");
    std::shared_ptr<CjAbilityLifecycleCallbackImpl> cjAbilityLifecycleCallbackImpl =
        std::make_shared<CjAbilityLifecycleCallbackImpl>();
    ASSERT_NE(cjAbilityLifecycleCallbackImpl, nullptr);

    int64_t testAbility = 1;
    bool callbackCalled = false;
    std::function<void(int64_t)> callback = [&callbackCalled](int64_t value) { callbackCalled = true; };
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onAbilityWillDestroycallbacks_.size(), 0);
    RegisterCallback(cjAbilityLifecycleCallbackImpl->onAbilityWillDestroycallbacks_, testAbility, callback);
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onAbilityWillDestroycallbacks_.size(), 1);
    cjAbilityLifecycleCallbackImpl->OnAbilityWillDestroy(testAbility);
    EXPECT_TRUE(callbackCalled);

    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnAbilityWillDestroy_100 end");
}

/**
 * @tc.number: CjAbilityLifecycleCallbackImpl_OnAbilityWillForeground_100
 * @tc.name: OnAbilityWillForeground
 * @tc.desc: OnAbilityWillForeground
 */
HWTEST_F(
    CjAbilityLifecycleCallbackImplTest, CjAbilityLifecycleCallbackImpl_OnAbilityWillForeground_100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnAbilityWillForeground_100 start");
    std::shared_ptr<CjAbilityLifecycleCallbackImpl> cjAbilityLifecycleCallbackImpl =
        std::make_shared<CjAbilityLifecycleCallbackImpl>();
    ASSERT_NE(cjAbilityLifecycleCallbackImpl, nullptr);

    int64_t testAbility = 1;
    bool callbackCalled = false;
    std::function<void(int64_t)> callback = [&callbackCalled](int64_t value) { callbackCalled = true; };
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onAbilityWillForegroundcallbacks_.size(), 0);
    RegisterCallback(cjAbilityLifecycleCallbackImpl->onAbilityWillForegroundcallbacks_, testAbility, callback);
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onAbilityWillForegroundcallbacks_.size(), 1);
    cjAbilityLifecycleCallbackImpl->OnAbilityWillForeground(testAbility);
    EXPECT_TRUE(callbackCalled);

    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnAbilityWillForeground_100 end");
}

/**
 * @tc.number: CjAbilityLifecycleCallbackImpl_OnAbilityWillBackground_100
 * @tc.name: OnAbilityWillBackground
 * @tc.desc: OnAbilityWillBackground
 */
HWTEST_F(
    CjAbilityLifecycleCallbackImplTest, CjAbilityLifecycleCallbackImpl_OnAbilityWillBackground_100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnAbilityWillBackground_100 start");

    std::shared_ptr<CjAbilityLifecycleCallbackImpl> cjAbilityLifecycleCallbackImpl =
        std::make_shared<CjAbilityLifecycleCallbackImpl>();
    ASSERT_NE(cjAbilityLifecycleCallbackImpl, nullptr);

    int64_t testAbility = 1;
    bool callbackCalled = false;
    std::function<void(int64_t)> callback = [&callbackCalled](int64_t value) { callbackCalled = true; };
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onAbilityWillBackgroundcallbacks_.size(), 0);
    RegisterCallback(cjAbilityLifecycleCallbackImpl->onAbilityWillBackgroundcallbacks_, testAbility, callback);
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onAbilityWillBackgroundcallbacks_.size(), 1);
    cjAbilityLifecycleCallbackImpl->OnAbilityWillBackground(testAbility);
    EXPECT_TRUE(callbackCalled);

    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnAbilityWillBackground_100 end");
}

/**
 * @tc.number: CjAbilityLifecycleCallbackImpl_OnAbilityWillContinue_100
 * @tc.name: OnAbilityWillContinue
 * @tc.desc: OnAbilityWillContinue
 */
HWTEST_F(CjAbilityLifecycleCallbackImplTest, CjAbilityLifecycleCallbackImpl_OnAbilityWillContinue_100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnAbilityWillContinue_100 start");

    std::shared_ptr<CjAbilityLifecycleCallbackImpl> cjAbilityLifecycleCallbackImpl =
        std::make_shared<CjAbilityLifecycleCallbackImpl>();
    ASSERT_NE(cjAbilityLifecycleCallbackImpl, nullptr);

    int64_t testAbility = 1;
    bool callbackCalled = false;
    std::function<void(int64_t)> callback = [&callbackCalled](int64_t value) { callbackCalled = true; };
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onAbilityWillContinuecallbacks_.size(), 0);
    RegisterCallback(cjAbilityLifecycleCallbackImpl->onAbilityWillContinuecallbacks_, testAbility, callback);
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onAbilityWillContinuecallbacks_.size(), 1);
    cjAbilityLifecycleCallbackImpl->OnAbilityWillContinue(testAbility);
    EXPECT_TRUE(callbackCalled);

    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnAbilityWillContinue_100 end");
}

/**
 * @tc.number: CjAbilityLifecycleCallbackImpl_OnAbilityWillSaveState_100
 * @tc.name: OnAbilityWillSaveState
 * @tc.desc: OnAbilityWillSaveState
 */
HWTEST_F(CjAbilityLifecycleCallbackImplTest, CjAbilityLifecycleCallbackImpl_OnAbilityWillSaveState_100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnAbilityWillSaveState_100 start");

    std::shared_ptr<CjAbilityLifecycleCallbackImpl> cjAbilityLifecycleCallbackImpl =
        std::make_shared<CjAbilityLifecycleCallbackImpl>();
    ASSERT_NE(cjAbilityLifecycleCallbackImpl, nullptr);

    int64_t testAbility = 1;
    bool callbackCalled = false;
    std::function<void(int64_t)> callback = [&callbackCalled](int64_t value) { callbackCalled = true; };
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onAbilityWillSaveStatecallbacks_.size(), 0);
    RegisterCallback(cjAbilityLifecycleCallbackImpl->onAbilityWillSaveStatecallbacks_, testAbility, callback);
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onAbilityWillSaveStatecallbacks_.size(), 1);
    cjAbilityLifecycleCallbackImpl->OnAbilityWillSaveState(testAbility);
    EXPECT_TRUE(callbackCalled);

    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnAbilityWillSaveState_100 end");
}

/**
 * @tc.number: CjAbilityLifecycleCallbackImpl_OnAbilitySaveState_100
 * @tc.name: OnAbilitySaveState
 * @tc.desc: OnAbilitySaveState
 */
HWTEST_F(CjAbilityLifecycleCallbackImplTest, CjAbilityLifecycleCallbackImpl_OnAbilitySaveState_100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnAbilitySaveState_100 start");

    std::shared_ptr<CjAbilityLifecycleCallbackImpl> cjAbilityLifecycleCallbackImpl =
        std::make_shared<CjAbilityLifecycleCallbackImpl>();
    ASSERT_NE(cjAbilityLifecycleCallbackImpl, nullptr);

    int64_t testAbility = 1;
    bool callbackCalled = false;
    std::function<void(int64_t)> callback = [&callbackCalled](int64_t value) { callbackCalled = true; };
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onAbilitySaveStatecallbacks_.size(), 0);
    RegisterCallback(cjAbilityLifecycleCallbackImpl->onAbilitySaveStatecallbacks_, testAbility, callback);
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onAbilitySaveStatecallbacks_.size(), 1);
    cjAbilityLifecycleCallbackImpl->OnAbilitySaveState(testAbility);
    EXPECT_TRUE(callbackCalled);

    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnAbilitySaveState_100 end");
}

/**
 * @tc.number: CjAbilityLifecycleCallbackImpl_OnWindowStageWillCreate_100
 * @tc.name: OnWindowStageWillCreate
 * @tc.desc: OnWindowStageWillCreate
 */
HWTEST_F(
    CjAbilityLifecycleCallbackImplTest, CjAbilityLifecycleCallbackImpl_OnWindowStageWillCreate_100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnWindowStageWillCreate_100 start");

    std::shared_ptr<CjAbilityLifecycleCallbackImpl> cjAbilityLifecycleCallbackImpl =
        std::make_shared<CjAbilityLifecycleCallbackImpl>();
    ASSERT_NE(cjAbilityLifecycleCallbackImpl, nullptr);

    int64_t testAbility = 1;
    bool callbackCalled = false;
    std::function<void(int64_t, WindowStagePtr)> callback =
        [&callbackCalled](int64_t value, WindowStagePtr cjWindowStage) { callbackCalled = true; };
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onWindowStageWillCreatecallbacks_.size(), 0);
    RegisterCallback(cjAbilityLifecycleCallbackImpl->onWindowStageWillCreatecallbacks_, testAbility, callback);
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onWindowStageWillCreatecallbacks_.size(), 1);
    WindowStagePtr windowStageTest = reinterpret_cast<WindowStagePtr>(&WindowStagePtrTest);
    cjAbilityLifecycleCallbackImpl->OnWindowStageWillCreate(testAbility, windowStageTest);
    EXPECT_TRUE(callbackCalled);

    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnWindowStageWillCreate_100 end");
}

/**
 * @tc.number: CjAbilityLifecycleCallbackImpl_OnWindowStageWillDestroy_100
 * @tc.name: OnWindowStageWillDestroy
 * @tc.desc: OnWindowStageWillDestroy
 */
HWTEST_F(
    CjAbilityLifecycleCallbackImplTest, CjAbilityLifecycleCallbackImpl_OnWindowStageWillDestroy_100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnWindowStageWillDestroy_100 start");

    std::shared_ptr<CjAbilityLifecycleCallbackImpl> cjAbilityLifecycleCallbackImpl =
        std::make_shared<CjAbilityLifecycleCallbackImpl>();
    ASSERT_NE(cjAbilityLifecycleCallbackImpl, nullptr);

    int64_t testAbility = 1;
    bool callbackCalled = false;
    std::function<void(int64_t, WindowStagePtr)> callback =
        [&callbackCalled](int64_t value, WindowStagePtr cjWindowStage) { callbackCalled = true; };
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onWindowStageWillDestroycallbacks_.size(), 0);
    RegisterCallback(cjAbilityLifecycleCallbackImpl->onWindowStageWillDestroycallbacks_, testAbility, callback);
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onWindowStageWillDestroycallbacks_.size(), 1);
    WindowStagePtr windowStageTest = reinterpret_cast<WindowStagePtr>(&WindowStagePtrTest);
    cjAbilityLifecycleCallbackImpl->OnWindowStageWillDestroy(testAbility, windowStageTest);
    EXPECT_TRUE(callbackCalled);

    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnWindowStageWillDestroy_100 end");
}

/**
 * @tc.number: CjAbilityLifecycleCallbackImpl_OnWindowStageWillRestore_100
 * @tc.name: OnWindowStageWillRestore
 * @tc.desc: OnWindowStageWillRestore
 */
HWTEST_F(
    CjAbilityLifecycleCallbackImplTest, CjAbilityLifecycleCallbackImpl_OnWindowStageWillRestore_100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnWindowStageWillRestore_100 start");

    std::shared_ptr<CjAbilityLifecycleCallbackImpl> cjAbilityLifecycleCallbackImpl =
        std::make_shared<CjAbilityLifecycleCallbackImpl>();
    ASSERT_NE(cjAbilityLifecycleCallbackImpl, nullptr);

    int64_t testAbility = 1;
    bool callbackCalled = false;
    std::function<void(int64_t, WindowStagePtr)> callback =
        [&callbackCalled](int64_t value, WindowStagePtr cjWindowStage) { callbackCalled = true; };
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onWindowStageWillRestorecallbacks_.size(), 0);
    RegisterCallback(cjAbilityLifecycleCallbackImpl->onWindowStageWillRestorecallbacks_, testAbility, callback);
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onWindowStageWillRestorecallbacks_.size(), 1);
    WindowStagePtr windowStageTest = reinterpret_cast<WindowStagePtr>(&WindowStagePtrTest);
    cjAbilityLifecycleCallbackImpl->OnWindowStageWillRestore(testAbility, windowStageTest);
    EXPECT_TRUE(callbackCalled);

    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnWindowStageWillRestore_100 end");
}

/**
 * @tc.number: CjAbilityLifecycleCallbackImpl_OnWindowStageRestore_100
 * @tc.name: OnWindowStageRestore
 * @tc.desc: OnWindowStageRestore
 */
HWTEST_F(CjAbilityLifecycleCallbackImplTest, CjAbilityLifecycleCallbackImpl_OnWindowStageRestore_100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnWindowStageRestore_100 start");

    std::shared_ptr<CjAbilityLifecycleCallbackImpl> cjAbilityLifecycleCallbackImpl =
        std::make_shared<CjAbilityLifecycleCallbackImpl>();
    ASSERT_NE(cjAbilityLifecycleCallbackImpl, nullptr);

    int64_t testAbility = 1;
    bool callbackCalled = false;
    std::function<void(int64_t, WindowStagePtr)> callback =
        [&callbackCalled](int64_t value, WindowStagePtr cjWindowStage) { callbackCalled = true; };
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onWindowStageRestorecallbacks_.size(), 0);
    RegisterCallback(cjAbilityLifecycleCallbackImpl->onWindowStageRestorecallbacks_, testAbility, callback);
    EXPECT_EQ(cjAbilityLifecycleCallbackImpl->onWindowStageRestorecallbacks_.size(), 1);
    WindowStagePtr windowStageTest = reinterpret_cast<WindowStagePtr>(&WindowStagePtrTest);
    cjAbilityLifecycleCallbackImpl->OnWindowStageRestore(testAbility, windowStageTest);
    EXPECT_TRUE(callbackCalled);

    TAG_LOGI(AAFwkTag::TEST, "CjAbilityLifecycleCallbackImpl_OnWindowStageRestore_100 end");
}
} // namespace AbilityRuntime
} // namespace OHOS