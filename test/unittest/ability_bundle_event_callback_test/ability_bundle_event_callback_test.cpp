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

#include <gtest/gtest.h>
#define private public
#define protected public
#include "ability_bundle_event_callback.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
namespace OHOS {
namespace AAFwk {
class AbilityBundleEventCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void AbilityBundleEventCallbackTest::SetUpTestCase(void) {}
void AbilityBundleEventCallbackTest::TearDownTestCase(void) {}
void AbilityBundleEventCallbackTest::TearDown() {}
void AbilityBundleEventCallbackTest::SetUp() {}

class MockTaskHandlerWrap : public AAFwk::TaskHandlerWrap {
public:
    explicit MockTaskHandlerWrap(const std::string &queueName = "") : TaskHandlerWrap(queueName) {};

    virtual ~MockTaskHandlerWrap() {};

    std::shared_ptr<AAFwk::InnerTaskHandle> SubmitTaskInner(
        std::function<void()>&& task, const AAFwk::TaskAttribute& taskAttr) override
    {
        taskCount++;
        task();
        return nullptr;
    }

    bool CancelTaskInner(const std::shared_ptr<AAFwk::InnerTaskHandle>& taskHandle) override
    {
        return false;
    }

    void WaitTaskInner(const std::shared_ptr<AAFwk::InnerTaskHandle>& taskHandle) override
    {
        return;
    }

    uint64_t GetTaskCount() override
    {
        return tasks_.size();
    }

    int32_t taskCount = 0;
};

/**
 * @tc.name: AbilityBundleEventCallbackTest_OnReceiveEvent_0100
 * @tc.desc: Test the state of OnReceiveEvent
 * @tc.type: FUNC
 */
HWTEST_F(AbilityBundleEventCallbackTest, OnReceiveEvent_0100, TestSize.Level1)
{
    sptr<AbilityBundleEventCallback> abilityBundleEventCallback_ =
        new (std::nothrow) AbilityBundleEventCallback(nullptr, nullptr);
    EXPECT_NE(abilityBundleEventCallback_, nullptr);
    EventFwk::CommonEventData eventData;
    abilityBundleEventCallback_->OnReceiveEvent(eventData);
    EXPECT_EQ(abilityBundleEventCallback_->taskHandler_, nullptr);
}

/**
 * @tc.name: AbilityBundleEventCallbackTest_OnReceiveEvent_0200
 * @tc.desc: Test the state of OnReceiveEvent
 * @tc.type: FUNC
 */
HWTEST_F(AbilityBundleEventCallbackTest, OnReceiveEvent_0200, TestSize.Level1)
{
    sptr<AbilityBundleEventCallback> abilityBundleEventCallback_ =
        new (std::nothrow) AbilityBundleEventCallback(nullptr, nullptr);
    EXPECT_NE(abilityBundleEventCallback_, nullptr);
    abilityBundleEventCallback_->taskHandler_ = TaskHandlerWrap::CreateQueueHandler("AbilityBundleEventCallbackTest");
    EventFwk::CommonEventData eventData;
    abilityBundleEventCallback_->OnReceiveEvent(eventData);
    EXPECT_NE(abilityBundleEventCallback_->taskHandler_, nullptr);
}

/**
 * @tc.name: AbilityBundleEventCallbackTest_OnReceiveEvent_0300
 * @tc.desc: Test the state of OnReceiveEvent
 * @tc.type: FUNC
 */
HWTEST_F(AbilityBundleEventCallbackTest, OnReceiveEvent_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnReceiveEvent_0300 start";

    sptr<AbilityBundleEventCallback> abilityBundleEventCallback_ =
        new (std::nothrow) AbilityBundleEventCallback(nullptr, nullptr);
    EXPECT_NE(abilityBundleEventCallback_, nullptr);

    auto mockHandler = std::make_shared<MockTaskHandlerWrap>();
    abilityBundleEventCallback_->taskHandler_ = mockHandler;
    EventFwk::CommonEventData eventData;
    Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    want.SetBundle("com.test.demo");
    want.SetParam("isRecover", false);
    eventData.SetWant(want);

    abilityBundleEventCallback_->OnReceiveEvent(eventData);
    EXPECT_TRUE(mockHandler->taskCount >= 0);

    GTEST_LOG_(INFO) << "OnReceiveEvent_0300 end";
}

/**
 * @tc.name: AbilityBundleEventCallbackTest_OnReceiveEvent_0400
 * @tc.desc: Test the state of OnReceiveEvent
 * @tc.type: FUNC
 */
HWTEST_F(AbilityBundleEventCallbackTest, OnReceiveEvent_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnReceiveEvent_0400 start";

    sptr<AbilityBundleEventCallback> abilityBundleEventCallback_ =
        new (std::nothrow) AbilityBundleEventCallback(nullptr, nullptr);
    EXPECT_NE(abilityBundleEventCallback_, nullptr);

    auto mockHandler = std::make_shared<MockTaskHandlerWrap>();
    abilityBundleEventCallback_->taskHandler_ = mockHandler;
    EventFwk::CommonEventData eventData;
    Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    want.SetBundle("com.test.demo");
    want.SetParam("isRecover", true);
    eventData.SetWant(want);

    abilityBundleEventCallback_->OnReceiveEvent(eventData);
    EXPECT_TRUE(mockHandler->taskCount >= 1);

    GTEST_LOG_(INFO) << "OnReceiveEvent_0400 end";
}
} // namespace AAFwk
} // namespace OHOS
