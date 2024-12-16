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
#define private public
#define protected public
#include "ability_manager_event_subscriber.h"
#undef private
#undef protected
#include "common_event_support.h"
#include "hilog_tag_wrapper.h"

using namespace testing::ext;
using namespace testing;
namespace OHOS {
namespace AbilityRuntime {
class AbilityManagerEventSubscriberTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void AbilityManagerEventSubscriberTest::SetUpTestCase(void) {}
void AbilityManagerEventSubscriberTest::TearDownTestCase(void) {}
void AbilityManagerEventSubscriberTest::TearDown() {}
void AbilityManagerEventSubscriberTest::SetUp() {}

/**
 * @tc.name: AbilityManagerEventSubscriberTest_OnReceiveEvent_0001
 * @tc.desc: Test the state of OnReceiveEvent
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerEventSubscriberTest, OnReceiveEvent_0001, TestSize.Level1)
{
    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    std::function<void()> userScreenUnlockCallback = []() {};
    EXPECT_NE(userScreenUnlockCallback, nullptr);
    auto subscriber = std::make_shared<AbilityManagerEventSubscriber>(
        subscribeInfo, userScreenUnlockCallback);
    EventFwk::CommonEventData data;
    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED;
    subscriber->OnReceiveEvent(data);
    EXPECT_NE(subscriber->userScreenUnlockCallback_, nullptr);
}
} // namespace AAFwk
} // namespace OHOS
