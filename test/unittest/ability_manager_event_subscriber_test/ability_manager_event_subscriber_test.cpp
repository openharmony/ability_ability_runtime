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
 * @tc.name: AbilityManagerEventSubscriberTest_ScreenUnlock_OnReceiveEvent_0001
 * @tc.desc: receive other event
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerEventSubscriberTest, ScreenUnlock_OnReceiveEvent_0001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest ScreenUnlock_OnReceiveEvent_0001 start");
    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    std::function<void(int32_t)> callback = [](int32_t) {};
    EXPECT_NE(callback, nullptr);
    auto subscriber = std::make_shared<AbilityScreenUnlockEventSubscriber>(subscribeInfo, callback);
    EventFwk::CommonEventData data;
    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED;
    subscriber->OnReceiveEvent(data);
    EXPECT_NE(subscriber->screenUnlockCallback_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest ScreenUnlock_OnReceiveEvent_0001 end");
}

/**
 * @tc.name: AbilityManagerEventSubscriberTest_ScreenUnlock_OnReceiveEvent_0002
 * @tc.desc: callback is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerEventSubscriberTest, ScreenUnlock_OnReceiveEvent_0002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest ScreenUnlock_OnReceiveEvent_0002 start");
    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    std::function<void(int32_t)> callback = [](int32_t) {};
    EXPECT_NE(callback, nullptr);
    auto subscriber = std::make_shared<AbilityScreenUnlockEventSubscriber>(subscribeInfo, callback);
    EventFwk::CommonEventData data;
    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED;
    subscriber->screenUnlockCallback_ = nullptr;
    subscriber->OnReceiveEvent(data);
    EXPECT_EQ(subscriber->screenUnlockCallback_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest ScreenUnlock_OnReceiveEvent_0002 end");
}

/**
 * @tc.name: AbilityManagerEventSubscriberTest_ScreenUnlock_OnReceiveEvent_0003
 * @tc.desc: receive COMMON_EVENT_SCREEN_UNLOCKED, userId valid, but not trigger callback
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerEventSubscriberTest, ScreenUnlock_OnReceiveEvent_0003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest ScreenUnlock_OnReceiveEvent_0003 start");
    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    std::function<void(int32_t)> callback = [](int32_t) {};
    EXPECT_NE(callback, nullptr);
    auto subscriber = std::make_shared<AbilityScreenUnlockEventSubscriber>(subscribeInfo, callback);
    EventFwk::CommonEventData data;
    int32_t userId = 1;
    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED;
    data.want_.SetParam("userId", userId);
    subscriber->OnReceiveEvent(data);
    EXPECT_NE(subscriber->screenUnlockCallback_, nullptr);
    bool screenFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].screenUnlock_;
    bool userFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].userUnlock_;
    EXPECT_EQ(screenFlag, true);
    EXPECT_EQ(userFlag, false);
    AbilityEventMapManager::GetInstance().RemoveUser(userId);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest ScreenUnlock_OnReceiveEvent_0003 end");
}

/**
 * @tc.name: AbilityManagerEventSubscriberTest_ScreenUnlock_OnReceiveEvent_0004
 * @tc.desc: receive COMMON_EVENT_SCREEN_UNLOCKED, userId inValid, not trigger callback
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerEventSubscriberTest, ScreenUnlock_OnReceiveEvent_0004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest ScreenUnlock_OnReceiveEvent_0004 start");
    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    std::function<void(int32_t)> callback = [](int32_t) {};
    EXPECT_NE(callback, nullptr);
    auto subscriber = std::make_shared<AbilityScreenUnlockEventSubscriber>(subscribeInfo, callback);
    EventFwk::CommonEventData data;
    int32_t userId = -1;
    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED;
    data.want_.SetParam("userId", userId);
    subscriber->OnReceiveEvent(data);
    EXPECT_NE(subscriber->screenUnlockCallback_, nullptr);
    bool screenFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].screenUnlock_;
    bool userFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].userUnlock_;
    EXPECT_EQ(screenFlag, false);
    EXPECT_EQ(userFlag, false);
    AbilityEventMapManager::GetInstance().RemoveUser(userId);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest ScreenUnlock_OnReceiveEvent_0004 end");
}

/**
 * @tc.name: AbilityManagerEventSubscriberTest_ScreenUnlock_OnReceiveEvent_0005
 * @tc.desc: repeated receive COMMON_EVENT_SCREEN_UNLOCKED, but not trigger callback
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerEventSubscriberTest, ScreenUnlock_OnReceiveEvent_0005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest ScreenUnlock_OnReceiveEvent_0005 start");
    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    std::function<void(int32_t)> callback = [](int32_t) {};
    EXPECT_NE(callback, nullptr);
    auto subscriber = std::make_shared<AbilityScreenUnlockEventSubscriber>(subscribeInfo, callback);
    EventFwk::CommonEventData data;
    int32_t userId = 1;
    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED;
    data.want_.SetParam("userId", userId);
    subscriber->OnReceiveEvent(data);
    EXPECT_NE(subscriber->screenUnlockCallback_, nullptr);
    bool screenFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].screenUnlock_;
    bool userFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].userUnlock_;
    EXPECT_EQ(screenFlag, true);
    EXPECT_EQ(userFlag, false);
    subscriber->OnReceiveEvent(data);
    screenFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].screenUnlock_;
    userFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].userUnlock_;
    EXPECT_EQ(screenFlag, true);
    EXPECT_EQ(userFlag, false);
    AbilityEventMapManager::GetInstance().RemoveUser(userId);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest ScreenUnlock_OnReceiveEvent_0005 end");
}

/**
 * @tc.name: AbilityManagerEventSubscriberTest_userUnlock_OnReceiveEvent_0001
 * @tc.desc: receive other event
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerEventSubscriberTest, userUnlock_OnReceiveEvent_0001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest userUnlock_OnReceiveEvent_0001 start");
    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    std::function<void(int32_t)> callback = [](int32_t) {};
    std::function<void()> callback2 = []() {};
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(callback2, nullptr);
    auto subscriber = std::make_shared<AbilityUserUnlockEventSubscriber>(subscribeInfo, callback, callback2);
    EventFwk::CommonEventData data;
    int32_t userId = 1;
    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED;
    data.code_ = userId;
    subscriber->OnReceiveEvent(data);
    EXPECT_NE(subscriber->screenUnlockCallback_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest userUnlock_OnReceiveEvent_0001 end");
}

/**
 * @tc.name: AbilityManagerEventSubscriberTest_userUnlock_OnReceiveEvent_0002
 * @tc.desc: userScreenUnlockCallback_ screenUnlockCallback_ nullptr nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerEventSubscriberTest, userUnlock_OnReceiveEvent_0002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest userUnlock_OnReceiveEvent_0002 start");
    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    std::function<void(int32_t)> callback = [](int32_t) {};
    std::function<void()> callback2 = []() {};
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(callback2, nullptr);
    auto subscriber = std::make_shared<AbilityUserUnlockEventSubscriber>(subscribeInfo, callback, callback2);
    subscriber->userScreenUnlockCallback_ = nullptr;
    subscriber->screenUnlockCallback_ = nullptr;
    EventFwk::CommonEventData data;
    int32_t userId = 1;
    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED;
    data.code_ = userId;
    subscriber->OnReceiveEvent(data);
    EXPECT_EQ(subscriber->screenUnlockCallback_, nullptr);
    EXPECT_EQ(subscriber->userScreenUnlockCallback_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest userUnlock_OnReceiveEvent_0002 end");
}

/**
 * @tc.name: AbilityManagerEventSubscriberTest_userUnlock_OnReceiveEvent_0003
 * @tc.desc: userScreenUnlockCallback_ screenUnlockCallback_ nullptr valid
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerEventSubscriberTest, userUnlock_OnReceiveEvent_0003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest userUnlock_OnReceiveEvent_0003 start");
    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    std::function<void(int32_t)> callback = [](int32_t) {};
    std::function<void()> callback2 = []() {};
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(callback2, nullptr);
    auto subscriber = std::make_shared<AbilityUserUnlockEventSubscriber>(subscribeInfo, callback, callback2);
    subscriber->userScreenUnlockCallback_ = nullptr;
    EventFwk::CommonEventData data;
    int32_t userId = 1;
    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED;
    data.code_ = userId;
    subscriber->OnReceiveEvent(data);
    EXPECT_NE(subscriber->screenUnlockCallback_, nullptr);
    EXPECT_EQ(subscriber->userScreenUnlockCallback_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest userUnlock_OnReceiveEvent_0003 end");
}

/**
 * @tc.name: AbilityManagerEventSubscriberTest_userUnlock_OnReceiveEvent_0004
 * @tc.desc: userScreenUnlockCallback_ screenUnlockCallback_ valid nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerEventSubscriberTest, userUnlock_OnReceiveEvent_0004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest userUnlock_OnReceiveEvent_0004 start");
    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    std::function<void(int32_t)> callback = [](int32_t) {};
    std::function<void()> callback2 = []() {};
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(callback2, nullptr);
    auto subscriber = std::make_shared<AbilityUserUnlockEventSubscriber>(subscribeInfo, callback, callback2);
    subscriber->screenUnlockCallback_ = nullptr;
    EventFwk::CommonEventData data;
    int32_t userId = 1;
    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED;
    data.code_ = userId;
    subscriber->OnReceiveEvent(data);
    EXPECT_EQ(subscriber->screenUnlockCallback_, nullptr);
    EXPECT_NE(subscriber->userScreenUnlockCallback_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest userUnlock_OnReceiveEvent_0004 end");
}

/**
 * @tc.name: AbilityManagerEventSubscriberTest_userUnlock_OnReceiveEvent_0005
 * @tc.desc: repeated receive COMMON_EVENT_USER_UNLOCKED, but not trigger callback
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerEventSubscriberTest, userUnlock_OnReceiveEvent_0005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest userUnlock_OnReceiveEvent_0005 start");
    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    std::function<void(int32_t)> callback = [](int32_t) {};
    std::function<void()> callback2 = []() {};
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(callback2, nullptr);
    auto subscriber = std::make_shared<AbilityUserUnlockEventSubscriber>(subscribeInfo, callback, callback2);
    EventFwk::CommonEventData data;
    int32_t userId = 1;
    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED;
    data.code_ = userId;
    subscriber->OnReceiveEvent(data);
    EXPECT_NE(subscriber->screenUnlockCallback_, nullptr);
    EXPECT_NE(subscriber->userScreenUnlockCallback_, nullptr);
    bool screenFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].screenUnlock_;
    bool userFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].userUnlock_;
    EXPECT_EQ(screenFlag, false);
    EXPECT_EQ(userFlag, true);
    subscriber->OnReceiveEvent(data);
    screenFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].screenUnlock_;
    userFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].userUnlock_;
    EXPECT_EQ(screenFlag, false);
    EXPECT_EQ(userFlag, true);
    AbilityEventMapManager::GetInstance().RemoveUser(userId);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest userUnlock_OnReceiveEvent_0005 end");
}

/**
 * @tc.name: AbilityManagerEventSubscriberTest_AbilityEventSubscriber_OnReceiveEvent_0001
 * @tc.desc: receive both event, trigger callback from screenUnlockSubscriber
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerEventSubscriberTest, AbilityEventSubscriber_OnReceiveEvent_0001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest AbilityEventSubscriber_OnReceiveEvent_0001 start");
    EventFwk::CommonEventSubscribeInfo userSubscribeInfo;
    std::function<void(int32_t)> callback = [](int32_t) {};
    std::function<void()> callback2 = []() {};
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(callback2, nullptr);
    auto userSubscriber = std::make_shared<AbilityUserUnlockEventSubscriber>(userSubscribeInfo, callback, callback2);
    EventFwk::CommonEventData userData;
    int32_t userId = 1;
    userData.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED;
    userData.code_ = userId;
    userSubscriber->OnReceiveEvent(userData);
    EXPECT_NE(userSubscriber->screenUnlockCallback_, nullptr);
    EXPECT_NE(userSubscriber->userScreenUnlockCallback_, nullptr);
    bool screenFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].screenUnlock_;
    bool userFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].userUnlock_;
    EXPECT_EQ(screenFlag, false);
    EXPECT_EQ(userFlag, true);


    EventFwk::CommonEventSubscribeInfo screenSubscribeInfo;
    EXPECT_NE(callback, nullptr);
    auto screenSubscriber = std::make_shared<AbilityScreenUnlockEventSubscriber>(screenSubscribeInfo, callback);
    EventFwk::CommonEventData screenData;
    screenData.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED;
    screenData.want_.SetParam("userId", userId);
    screenSubscriber->OnReceiveEvent(screenData);
    EXPECT_NE(screenSubscriber->screenUnlockCallback_, nullptr);
    screenFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].screenUnlock_;
    userFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].userUnlock_;
    // removed After triggered
    EXPECT_EQ(screenFlag, false);
    EXPECT_EQ(userFlag, false);
    AbilityEventMapManager::GetInstance().RemoveUser(userId);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest AbilityEventSubscriber_OnReceiveEvent_0001 end");
}

/**
 * @tc.name: AbilityManagerEventSubscriberTest_AbilityEventSubscriber_OnReceiveEvent_0002
 * @tc.desc: receive both event, trigger callback from userUnlockSubscriber
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerEventSubscriberTest, AbilityEventSubscriber_OnReceiveEvent_0002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest AbilityEventSubscriber_OnReceiveEvent_0002 start");
    EventFwk::CommonEventSubscribeInfo screenSubscribeInfo;
    std::function<void(int32_t)> callback = [](int32_t) {};
    std::function<void()> callback2 = []() {};
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(callback2, nullptr);
    int32_t userId = 1;
    auto screenSubscriber = std::make_shared<AbilityScreenUnlockEventSubscriber>(screenSubscribeInfo, callback);
    EventFwk::CommonEventData screenData;
    screenData.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED;
    screenData.want_.SetParam("userId", userId);
    screenSubscriber->OnReceiveEvent(screenData);
    EXPECT_NE(screenSubscriber->screenUnlockCallback_, nullptr);
    bool screenFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].screenUnlock_;
    bool userFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].userUnlock_;
    EXPECT_EQ(screenFlag, true);
    EXPECT_EQ(userFlag, false);

    EventFwk::CommonEventSubscribeInfo userSubscribeInfo;
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(callback2, nullptr);
    auto userSubscriber = std::make_shared<AbilityUserUnlockEventSubscriber>(userSubscribeInfo, callback, callback2);
    EventFwk::CommonEventData userData;
    userData.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED;
    userData.code_ = userId;
    userSubscriber->OnReceiveEvent(userData);
    EXPECT_NE(userSubscriber->screenUnlockCallback_, nullptr);
    EXPECT_NE(userSubscriber->userScreenUnlockCallback_, nullptr);
    screenFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].screenUnlock_;
    userFlag = AbilityEventMapManager::GetInstance().eventMap_[userId].userUnlock_;
    // removed After triggered
    EXPECT_EQ(screenFlag, false);
    EXPECT_EQ(userFlag, false);
    AbilityEventMapManager::GetInstance().RemoveUser(userId);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerEventSubscriberTest AbilityEventSubscriber_OnReceiveEvent_0002 end");
}
} // namespace AAFwk
} // namespace OHOS