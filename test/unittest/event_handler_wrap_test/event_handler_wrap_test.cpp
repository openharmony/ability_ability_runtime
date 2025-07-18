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

#include <chrono>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>

#include "event_handler_wrap.h"
#include "hilog_tag_wrapper.h"
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
namespace {
constexpr int32_t TIME_DELAY = 100;
constexpr int32_t TIME_SLEEP = 4000;
inline int64_t GetCurrentTimeMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
}
MockLogger MockLogger::instance;
bool EventTask::cancelStatus = false;
static std::shared_ptr<TaskHandlerWrap> instance = std::make_shared<TaskHandlerWrap>();
std::shared_ptr<TaskHandlerWrap> TaskHandlerWrap::GetFfrtHandler()
{
    return instance;
}

static bool g_isEqual = false;
bool operator==(const EventWrap &lhs, const EventWrap &rhs)
{
    return g_isEqual;
}

class MockEventHandlerWrap : public EventHandlerWrap {
public:
    MOCK_METHOD(void, ProcessEvent, (const EventWrap& event), ());
};

class EventHandlerWrapTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void EventHandlerWrapTest::SetUpTestCase(void)
{}
void EventHandlerWrapTest::TearDownTestCase(void)
{}
void EventHandlerWrapTest::SetUp()
{}
void EventHandlerWrapTest::TearDown()
{}

/**
 * @tc.name: SendEvent_0010
 * @tc.desc: Task handler is null.
 * @tc.type: FUNC
 */
HWTEST_F(EventHandlerWrapTest, SendEvent_0010, TestSize.Level2)
{
    auto handler = std::make_shared<MockEventHandlerWrap>();
    handler->taskHandler_ = nullptr;

    EventWrap event;
    bool result = handler->SendEvent(event, TIME_DELAY, false);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SendEvent_0020
 * @tc.desc: Send same event fail.
 * @tc.type: FUNC
 */
HWTEST_F(EventHandlerWrapTest, SendEvent_0020, TestSize.Level2)
{
    auto handler = std::make_shared<MockEventHandlerWrap>();
    auto taskHandler = std::make_shared<TaskHandlerWrap>();
    handler->taskHandler_ = taskHandler;

    EventWrap event;
    handler->eventMap_["test_event"] = event;
    event.eventString = "test_event";
    bool result = handler->SendEvent(event, TIME_DELAY, false);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SendEvent_0030
 * @tc.desc: Send event success.
 * @tc.type: FUNC
 */
HWTEST_F(EventHandlerWrapTest, SendEvent_0030, TestSize.Level2)
{
    auto handler = std::make_shared<MockEventHandlerWrap>();
    auto taskHandler = std::make_shared<TaskHandlerWrap>();
    handler->taskHandler_ = taskHandler;

    EventWrap event;
    event.eventString = "test_event";

    EXPECT_CALL(*taskHandler, SubmitTaskJust(::testing::_, "test_event", TIME_DELAY))
        .WillOnce(::testing::Return(std::make_shared<int32_t>(0)));

    bool result = handler->SendEvent(event, TIME_DELAY, false);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: SendEvent_0040
 * @tc.desc: force insert event success.
 * @tc.type: FUNC
 */
HWTEST_F(EventHandlerWrapTest, SendEvent_0040, TestSize.Level2) {
    auto handler = std::make_shared<MockEventHandlerWrap>();
    auto taskHandler = std::make_shared<TaskHandlerWrap>();
    handler->taskHandler_ = taskHandler;

    EventWrap event1, event2;
    event2.eventString = "test_event";
    handler->eventMap_["test_event"] = event1;

    EXPECT_CALL(*taskHandler, SubmitTaskJust(::testing::_, "test_event", TIME_DELAY))
        .WillOnce(::testing::Return(std::make_shared<int32_t>(0)));

    bool result = handler->SendEvent(event2, TIME_DELAY, true);
    EXPECT_TRUE(result);
    EXPECT_EQ(handler->eventMap_["test_event"].GetEventString(), "test_event");
}

/**
 * @tc.name: SendEvent_0050
 * @tc.desc: SendEvent event success and execute timeout.
 * @tc.type: FUNC
 */
HWTEST_F(EventHandlerWrapTest, SendEvent_0050, TestSize.Level2) {
    auto handler = std::make_shared<MockEventHandlerWrap>();
    auto taskHandler = std::make_shared<TaskHandlerWrap>();
    handler->taskHandler_ = taskHandler;

    EventWrap event2;
    event2.eventString = "test_event";
    event2.sameStatus = true;

    EXPECT_CALL(*taskHandler, SubmitTaskJust(::testing::_, "test_event", TIME_DELAY))
        .WillOnce([](std::function<void()> task, const std::string& name, int64_t delay) {
            if (task) {
                std::thread(task).detach();
            }
            return std::make_shared<int32_t>(0);
            });
    EXPECT_CALL(MockLogger::instance, PrintLog).Times(2)
        .WillRepeatedly([](const std::string &fmt) {
            GTEST_LOG_(INFO) << fmt;
        });
    EXPECT_CALL(*handler, ProcessEvent).Times(1);
    bool result = handler->SendEvent(event2, TIME_DELAY, true);
    usleep(TIME_SLEEP);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: SendEvent_0060
 * @tc.desc: SendEvent event success and execute timeout.
 * @tc.type: FUNC
 */
HWTEST_F(EventHandlerWrapTest, SendEvent_0060, TestSize.Level2) {
    auto handler = std::make_shared<MockEventHandlerWrap>();
    auto taskHandler = std::make_shared<TaskHandlerWrap>();
    handler->taskHandler_ = taskHandler;

    EventWrap event2;
    event2.eventString = "test_event";
    event2.sameStatus = true;
    event2.createTime = GetCurrentTimeMillis();

    EXPECT_CALL(*taskHandler, SubmitTaskJust(::testing::_, "test_event", TIME_DELAY))
        .WillOnce([](std::function<void()> task, const std::string& name, int64_t delay) {
            if (task) {
                std::thread(task).detach();
            }
            return std::make_shared<int32_t>(0);
            });
    EXPECT_CALL(MockLogger::instance, PrintLog).Times(1);
    EXPECT_CALL(*handler, ProcessEvent).Times(1);
    bool result = handler->SendEvent(event2, TIME_DELAY, true);
    usleep(TIME_SLEEP);
    EXPECT_TRUE(result);
    Mock::VerifyAndClear(&MockLogger::instance);
}

/**
 * @tc.name: RemoveEvent_0010
 * @tc.desc: RemoveEvent not found.
 * @tc.type: FUNC
 */
HWTEST_F(EventHandlerWrapTest, RemoveEvent_0010, TestSize.Level2) {
    auto handler = std::make_shared<MockEventHandlerWrap>();

    EventWrap event2;
    event2.eventString = "test_event";

    bool result = handler->RemoveEvent(event2);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: RemoveEvent_0020
 * @tc.desc: RemoveEvent force success.
 * @tc.type: FUNC
 */
HWTEST_F(EventHandlerWrapTest, RemoveEvent_0020, TestSize.Level2) {
    auto handler = std::make_shared<MockEventHandlerWrap>();

    EventWrap event2;
    event2.eventString = "test_event";
    handler->eventMap_["test_event"] = event2;

    bool result = handler->RemoveEvent(event2);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: RemoveEvent_0030
 * @tc.desc: RemoveEvent same success.
 * @tc.type: FUNC
 */
HWTEST_F(EventHandlerWrapTest, RemoveEvent_0030, TestSize.Level2) {
    auto handler = std::make_shared<MockEventHandlerWrap>();

    EventWrap event2;
    event2.eventString = "test_event";
    event2.sameStatus = true;
    handler->eventMap_["test_event"] = event2;

    bool result = handler->RemoveEvent(event2, false);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: RemoveEvent_0040
 * @tc.desc: RemoveEvent fail (not same, not force).
 * @tc.type: FUNC
 */
HWTEST_F(EventHandlerWrapTest, RemoveEvent_0040, TestSize.Level2) {
    auto handler = std::make_shared<MockEventHandlerWrap>();

    EventWrap event2;
    event2.eventString = "test_event";
    event2.sameStatus = false;
    handler->eventMap_["test_event"] = event2;

    bool result = handler->RemoveEvent(event2, false);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: RemoveEvent_0050
 * @tc.desc: RemoveEvent success and cancel success.
 * @tc.type: FUNC
 */
HWTEST_F(EventHandlerWrapTest, RemoveEvent_0050, TestSize.Level2) {
    auto handler = std::make_shared<MockEventHandlerWrap>();

    EventWrap event2;
    event2.eventString = "test_event";
    event2.sameStatus = true;
    handler->eventMap_["test_event"] = event2;
    EventTask::cancelStatus = true;
    EXPECT_CALL(MockLogger::instance, PrintLog)
        .WillRepeatedly([](const std::string &fmt) {
            GTEST_LOG_(INFO) << fmt;
        });
    bool result = handler->RemoveEvent(event2);
    EXPECT_TRUE(result);
    EventTask::cancelStatus = false;
}

/**
 * @tc.name: RemoveEvent_0060
 * @tc.desc: RemoveEvent success and cancel success.
 * @tc.type: FUNC
 */
HWTEST_F(EventHandlerWrapTest, RemoveEvent_0060, TestSize.Level2) {
    auto handler = std::make_shared<MockEventHandlerWrap>();

    EventWrap event2;
    event2.eventString = "test_event";
    event2.sameStatus = true;
    event2.createTime = GetCurrentTimeMillis();
    handler->eventMap_["test_event"] = event2;
    EventTask::cancelStatus = true;
    EXPECT_CALL(MockLogger::instance, PrintLog).Times(0);
    bool result = handler->RemoveEvent(event2);
    EXPECT_TRUE(result);
    EventTask::cancelStatus = false;
    Mock::VerifyAndClear(&MockLogger::instance);
}
}  // namespace AAFwk
}  // namespace OHOS