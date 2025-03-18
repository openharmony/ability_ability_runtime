/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <parameter.h>
#include "ability_manager_service.h"
#include "ability_event_handler.h"

using namespace testing::ext;
namespace OHOS {
namespace AAFwk {

class AbilityEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AbilityEventHandlerTest::SetUpTestCase()
{}

void AbilityEventHandlerTest::TearDownTestCase()
{}

void AbilityEventHandlerTest::SetUp()
{}

void AbilityEventHandlerTest::TearDown()
{}

/*
 * Feature: Ability Event Handler
 * Function: ProcessEvent
 * SubFunction: NA
 * FunctionPoints: Ability Event Handler ProcessEvent
 * EnvConditions: NA
 * CaseDescription: Verify ProcessEvent
 */
HWTEST_F(AbilityEventHandlerTest, ability_event_handler_001, TestSize.Level1)
{
    std::shared_ptr<TaskHandlerWrap> runner;
    std::weak_ptr<AbilityManagerService> server;
    std::shared_ptr<UserEvent> eventData = std::make_shared<UserEvent>();
    auto event = EventWrap(UserEventHandler::EVENT_SYSTEM_USER_START, eventData);
    auto handler = std::make_shared<AbilityEventHandler>(runner, server);
    SetParameter("libc.hook_mode", "startup:");
    handler->ProcessEvent(event);
    SetParameter("libc.hook_mode", "test_parameter");
    handler->ProcessEvent(event);
    auto event2 = EventWrap(AbilityManagerService::LOAD_TIMEOUT_MSG, event.GetParam());
    std::string str = std::to_string(event.GetEventId());
    handler->ProcessEvent(event2);
    event2 = EventWrap(AbilityManagerService::ACTIVE_TIMEOUT_MSG, event.GetParam());
    handler->ProcessEvent(event2);
    event2 = EventWrap(AbilityManagerService::INACTIVE_TIMEOUT_MSG, event.GetParam());
    handler->ProcessEvent(event2);
    event2 = EventWrap(AbilityManagerService::FOREGROUND_TIMEOUT_MSG, event.GetParam());
    handler->ProcessEvent(event2);
    event2 = EventWrap(AbilityManagerService::BACKGROUND_TIMEOUT_MSG, event.GetParam());
    handler->ProcessEvent(event2);
    EXPECT_TRUE(handler != nullptr);
}  // namespace AppExecFwk

/*
 * Feature: Ability Event Handler
 * Function: EventWrap
 * SubFunction: NA
 * FunctionPoints: EventWrap
 * EnvConditions: NA
 * CaseDescription: Verify ProcessEvent
 */
HWTEST_F(AbilityEventHandlerTest, event_wrap_001, TestSize.Level1)
{
    auto event = EventWrap(10);
    EXPECT_TRUE(event.GetEventId() == 10);
    EXPECT_TRUE(event.GetParam() == 0);
}  // namespace AppExecFwk

/*
 * Feature: Ability Event Handler
 * Function: EventWrap
 * SubFunction: NA
 * FunctionPoints: EventWrap
 * EnvConditions: NA
 * CaseDescription: Verify ProcessEvent
 */
HWTEST_F(AbilityEventHandlerTest, event_wrap_002, TestSize.Level1)
{
    auto event = EventWrap(10, 101);
    EXPECT_TRUE(event.GetEventId() == 10);
    EXPECT_TRUE(event.GetParam() == 101);
    EXPECT_FALSE(event.IsExtension());
}  // namespace AppExecFwk

/*
 * Feature: Ability Event Handler
 * Function: EventWrap
 * SubFunction: NA
 * FunctionPoints: EventWrap
 * EnvConditions: NA
 * CaseDescription: Verify ProcessEvent
 */
HWTEST_F(AbilityEventHandlerTest, event_wrap_003, TestSize.Level1)
{
    auto event = EventWrap(10, 101, true);
    EXPECT_TRUE(event.GetEventId() == 10);
    EXPECT_TRUE(event.GetParam() == 101);
    EXPECT_TRUE(event.IsExtension());
    EXPECT_TRUE(event.GetEventString() == "10_101");
}  // namespace AppExecFwk

/*
 * Feature: Ability Event Handler
 * Function: EventWrap
 * SubFunction: NA
 * FunctionPoints: EventWrap
 * EnvConditions: NA
 * CaseDescription: Verify ProcessEvent
 */
HWTEST_F(AbilityEventHandlerTest, event_wrap_004, TestSize.Level1)
{
    auto event = EventWrap(10, "connectTimeout_101");
    EXPECT_TRUE(event.GetEventId() == 10);
    EXPECT_TRUE(event.GetEventString() == "10_connectTimeout_101");
}  // namespace AppExecFwk

/*
 * Feature: Ability Event Handler
 * Function: EventWrap
 * SubFunction: NA
 * FunctionPoints: EventWrap
 * EnvConditions: NA
 * CaseDescription: Verify ProcessEvent
 */
HWTEST_F(AbilityEventHandlerTest, event_wrap_005, TestSize.Level1)
{
    auto event = EventWrap(10, 101, true, "connectTimeout_101");
    EXPECT_TRUE(event.GetEventId() == 10);
    EXPECT_TRUE(event.GetParam() == 101);
    EXPECT_TRUE(event.IsExtension());
    EXPECT_TRUE(event.GetEventString() == "10_connectTimeout_101");
}  // namespace AppExecFwk

/*
 * Feature: Ability Event Handler
 * Function: EventWrap
 * SubFunction: NA
 * FunctionPoints: EventWrap
 * EnvConditions: NA
 * CaseDescription: Verify ProcessEvent
 */
HWTEST_F(AbilityEventHandlerTest, event_wrap_006, TestSize.Level1)
{
    auto event = EventWrap(10, "connectTimeout_101");
    event.SetTimeout(10000);
    EXPECT_TRUE(event.GetEventId() == 10);
    EXPECT_TRUE(event.GetEventString() == "10_connectTimeout_101");
    EXPECT_TRUE(event.GetTimeout() == 10000);
}  // namespace AppExecFwk

/*
 * Feature: Ability Event Handler
 * Function: EventWrap
 * SubFunction: NA
 * FunctionPoints: EventWrap
 * EnvConditions: NA
 * CaseDescription: Verify ProcessEvent
 */
HWTEST_F(AbilityEventHandlerTest, event_wrap_007, TestSize.Level1)
{
    auto event = EventWrap(10, "connectTimeout_101");
    event.SetRunCount(6);
    EXPECT_TRUE(event.GetEventId() == 10);
    EXPECT_TRUE(event.GetEventString() == "10_connectTimeout_101");
    EXPECT_TRUE(event.GetRunCount() == 6);
}  // namespace AppExecFwk
}  // namespace OHOS
}