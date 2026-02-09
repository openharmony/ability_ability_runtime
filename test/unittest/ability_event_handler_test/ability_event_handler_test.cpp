/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

namespace {
constexpr int32_t BUFFER_LEN = 128;
constexpr const char *HOOK_MODE_KEY = "libc.hook_mode";
constexpr const char *HOOK_MODE_STARTUP = "startup:";
constexpr const char *HOOK_MODE_NORMAL = "";

class ScopedSystemParam final {
public:
    ScopedSystemParam(const std::string &key, const std::string &value) : key_(key)
    {
        char paramOutBuf[BUFFER_LEN] = {0};
        GetParameter(key.c_str(), "", paramOutBuf, BUFFER_LEN);
        oldValue_ = paramOutBuf;
        SetParameter(key.c_str(), value.c_str());
    }

    ~ScopedSystemParam()
    {
        SetParameter(key_.c_str(), oldValue_.c_str());
    }

private:
    std::string key_;
    std::string oldValue_;
};

constexpr int32_t TEST_UNIQUE_ID = 101;
}

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
    event.SetCreateTime(6);
    EXPECT_TRUE(event.GetEventId() == 10);
    EXPECT_TRUE(event.GetEventString() == "10_connectTimeout_101");
    EXPECT_TRUE(event.GetCreateTime() == 6);
}

/*
 * Feature: Ability Event Handler
 * Function: ProcessEvent
 * SubFunction: SHAREDATA_TIMEOUT_MSG
 * FunctionPoints: Share data timeout callback
 * EnvConditions: NA
 * CaseDescription: Verify share data timeout triggers callback and clears map.
 */
HWTEST_F(AbilityEventHandlerTest, ability_event_handler_001, TestSize.Level1)
{
    ScopedSystemParam hookMode(HOOK_MODE_KEY, HOOK_MODE_NORMAL);
    AbilityEventHandler handler(nullptr, std::weak_ptr<AbilityManagerService>());

    EXPECT_NO_FATAL_FAILURE(handler.ProcessEvent(
        EventWrap(AbilityManagerService::SHAREDATA_TIMEOUT_MSG, TEST_UNIQUE_ID)));
}

/*
 * Feature: Ability Event Handler
 * Function: ProcessEvent
 * SubFunction: Hook mode
 * FunctionPoints: Startup hook mode should skip processing
 * EnvConditions: NA
 * CaseDescription: Verify hook mode startup skips timeout processing.
 */
HWTEST_F(AbilityEventHandlerTest, ability_event_handler_002, TestSize.Level1)
{
    ScopedSystemParam hookMode(HOOK_MODE_KEY, HOOK_MODE_STARTUP);
    AbilityEventHandler handler(nullptr, std::weak_ptr<AbilityManagerService>());

    EXPECT_NO_FATAL_FAILURE(handler.ProcessEvent(
        EventWrap(AbilityManagerService::CONNECT_TIMEOUT_MSG, TEST_UNIQUE_ID)));
}

/*
 * Feature: Ability Event Handler
 * Function: ProcessEvent
 * SubFunction: Other timeout messages
 * FunctionPoints: Safe handling for all timeout events and default branch
 * EnvConditions: NA
 * CaseDescription: Verify handler safely processes different event IDs with null server.
 */
HWTEST_F(AbilityEventHandlerTest, ability_event_handler_003, TestSize.Level1)
{
    ScopedSystemParam hookMode(HOOK_MODE_KEY, HOOK_MODE_NORMAL);
    AbilityEventHandler handler(nullptr, std::weak_ptr<AbilityManagerService>());

    EXPECT_NO_FATAL_FAILURE(handler.ProcessEvent(EventWrap(AbilityManagerService::LOAD_HALF_TIMEOUT_MSG, 1)));
    EXPECT_NO_FATAL_FAILURE(handler.ProcessEvent(EventWrap(AbilityManagerService::LOAD_TIMEOUT_MSG, 2)));
    EXPECT_NO_FATAL_FAILURE(handler.ProcessEvent(EventWrap(AbilityManagerService::ACTIVE_TIMEOUT_MSG, 3)));
    EXPECT_NO_FATAL_FAILURE(handler.ProcessEvent(EventWrap(AbilityManagerService::INACTIVE_TIMEOUT_MSG, 4)));
    EXPECT_NO_FATAL_FAILURE(handler.ProcessEvent(EventWrap(AbilityManagerService::FOREGROUND_HALF_TIMEOUT_MSG, 5)));
    EXPECT_NO_FATAL_FAILURE(handler.ProcessEvent(EventWrap(AbilityManagerService::FOREGROUND_TIMEOUT_MSG, 6)));
    EXPECT_NO_FATAL_FAILURE(handler.ProcessEvent(EventWrap(AbilityManagerService::CONNECT_TIMEOUT_MSG, 7)));
    EXPECT_NO_FATAL_FAILURE(handler.ProcessEvent(EventWrap(AbilityManagerService::CONNECT_HALF_TIMEOUT_MSG, 8)));
    EXPECT_NO_FATAL_FAILURE(handler.ProcessEvent(EventWrap(99999, 9)));
}
}  // namespace AppExecFwk
}  // namespace OHOS