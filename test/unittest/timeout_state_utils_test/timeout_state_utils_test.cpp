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
#include "ability_manager_service.h"
#include "timeout_state_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class TimeoutStateUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void TimeoutStateUtilsTest::SetUpTestCase(void)
{}

void TimeoutStateUtilsTest::TearDownTestCase(void)
{}

void TimeoutStateUtilsTest::SetUp()
{}

void TimeoutStateUtilsTest::TearDown()
{}

/**
 * @tc.number: StateUtilsTest_MsgId2FreezeTimeOutState_0100
 * @tc.desc: MsgId2FreezeTimeOutState
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(TimeoutStateUtilsTest, TimeoutStateUtilsTest_MsgId2FreezeTimeOutState_0100, TestSize.Level2)
{
    EXPECT_EQ(TimeoutStateUtils::MsgId2FreezeTimeOutState(AbilityManagerService::LOAD_TIMEOUT_MSG),
        AbilityRuntime::FreezeUtil::TimeoutState::LOAD);
    EXPECT_EQ(TimeoutStateUtils::MsgId2FreezeTimeOutState(AbilityManagerService::FOREGROUND_TIMEOUT_MSG),
        AbilityRuntime::FreezeUtil::TimeoutState::FOREGROUND);
    EXPECT_EQ(TimeoutStateUtils::MsgId2FreezeTimeOutState(AbilityManagerService::BACKGROUND_TIMEOUT_MSG),
        AbilityRuntime::FreezeUtil::TimeoutState::BACKGROUND);
    EXPECT_EQ(TimeoutStateUtils::MsgId2FreezeTimeOutState(AbilityManagerService::CONNECT_TIMEOUT_MSG),
        AbilityRuntime::FreezeUtil::TimeoutState::CONNECT);
    EXPECT_EQ(TimeoutStateUtils::MsgId2FreezeTimeOutState(AbilityManagerService::CONNECT_HALF_TIMEOUT_MSG),
        AbilityRuntime::FreezeUtil::TimeoutState::UNKNOWN);
}

}  // namespace AAFwk
}  // namespace OHOS
 