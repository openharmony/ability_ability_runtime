/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include <iostream>
#include <cstddef>
#include <cstdint>
#define private public
#include "ability_event_util.h"
#undef private
#include "hilog_tag_wrapper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AbilityRuntime {
class AbilityEventUtilTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AbilityEventUtilTest::SetUpTestCase(void) {}
void AbilityEventUtilTest::TearDownTestCase(void) {}
void AbilityEventUtilTest::SetUp() {}
void AbilityEventUtilTest::TearDown() {}

/**
 * @tc.name: AbilityEventUtil_SendStartAbilityError_0100
 * @tc.desc: SendStartAbilityError
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(AbilityEventUtilTest, AbilityEventUtil_SendStartAbilityError_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityEventUtil_SendStartAbilityError_0100 start");
    EventInfo eventInfo = {};
    int32_t errCode = -1;
    std::string errMsg = "test event";
    AbilityEventUtil::SendStartAbilityErrorEvent(eventInfo, errCode, errMsg);
    EXPECT_EQ(eventInfo.userId, -1);
    TAG_LOGI(AAFwkTag::TEST, "AbilityEventUtil_SendStartAbilityError_0100 end");
}

/**
 * @tc.name: AbilityEventUtil_SendStartAbilityError_0200
 * @tc.desc: SendStartAbilityError
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(AbilityEventUtilTest, AbilityEventUtil_SendStartAbilityError_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityEventUtil_SendStartAbilityError_0200 start");
    EventInfo eventInfo = {};
    int32_t errCode = -1;
    std::string errMsg = "test event";
    AbilityEventUtil::SendStartAbilityErrorEvent(eventInfo, errCode, errMsg, true);
    EXPECT_EQ(eventInfo.userId, -1);
    TAG_LOGI(AAFwkTag::TEST, "AbilityEventUtil_SendStartAbilityError_0200 end");
}

/**
 * @tc.name: AbilityEventUtil_SendStartAbilityError_0300
 * @tc.desc: SendKillProcessWithReasonEvent
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(AbilityEventUtilTest, AbilityEventUtil_SendStartAbilityError_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityEventUtil_SendStartAbilityError_0300 start");
    EventInfo eventInfo = {};
    int32_t errCode = 0;
    std::string errMsg = "test event";
    AbilityEventUtil::SendStartAbilityErrorEvent(eventInfo, errCode, errMsg);
    EXPECT_EQ(eventInfo.userId, -1);
    TAG_LOGI(AAFwkTag::TEST, "AbilityEventUtil_SendStartAbilityError_0300 end");
}

/**
 * @tc.name: AbilityEventUtil_SendKillProcessWithReasonEvent_0100
 * @tc.desc: SendKillProcessWithReasonEvent
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(AbilityEventUtilTest, AbilityEventUtil_SendKillProcessWithReasonEvent_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityEventUtil_SendKillProcessWithReasonEvent_0100 start");
    EventInfo eventInfo = {};
    int32_t errCode = -1;
    std::string errMsg = "test event";
    AbilityEventUtil::SendKillProcessWithReasonEvent(errCode, errMsg, eventInfo);
    EXPECT_EQ(eventInfo.userId, -1);
    TAG_LOGI(AAFwkTag::TEST, "AbilityEventUtil_SendKillProcessWithReasonEvent_0100 end");
}
}  // namespace AAFwk
}  // namespace OHOS
