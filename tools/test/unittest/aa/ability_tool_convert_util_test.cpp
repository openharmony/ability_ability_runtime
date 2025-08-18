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

#include "ability_tool_convert_util.h"
#include "hilog_tag_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AAFwk;

class AbilityToolConvertUtilTest : public ::testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AbilityToolConvertUtilTest::SetUpTestCase()
{}

void AbilityToolConvertUtilTest::TearDownTestCase()
{}

void AbilityToolConvertUtilTest::SetUp()
{}

void AbilityToolConvertUtilTest::TearDown()
{}

/**
 * @tc.number: CovertExitReason_0001
 * @tc.name: CovertExitReason
 * @tc.desc: Verify the CovertExitReason function.
 */
HWTEST_F(AbilityToolConvertUtilTest, CovertExitReason_0001,
         Function | MediumTest | Level1) {
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0001 is called");
    std::string reasonStr = "";
    EXPECT_EQ(AbilityToolConvertUtil::CovertExitReason(reasonStr), Reason::REASON_UNKNOWN);
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0001 is end");
}

/**
 * @tc.number: CovertExitReason_0002
 * @tc.name: CovertExitReason
 * @tc.desc: Verify the CovertExitReason function.
 */
HWTEST_F(AbilityToolConvertUtilTest, CovertExitReason_0002,
         Function | MediumTest | Level1) {
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0002 is called");
    std::string reasonStr = "UNKNOWN";
    EXPECT_EQ(AbilityToolConvertUtil::CovertExitReason(reasonStr), Reason::REASON_UNKNOWN);
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0002 is end");
}

/**
 * @tc.number: CovertExitReason_0003
 * @tc.name: CovertExitReason
 * @tc.desc: Verify the CovertExitReason function.
 */
HWTEST_F(AbilityToolConvertUtilTest, CovertExitReason_0003,
         Function | MediumTest | Level1) {
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0003 is called");
    std::string reasonStr = "NORMAL";
    EXPECT_EQ(AbilityToolConvertUtil::CovertExitReason(reasonStr), Reason::REASON_NORMAL);
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0003 is end");
}

/**
 * @tc.number: CovertExitReason_0004
 * @tc.name: CovertExitReason
 * @tc.desc: Verify the CovertExitReason function.
 */
HWTEST_F(AbilityToolConvertUtilTest, CovertExitReason_0004,
         Function | MediumTest | Level1) {
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0004 is called");
    std::string reasonStr = "CPP_CRASH";
    EXPECT_EQ(AbilityToolConvertUtil::CovertExitReason(reasonStr), Reason::REASON_CPP_CRASH);
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0004 is end");
}

/**
 * @tc.number: CovertExitReason_0005
 * @tc.name: CovertExitReason
 * @tc.desc: Verify the CovertExitReason function.
 */
HWTEST_F(AbilityToolConvertUtilTest, CovertExitReason_0005,
         Function | MediumTest | Level1) {
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0005 is called");
    std::string reasonStr = "JS_ERROR";
    EXPECT_EQ(AbilityToolConvertUtil::CovertExitReason(reasonStr), Reason::REASON_JS_ERROR);
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0005 is end");
}

/**
 * @tc.number: CovertExitReason_0006
 * @tc.name: CovertExitReason
 * @tc.desc: Verify the CovertExitReason function.
 */
HWTEST_F(AbilityToolConvertUtilTest, CovertExitReason_0006,
         Function | MediumTest | Level1) {
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0006 is called");
    std::string reasonStr = "APP_FREEZE";
    EXPECT_EQ(AbilityToolConvertUtil::CovertExitReason(reasonStr), Reason::REASON_APP_FREEZE);
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0006 is end");
}

/**
 * @tc.number: CovertExitReason_0007
 * @tc.name: CovertExitReason
 * @tc.desc: Verify the CovertExitReason function.
 */
HWTEST_F(AbilityToolConvertUtilTest, CovertExitReason_0007,
         Function | MediumTest | Level1) {
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0007 is called");
    std::string reasonStr = "PERFORMANCE_CONTROL";
    EXPECT_EQ(AbilityToolConvertUtil::CovertExitReason(reasonStr),
            Reason::REASON_PERFORMANCE_CONTROL);
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0007 is end");
}

/**
 * @tc.number: CovertExitReason_0008
 * @tc.name: CovertExitReason
 * @tc.desc: Verify the CovertExitReason function.
 */
HWTEST_F(AbilityToolConvertUtilTest, CovertExitReason_0008,
         Function | MediumTest | Level1) {
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0008 is called");
    std::string reasonStr = "RESOURCE_CONTROL";
    EXPECT_EQ(AbilityToolConvertUtil::CovertExitReason(reasonStr), Reason::REASON_RESOURCE_CONTROL);
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0008 is end");
}

/**
 * @tc.number: CovertExitReason_0009
 * @tc.name: CovertExitReason
 * @tc.desc: Verify the CovertExitReason function.
 */
HWTEST_F(AbilityToolConvertUtilTest, CovertExitReason_0009,
         Function | MediumTest | Level1) {
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0009 is called");
    std::string reasonStr = "UPGRADE";
    EXPECT_EQ(AbilityToolConvertUtil::CovertExitReason(reasonStr), Reason::REASON_UPGRADE);
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0009 is end");
}

/**
 * @tc.number: CovertExitReason_0010
 * @tc.name: CovertExitReason
 * @tc.desc: Verify the CovertExitReason function.
 */
HWTEST_F(AbilityToolConvertUtilTest, CovertExitReason_0010,
         Function | MediumTest | Level1) {
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0010 is called");
    std::string reasonStr = "null";
    EXPECT_EQ(AbilityToolConvertUtil::CovertExitReason(reasonStr), Reason::REASON_UNKNOWN);
    TAG_LOGI(AAFwkTag::TEST, "CovertExitReason_0010 is end");
}