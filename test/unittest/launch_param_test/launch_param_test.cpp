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
#include "gmock/gmock.h"

#define private public
#define protected public
#include "launch_param.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class LaunchParamTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LaunchParamTest::SetUpTestCase()
{
}

void LaunchParamTest::TearDownTestCase()
{
}

void LaunchParamTest::SetUp()
{
}

void LaunchParamTest::TearDown()
{
}

/**
 * @tc.number: LaunchParamTest_Marshalling_001
 * @tc.desc: Test LaunchParam Marshalling with valid data
 * @tc.type: FUNC
 */
HWTEST_F(LaunchParamTest, LaunchParamTest_Marshalling_001, TestSize.Level1)
{
    Parcel parcel;
    LaunchParam launchParam;
    launchParam.launchReason = LaunchReason::LAUNCHREASON_START_ABILITY;
    launchParam.lastExitReason = LastExitReason::LASTEXITREASON_NORMAL;
    launchParam.launchReasonMessage = "Test launch reason";
    launchParam.lastExitMessage = "Test exit message";
    launchParam.lastExitDetailInfo.pid = 5523;
    launchParam.lastExitDetailInfo.uid = 520;
    launchParam.lastExitDetailInfo.exitSubReason = 1;
    launchParam.lastExitDetailInfo.rss = 0;
    launchParam.lastExitDetailInfo.pss = 0;
    launchParam.lastExitDetailInfo.processState = 1;
    launchParam.lastExitDetailInfo.timestamp = 0;
    launchParam.lastExitDetailInfo.processName = "launch_process";
    launchParam.lastExitDetailInfo.exitMsg = "exit message";
    launchParam.launchUptime = 0;
    launchParam.launchUTCTime = 0;
    EXPECT_TRUE(launchParam.Marshalling(parcel));
}

/**
 * @tc.number: LaunchParam_Unmarshalling_001
 * @tc.desc: Test Unmarshalling with valid data
 * @tc.type: FUNC
 */
HWTEST_F(LaunchParamTest, LaunchParam_Unmarshalling_001, TestSize.Level1)
{
    Parcel parcel;
    LaunchParam launchParam;
    launchParam.launchReason = LaunchReason::LAUNCHREASON_CALL;
    launchParam.lastExitReason = LastExitReason::LASTEXITREASON_CPP_CRASH;
    launchParam.launchReasonMessage = "call reason";
    launchParam.lastExitMessage = "crash message";
    launchParam.lastExitDetailInfo.pid = 5523;
    launchParam.lastExitDetailInfo.uid = 520;
    launchParam.lastExitDetailInfo.processName = "crash_process";
    launchParam.lastExitDetailInfo.exitMsg = "cpp crash";
    launchParam.launchUptime = 0;
    launchParam.launchUTCTime = 0;

    EXPECT_TRUE(launchParam.Marshalling(parcel));

    LaunchParam* result = LaunchParam::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->launchReason, LaunchReason::LAUNCHREASON_CALL);
    EXPECT_EQ(result->lastExitReason, LastExitReason::LASTEXITREASON_CPP_CRASH);
    EXPECT_EQ(result->launchReasonMessage, "call reason");
    EXPECT_EQ(result->lastExitMessage, "crash message");
    EXPECT_EQ(result->lastExitDetailInfo.pid, 5523);
    EXPECT_EQ(result->lastExitDetailInfo.uid, 520);
    EXPECT_EQ(result->lastExitDetailInfo.processName, "crash_process");
    EXPECT_EQ(result->lastExitDetailInfo.exitMsg, "cpp crash");
    EXPECT_EQ(result->launchUptime, 0);
    EXPECT_EQ(result->launchUTCTime, 0);
    delete result;
}

/**
 * @tc.number: LaunchParam_Marshalling_Unmarshalling_002
 * @tc.desc: Test complete marshalling and unmarshalling cycle
 * @tc.type: FUNC
 */
HWTEST_F(LaunchParamTest, LaunchParam_Marshalling_Unmarshalling_002, TestSize.Level1)
{
    Parcel parcel;
    LaunchParam original;
    original.launchReason = LaunchReason::LAUNCHREASON_APP_RECOVERY;
    original.lastExitReason = LastExitReason::LASTEXITREASON_JS_ERROR;
    original.launchReasonMessage = "recovery message";
    original.lastExitMessage = "js error details";
    original.lastExitDetailInfo.pid = 520;
    original.lastExitDetailInfo.uid = 5201314;
    original.lastExitDetailInfo.exitSubReason = 1;
    original.lastExitDetailInfo.rss = 666;
    original.lastExitDetailInfo.pss = 888;
    original.lastExitDetailInfo.processState = 1;
    original.lastExitDetailInfo.timestamp = 0;
    original.lastExitDetailInfo.processName = "recovery_process";
    original.lastExitDetailInfo.exitMsg = "js error occurred";
    original.launchUptime = 0;
    original.launchUTCTime = 0;

    EXPECT_TRUE(original.Marshalling(parcel));

    LaunchParam* result = LaunchParam::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->launchReason, original.launchReason);
    EXPECT_EQ(result->lastExitReason, original.lastExitReason);
    EXPECT_EQ(result->launchReasonMessage, original.launchReasonMessage);
    EXPECT_EQ(result->lastExitMessage, original.lastExitMessage);
    EXPECT_EQ(result->lastExitDetailInfo.pid, original.lastExitDetailInfo.pid);
    EXPECT_EQ(result->lastExitDetailInfo.uid, original.lastExitDetailInfo.uid);
    EXPECT_EQ(result->lastExitDetailInfo.exitSubReason, original.lastExitDetailInfo.exitSubReason);
    EXPECT_EQ(result->lastExitDetailInfo.rss, original.lastExitDetailInfo.rss);
    EXPECT_EQ(result->lastExitDetailInfo.pss, original.lastExitDetailInfo.pss);
    EXPECT_EQ(result->lastExitDetailInfo.processState, original.lastExitDetailInfo.processState);
    EXPECT_EQ(result->lastExitDetailInfo.timestamp, original.lastExitDetailInfo.timestamp);
    EXPECT_EQ(result->lastExitDetailInfo.processName, original.lastExitDetailInfo.processName);
    EXPECT_EQ(result->lastExitDetailInfo.exitMsg, original.lastExitDetailInfo.exitMsg);
    EXPECT_EQ(result->launchUptime, original.launchUptime);
    EXPECT_EQ(result->launchUTCTime, original.launchUTCTime);

    delete result;
}

} // namespace AAFwk
} // namespace OHOS