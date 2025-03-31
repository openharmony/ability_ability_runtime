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

#include "insight_intent/insight_intent_profile.cpp"
#include "insight_intent_profile.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
namespace {
    const std::string profileJsonStr = "{"
        "\"insightIntents\":["
        "{"
            "\"intentName\":\"test1\","
            "\"domain\":\"domain1\","
            "\"intentVersion\":\"1.0\","
            "\"srcEntry\":\"entry1\","
            "\"uiAbility\":{"
                "\"ability\":\"ability1\","
                "\"executeMode\":[\"foreground\"]"
            "},"
            "\"uiExtension\":{"
                "\"ability\":\"ability1\""
            "},"
            "\"serviceExtension\":{"
                "\"ability\":\"ability1\""
            "},"
            "\"form\":{"
                "\"ability\":\"ability1\","
                "\"formName\":\"form1\""
            "}"
        "},"
        "{"
            "\"intentName\":\"test2\","
            "\"domain\":\"domain1\","
            "\"intentVersion\":\"1.0\","
            "\"srcEntry\":\"entry1\","
            "\"uiAbility\":{"
                "\"ability\":\"ability1\","
                "\"executeMode\":[\"foreground\"]"
            "},"
            "\"uiExtension\":{"
                "\"ability\":\"ability1\""
            "},"
            "\"serviceExtension\":{"
                "\"ability\":\"ability1\""
            "},"
            "\"form\": {"
                "\"ability\":\"ability1\","
                "\"formName\":\"form1\""
            "}"
        "}"
        "]"
    "}";
}

class InsightIntentProfileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void InsightIntentProfileTest::SetUpTestCase()
{}

void InsightIntentProfileTest::TearDownTestCase()
{}

void InsightIntentProfileTest::SetUp()
{}

void InsightIntentProfileTest::TearDown()
{}

/**
 * @tc.number: TransformToInsightIntentInfo_0100
 * @tc.name: TransformToInsightIntentInfo
 * @tc.desc: Test whether TransformToInsightIntentInfo and are called normally.
 */
HWTEST_F(InsightIntentProfileTest, TransformToInsightIntentInfo_0100, TestSize.Level2)
{
    InsightIntentProfileInfo insightIntent;
    InsightIntentInfo info;
    insightIntent.intentName = "";
    EXPECT_FALSE(TransformToInsightIntentInfo(insightIntent, info));

    insightIntent.intentName = "testIntent";
    insightIntent.intentDomain = "testDomain";
    insightIntent.intentVersion = "1.0";
    insightIntent.srcEntry = "testEntry";
    EXPECT_TRUE(TransformToInsightIntentInfo(insightIntent, info));
    EXPECT_EQ(info.intentName, "testIntent");
    EXPECT_EQ(info.intentDomain, "testDomain");
    EXPECT_EQ(info.intentVersion, "1.0");
    EXPECT_EQ(info.srcEntry, "testEntry");
}

/**
 * @tc.number: TransformToInsightIntentInfo_0200
 * @tc.name: TransformToInsightIntentInfo
 * @tc.desc: Test whether TransformToInsightIntentInfo and are called normally.
 */
HWTEST_F(InsightIntentProfileTest, TransformToInsightIntentInfo_0200, TestSize.Level2)
{
    InsightIntentProfileInfo insightIntent;
    InsightIntentInfo info;

    insightIntent.intentName = "testIntent";
    insightIntent.uiAbilityProfileInfo.supportExecuteMode = {"invalidMode"};

    TransformToInsightIntentInfo(insightIntent, info);

    EXPECT_EQ(info.uiAbilityIntentInfo.supportExecuteMode.size(), 0);
}

/**
 * @tc.number: TransformToInfos_0300
 * @tc.name: TransformToInfos
 * @tc.desc: Test whether TransformToInfos and are called normally.
 */
HWTEST_F(InsightIntentProfileTest, TransformToInfos_0300, TestSize.Level2)
{
    InsightIntentProfileInfoVec profileInfos;
    InsightIntentProfileInfo insightIntent;
    insightIntent.intentName = "testIntent";
    insightIntent.intentDomain = "testDomain";
    insightIntent.intentVersion = "1.0";
    insightIntent.srcEntry = "testEntry";
    profileInfos.insightIntents.push_back(insightIntent);
    std::vector<InsightIntentInfo> intentInfos;
    bool result = TransformToInfos(profileInfos, intentInfos);
    EXPECT_TRUE(result);
    EXPECT_EQ(intentInfos.size(), 1);
}

/**
 * @tc.number: TransformToInfos_0400
 * @tc.name: TransformToInfos
 * @tc.desc: Test whether TransformToInfos and are called normally.
 */
HWTEST_F(InsightIntentProfileTest, TransformToInfos_0400, TestSize.Level2)
{
    InsightIntentProfileInfoVec profileInfos;
    std::vector<InsightIntentInfo> intentInfos;
    InsightIntentProfileInfo insightIntent;
    insightIntent.intentName = "";
    profileInfos.insightIntents.push_back(insightIntent);
    bool result = TransformToInfos(profileInfos, intentInfos);
    EXPECT_FALSE(result);
    EXPECT_EQ(intentInfos.size(), 0);
}

/**
 * @tc.number: TransformTo_0500
 * @tc.name: TransformTo
 * @tc.desc: Test whether TransformTo and are called normally.
 */
HWTEST_F(InsightIntentProfileTest, TransformTo_0500, TestSize.Level2)
{
    std::string profileStr = "not a valid json string";
    std::vector<InsightIntentInfo> intentInfos;
    bool result = InsightIntentProfile::TransformTo(profileStr, intentInfos);
    EXPECT_FALSE(result);
    EXPECT_EQ(intentInfos.size(), 0);
}

/**
 * @tc.number: TransformTo_0600
 * @tc.name: TransformTo
 * @tc.desc: Test whether TransformTo and are called normally.
 */
HWTEST_F(InsightIntentProfileTest, TransformTo_0600, TestSize.Level2)
{
    std::vector<InsightIntentInfo> intentInfos;
    bool result = InsightIntentProfile::TransformTo(profileJsonStr, intentInfos);
    EXPECT_TRUE(result);
    EXPECT_EQ(intentInfos.size(), 2);
}

/**
 * @tc.number: TransformTo_0700
 * @tc.name: TransformTo
 * @tc.desc: Test whether TransformTo and are called normally.
 */
HWTEST_F(InsightIntentProfileTest, TransformTo_0700, TestSize.Level2)
{
    std::string profileStr = "{\"insightIntents\":\"test\"}";
    std::vector<InsightIntentInfo> intentInfos;
    bool result = InsightIntentProfile::TransformTo(profileStr, intentInfos);
    EXPECT_EQ(intentInfos.size(), 0);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
