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

/**
 * @tc.number: TransformToInsightIntentInfo_0300
 * @tc.name: TransformToInsightIntentInfo
 * @tc.desc: Test TransformToInsightIntentInfo with valid executeMode
 */
HWTEST_F(InsightIntentProfileTest, TransformToInsightIntentInfo_0300, TestSize.Level2)
{
    InsightIntentProfileInfo insightIntent;
    InsightIntentInfo info;

    insightIntent.intentName = "testIntent";
    insightIntent.uiAbilityProfileInfo.supportExecuteMode = {"foreground", "background"};

    TransformToInsightIntentInfo(insightIntent, info);

    EXPECT_EQ(info.uiAbilityIntentInfo.supportExecuteMode.size(), 2);
    EXPECT_EQ(info.uiAbilityIntentInfo.supportExecuteMode[0], ExecuteMode::UI_ABILITY_FOREGROUND);
    EXPECT_EQ(info.uiAbilityIntentInfo.supportExecuteMode[1], ExecuteMode::UI_ABILITY_BACKGROUND);
}

/**
 * @tc.number: TransformToInsightIntentInfo_0400
 * @tc.name: TransformToInsightIntentInfo
 * @tc.desc: Test TransformToInsightIntentInfo with extended fields
 */
HWTEST_F(InsightIntentProfileTest, TransformToInsightIntentInfo_0400, TestSize.Level2)
{
    InsightIntentProfileInfo insightIntent;
    InsightIntentInfo info;

    insightIntent.intentName = "testIntent";
    insightIntent.arkTSMode = "arkTSModeTest";
    insightIntent.displayName = "displayNameTest";
    insightIntent.icon = "iconTest";
    insightIntent.displayDescription = "descTest";
    insightIntent.bundleName = "bundleTest";
    insightIntent.moduleName = "moduleTest";
    insightIntent.keywords = {"key1", "key2"};
    insightIntent.cfgEntities = "{\"entity\":\"test\"}";
    insightIntent.inputParams = {"{\"param1\":\"value1\"}"};
    insightIntent.outputParams = {"{\"param2\":\"value2\"}"};
    insightIntent.uiExtensionProfileInfo.abilityName = "uiExtAbility";
    insightIntent.serviceExtensionProfileInfo.abilityName = "serviceExtAbility";
    insightIntent.formProfileInfo.abilityName = "formAbility";
    insightIntent.formProfileInfo.formName = "formNameTest";

    TransformToInsightIntentInfo(insightIntent, info);

    EXPECT_EQ(info.arkTSMode, "arkTSModeTest");
    EXPECT_EQ(info.displayName, "displayNameTest");
    EXPECT_EQ(info.icon, "iconTest");
    EXPECT_EQ(info.displayDescription, "descTest");
    EXPECT_EQ(info.bundleName, "bundleTest");
    EXPECT_EQ(info.moduleName, "moduleTest");
    EXPECT_EQ(info.keywords.size(), 2);
    EXPECT_EQ(info.cfgEntities, "{\"entity\":\"test\"}");
    EXPECT_EQ(info.inputParams.size(), 1);
    EXPECT_EQ(info.outputParams.size(), 1);
    EXPECT_EQ(info.uiExtensionIntentInfo.abilityName, "uiExtAbility");
    EXPECT_EQ(info.serviceExtensionIntentInfo.abilityName, "serviceExtAbility");
    EXPECT_EQ(info.formIntentInfo.abilityName, "formAbility");
    EXPECT_EQ(info.formIntentInfo.formName, "formNameTest");
}

/**
 * @tc.number: TransformTo_0800
 * @tc.name: TransformTo
 * @tc.desc: Test TransformTo with parse error (g_parseResult != ERR_OK)
 */
HWTEST_F(InsightIntentProfileTest, TransformTo_0800, TestSize.Level2)
{
    std::string profileStr = "{"
        "\"insightIntents\":["
        "{"
            "\"intentName\":\"\","
            "\"domain\":\"domain1\","
            "\"intentVersion\":\"1.0\","
            "\"srcEntry\":\"entry1\""
        "}"
        "]"
    "}";
    std::vector<InsightIntentInfo> intentInfos;
    bool result = InsightIntentProfile::TransformTo(profileStr, intentInfos);
    EXPECT_FALSE(result);
    EXPECT_EQ(intentInfos.size(), 0);
}

/**
 * @tc.number: ToJson_0100
 * @tc.name: ToJson
 * @tc.desc: Test InsightIntentProfile::ToJson with valid info
 */
HWTEST_F(InsightIntentProfileTest, ToJson_0100, TestSize.Level2)
{
    InsightIntentInfo info;
    nlohmann::json jsonObject;

    info.intentName = "testIntent";
    info.intentDomain = "testDomain";
    info.intentVersion = "1.0";
    info.srcEntry = "testEntry";
    info.uiAbilityIntentInfo.abilityName = "uiAbilityTest";
    info.uiAbilityIntentInfo.supportExecuteMode = {ExecuteMode::UI_ABILITY_FOREGROUND};
    info.cfgEntities = "{\"entity\":\"test\"}";
    info.inputParams = {"{\"param1\":\"value1\"}"};
    info.outputParams = {"{\"param2\":\"value2\"}"};

    bool result = InsightIntentProfile::ToJson(info, jsonObject);
    EXPECT_TRUE(result);
    EXPECT_TRUE(jsonObject.contains("insightIntents"));
    EXPECT_EQ(jsonObject["insightIntents"].size(), 1);
    EXPECT_EQ(jsonObject["insightIntents"][0]["intentName"], "testIntent");
}

/**
 * @tc.number: ToJson_0200
 * @tc.name: ToJson
 * @tc.desc: Test InsightIntentProfile::ToJson with invalid cfgEntities
 */
HWTEST_F(InsightIntentProfileTest, ToJson_0200, TestSize.Level2)
{
    InsightIntentInfo info;
    nlohmann::json jsonObject;

    info.intentName = "testIntent";
    info.cfgEntities = "invalid json";

    bool result = InsightIntentProfile::ToJson(info, jsonObject);
    EXPECT_TRUE(result); // ToJson仍返回true，但cfgEntities字段不会被添加
    EXPECT_FALSE(jsonObject["insightIntents"][0].contains("entites"));
}

/**
 * @tc.number: ToJson_0300
 * @tc.name: ToJson
 * @tc.desc: Test InsightIntentProfile::ToJson with empty input/output params
 */
HWTEST_F(InsightIntentProfileTest, ToJson_0300, TestSize.Level2)
{
    InsightIntentInfo info;
    nlohmann::json jsonObject;

    info.intentName = "testIntent";
    info.inputParams = {""};
    info.outputParams = {""};

    bool result = InsightIntentProfile::ToJson(info, jsonObject);
    EXPECT_TRUE(result);
    EXPECT_EQ(jsonObject["insightIntents"][0]["inputParams"].size(), 0);
    EXPECT_EQ(jsonObject["insightIntents"][0]["outputParams"].size(), 0);
}

/**
 * @tc.number: ParseParamsElement_0100
 * @tc.name: ParseParamsElement
 * @tc.desc: Test ParseParamsElement with invalid param type
 */
HWTEST_F(InsightIntentProfileTest, ParseParamsElement_0100, TestSize.Level2)
{
    nlohmann::json param = "not an object";
    std::string errorMsg;

    bool result = ParseParamsElement(param, errorMsg);
    EXPECT_FALSE(result);
    EXPECT_EQ(errorMsg, "type error: inputParams or outputParams element not object");
}

/**
 * @tc.number: ProcessIntputParams_0100
 * @tc.name: ProcessIntputParams
 * @tc.desc: Test ProcessIntputParams with non-array inputParams
 */
HWTEST_F(InsightIntentProfileTest, ProcessIntputParams_0100, TestSize.Level2)
{
    nlohmann::json jsonObject;
    jsonObject["inputParams"] = "not an array";
    InsightIntentProfileInfo insightIntentInfo;
    int32_t parseResult = ERR_OK;

    ProcessIntputParams(jsonObject, insightIntentInfo, parseResult);
    EXPECT_EQ(parseResult, ERR_INVALID_VALUE);
}

/**
 * @tc.number: ProcessOutputParams_0100
 * @tc.name: ProcessOutputParams
 * @tc.desc: Test ProcessOutputParams with non-array outputParams
 */
HWTEST_F(InsightIntentProfileTest, ProcessOutputParams_0100, TestSize.Level2)
{
    nlohmann::json jsonObject;
    jsonObject["outputParams"] = "not an array";
    InsightIntentProfileInfo insightIntentInfo;
    int32_t parseResult = ERR_OK;

    ProcessOutputParams(jsonObject, insightIntentInfo, parseResult);
    EXPECT_EQ(parseResult, ERR_INVALID_VALUE);
}

/**
 * @tc.number: TransformTo_0900
 * @tc.name: TransformTo
 * @tc.desc: Test TransformTo with entities field type error
 */
HWTEST_F(InsightIntentProfileTest, TransformTo_0900, TestSize.Level2)
{
    std::string profileStr = "{"
        "\"insightIntents\":["
        "{"
            "\"intentName\":\"test1\","
            "\"domain\":\"domain1\","
            "\"intentVersion\":\"1.0\","
            "\"srcEntry\":\"entry1\","
            "\"entites\":\"not an object\""
        "}"
        "]"
    "}";
    std::vector<InsightIntentInfo> intentInfos;
    bool result = InsightIntentProfile::TransformTo(profileStr, intentInfos);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: ToJson_0400
 * @tc.name: ToJson
 * @tc.desc: Test InsightIntentProfile::ToJson with discarded json object
 */
HWTEST_F(InsightIntentProfileTest, ToJson_0400, TestSize.Level2)
{
    InsightIntentInfo info;
    info.intentName = "";
    nlohmann::json jsonObject;

    bool result = InsightIntentProfile::ToJson(info, jsonObject);
    EXPECT_TRUE(result);
}

}  // namespace AbilityRuntime
}  // namespace OHOS
