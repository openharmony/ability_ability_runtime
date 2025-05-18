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

#include "insight_intent/extract_insight_intent_profile.cpp"
#include "extract_insight_intent_profile.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
namespace {
    const std::string errProfileJsonStr = "{"
        "\"insightIntents\": ["
        "{"
            "\"displayDescription\": \"game\","
            "\"schema\": \"GameList\","
            "\"keywords\": [\"123234345\",\"12345654321\"],"
            "\"intentName\": \"123\","
            "\"displayName\": \"Home\","
            "\"decoratorClass\": \"base\","
            "\"icon\": \"$r('app.media.startIcon')\","
            "\"moduleName\": \"entry\","
            "\"decoratorFile\": \"@normalized:N&&&entry/src/main/ets/pages/Index&\","
            "\"uri\": \"/data/app/base\","
            "\"paramMappings\": ["
              "{"
                "\"paramCategory\": \"dddd\","
                "\"paramMappingName\": \"ccc\","
                "\"paramName\": \"aaa\""
              "}"
            "],"
            "\"decoratorType\": \"@InsightIntentLinkErr\","
            "\"llmDescription\": \"123111321\","
            "\"domain\": \"game\","
            "\"intentVersion\": \"1.0.2\","
            "\"bundleName\": \"com.example.instent\","
            "\"parameters\": {"
              "\"type\": \"object\","
              "\"items\": {"
                "\"type\": \"array\","
                "\"items\": {"
                  "\"propertyNames\": {"
                    "\"enum\": [\"entityId\",\"entityGroupId\",\"gameType\"]"
                  "},"
                  "\"type\": \"object\","
                  "\"required\": [\"entityId\"],"
                  "\"properties\": {"
                    "\"gameType\": {"
                      "\"description\": \"游戏类型\","
                      "\"type\": \"string\","
                      "\"enum\": [\"3D\",\"2D\",\"RPG\"]"
                    "},"
                    "\"entityId\": {"
                      "\"description\": \"游戏唯一实体 id\","
                      "\"type\": \"string\""
                    "},"
                    "\"entityGroupId\": {"
                      "\"description\": \"用于确定游戏的更新形式（每日游戏）\","
                      "\"type\": \"string\""
                    "}"
                  "}"
                "}"
              "}"
            "}"
        "},"
        "{"
            "\"displayDescription\": \"music\","
            "\"schema\": \"ControlPlayback\","
            "\"keywords\": [\"ControlPlayback\"],"
            "\"intentName\": \"123\","
            "\"displayName\": \"Home\","
            "\"decoratorClass\": \"base\","
            "\"icon\": \"$r('app.media.startIcon')\","
            "\"moduleName\": \"entry\","
            "\"decoratorFile\": \"@normalized:N&&&entry/src/main/ets/pages/Index&\","
            "\"uri\": \"/data/app/base\","
            "\"paramMappings\": ["
              "{"
                "\"paramCategory\": \"dddd\","
                "\"paramMappingName\": \"ccc\","
                "\"paramName\": \"aaa\""
              "}"
            "],"
            "\"decoratorType\": \"@InsightIntentLinkErr2\","
            "\"llmDescription\": \"播放音乐控制\","
            "\"domain\": \"control\","
            "\"intentVersion\": \"1.0.1\","
            "\"bundleName\": \"com.example.instent\","
            "\"parameters\": {"
              "\"oneOf\": ["
                "{"
                  "\"required\": [\"playbackSpeed\"]"
                "},"
                "{"
                  "\"required\": [\"playbackProgress\"]"
                "}"
              "],"
              "\"propertyNames\": {"
                "\"enum\": [\"playbackSpeed\",\"playbackProgress\"]"
              "},"
              "\"type\": \"object\","
              "\"properties\": {"
                "\"playbackSpeed\": {"
                  "\"description\": \"播放倍速\","
                  "\"type\": \"number\","
                  "\"enum\": [0.5,0.75,1,1.25,1.5,2]"
                "},"
                "\"playbackProgress\": {"
                  "\"description\": \"播放进度,单位秒\","
                  "\"type\": \"number\""
                "}"
              "}"
            "}"
        "}"
        "]"
    "}";

    const std::string profileJsonStr = "{"
        "\"insightIntents\": ["
        "{"
            "\"displayDescription\": \"game\","
            "\"schema\": \"GameList\","
            "\"keywords\": [\"123234345\",\"12345654321\"],"
            "\"intentName\": \"123\","
            "\"displayName\": \"Home\","
            "\"decoratorClass\": \"base\","
            "\"icon\": \"$r('app.media.startIcon')\","
            "\"moduleName\": \"entry\","
            "\"decoratorFile\": \"@normalized:N&&&entry/src/main/ets/pages/Index&\","
            "\"uri\": \"/data/app/base\","
            "\"paramMappings\": ["
              "{"
                "\"paramCategory\": \"dddd\","
                "\"paramMappingName\": \"ccc\","
                "\"paramName\": \"aaa\""
              "}"
            "],"
            "\"decoratorType\": \"@InsightIntentLink\","
            "\"llmDescription\": \"123111321\","
            "\"domain\": \"game\","
            "\"intentVersion\": \"1.0.2\","
            "\"bundleName\": \"com.example.instent\","
            "\"parameters\": {"
              "\"type\": \"object\","
              "\"items\": {"
                "\"type\": \"array\","
                "\"items\": {"
                  "\"propertyNames\": {"
                    "\"enum\": [\"entityId\",\"entityGroupId\",\"gameType\"]"
                  "},"
                  "\"type\": \"object\","
                  "\"required\": [\"entityId\"],"
                  "\"properties\": {"
                    "\"gameType\": {"
                      "\"description\": \"游戏类型\","
                      "\"type\": \"string\","
                      "\"enum\": [\"3D\",\"2D\",\"RPG\"]"
                    "},"
                    "\"entityId\": {"
                      "\"description\": \"游戏唯一实体 id\","
                      "\"type\": \"string\""
                    "},"
                    "\"entityGroupId\": {"
                      "\"description\": \"用于确定游戏的更新形式（每日游戏）\","
                      "\"type\": \"string\""
                    "}"
                  "}"
                "}"
              "}"
            "}"
        "},"
        "{"
            "\"displayDescription\": \"music\","
            "\"schema\": \"ControlPlayback\","
            "\"keywords\": [\"ControlPlayback\"],"
            "\"intentName\": \"InsightIntent2\","
            "\"displayName\": \"Home\","
            "\"decoratorClass\": \"base\","
            "\"icon\": \"$r('app.media.startIcon')\","
            "\"moduleName\": \"entry\","
            "\"decoratorFile\": \"@normalized:N&&&entry/src/main/ets/pages/Index&\","
            "\"uri\": \"/data/app/base\","
            "\"paramMappings\": ["
              "{"
                "\"paramCategory\": \"dddd\","
                "\"paramMappingName\": \"ccc\","
                "\"paramName\": \"aaa\""
              "}"
            "],"
            "\"decoratorType\": \"@InsightIntentLink\","
            "\"llmDescription\": \"播放音乐控制\","
            "\"domain\": \"control\","
            "\"intentVersion\": \"1.0.1\","
            "\"bundleName\": \"com.example.instent\","
            "\"parameters\": {"
              "\"oneOf\": ["
                "{"
                  "\"required\": [\"playbackSpeed\"]"
                "},"
                "{"
                  "\"required\": [\"playbackProgress\"]"
                "}"
              "],"
              "\"propertyNames\": {"
                "\"enum\": [\"playbackSpeed\",\"playbackProgress\"]"
              "},"
              "\"type\": \"object\","
              "\"properties\": {"
                "\"playbackSpeed\": {"
                  "\"description\": \"播放倍速\","
                  "\"type\": \"number\","
                  "\"enum\": [0.5,0.75,1,1.25,1.5,2]"
                "},"
                "\"playbackProgress\": {"
                  "\"description\": \"播放进度,单位秒\","
                  "\"type\": \"number\""
                "}"
              "}"
            "}"
        "}"
        "]"
    "}";
}

class ExtractInsightIntentProfileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void ExtractInsightIntentProfileTest::SetUpTestCase()
{}

void ExtractInsightIntentProfileTest::TearDownTestCase()
{}

void ExtractInsightIntentProfileTest::SetUp()
{}

void ExtractInsightIntentProfileTest::TearDown()
{}

/**
 * @tc.number: TransformTo_0100
 * @tc.name: TransformTo
 * @tc.desc: Test TransformTo invalid param profileStr.
 */
HWTEST_F(ExtractInsightIntentProfileTest, TransformTo_0100, TestSize.Level0)
{
    ExtractInsightIntentProfileInfoVec infos;
    bool result = ExtractInsightIntentProfile::TransformTo(errProfileJsonStr, infos);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: TransformTo_0200
 * @tc.name: TransformTo, ToJson, ProfileInfoFormat
 * @tc.desc: Test TransformTo profileStr success.
 */
HWTEST_F(ExtractInsightIntentProfileTest, TransformTo_0200, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "TransformTo_0200 called. start");
    TAG_LOGI(AAFwkTag::TEST, "profileJsonStr: %{public}s", profileJsonStr.c_str());
    ExtractInsightIntentProfileInfoVec profileInfos;
    bool result = ExtractInsightIntentProfile::TransformTo(profileJsonStr, profileInfos);
    EXPECT_EQ(result, true);
    EXPECT_EQ(profileInfos.insightIntents.size(), 2);
    EXPECT_EQ(profileInfos.insightIntents[0].decoratorType, "@InsightIntentLink");
    EXPECT_EQ(profileInfos.insightIntents[0].intentName, "123");
    EXPECT_EQ(profileInfos.insightIntents[1].decoratorType, "@InsightIntentLink");
    EXPECT_EQ(profileInfos.insightIntents[1].intentName, "InsightIntent2");

    nlohmann::json jsonObject1;
    result = ExtractInsightIntentProfile::ToJson(profileInfos.insightIntents[0], jsonObject1);
    EXPECT_EQ(result, true);
    ExtractInsightIntentProfileInfoVec profileInfos1;
    result = ExtractInsightIntentProfile::TransformTo(jsonObject1.dump(), profileInfos1);
    EXPECT_EQ(result, true);
    TAG_LOGI(AAFwkTag::TEST, "jsonObject1 dump: %{public}s", jsonObject1.dump().c_str());
    EXPECT_EQ(profileInfos1.insightIntents.size(), 1);
    EXPECT_EQ(profileInfos1.insightIntents[0].decoratorType, "@InsightIntentLink");
    EXPECT_EQ(profileInfos1.insightIntents[0].intentName, "123");

    nlohmann::json jsonObject2;
    result = ExtractInsightIntentProfile::ToJson(profileInfos.insightIntents[1], jsonObject2);
    EXPECT_EQ(result, true);
    ExtractInsightIntentProfileInfoVec profileInfos2;
    result = ExtractInsightIntentProfile::TransformTo(jsonObject2.dump(), profileInfos2);
    EXPECT_EQ(result, true);
    TAG_LOGI(AAFwkTag::TEST, "jsonObject2 dump: %{public}s", jsonObject2.dump().c_str());
    EXPECT_EQ(profileInfos2.insightIntents.size(), 1);
    EXPECT_EQ(profileInfos2.insightIntents[0].decoratorType, "@InsightIntentLink");
    EXPECT_EQ(profileInfos2.insightIntents[0].intentName, "InsightIntent2");

    ExtractInsightIntentInfo info1;
    result = ExtractInsightIntentProfile::ProfileInfoFormat(profileInfos1.insightIntents[0], info1);
    EXPECT_EQ(result, true);
    EXPECT_EQ(info1.domain, "game");
    EXPECT_EQ(info1.genericInfo.decoratorType, "@InsightIntentLink");
    InsightIntentLinkInfo linkInfo1 = info1.genericInfo.get<InsightIntentLinkInfo>();
    EXPECT_EQ(linkInfo1.uri, "/data/app/base");
    EXPECT_EQ(linkInfo1.paramMapping.size(), 1);

    ExtractInsightIntentInfo info2;
    result = ExtractInsightIntentProfile::ProfileInfoFormat(profileInfos2.insightIntents[0], info2);
    EXPECT_EQ(result, true);
    EXPECT_EQ(info2.domain, "control");
    EXPECT_EQ(info2.genericInfo.decoratorType, "@InsightIntentLink");
    InsightIntentLinkInfo linkInfo2 = info2.genericInfo.get<InsightIntentLinkInfo>();
    EXPECT_EQ(linkInfo2.uri, "/data/app/base");
    EXPECT_EQ(linkInfo2.paramMapping.size(), 1);
    TAG_LOGI(AAFwkTag::TEST, "TransformTo_0200 called. end");
}
}  // namespace AbilityRuntime
}  // namespace OHOS
