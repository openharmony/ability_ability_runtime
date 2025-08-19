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

#include "hilog_tag_wrapper.h"
#include "json_utils.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace AAFwk {
class JsonUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void JsonUtilsTest::SetUpTestCase(void)
{}

void JsonUtilsTest::TearDownTestCase(void)
{}

void JsonUtilsTest::SetUp()
{}

void JsonUtilsTest::TearDown()
{}

/**
 * @tc.number: JsonToBool_0100
 * @tc.desc: Test JsonToBool works
 * @tc.type: FUNC
 */
HWTEST_F(JsonUtilsTest, JsonToBool_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "JsonToBool_0100 start.");

    const std::string jsonStr = R"({
        "key1": true
    })";
    nlohmann::json jsonObj = nlohmann::json::parse(jsonStr);
    bool result = JsonUtils::GetInstance().JsonToBool(jsonObj, "key1", false);
    EXPECT_EQ(result, true);

    TAG_LOGI(AAFwkTag::TEST, "JsonToBool_0100 end.");
}

/**
 * @tc.number: JsonToBool_0200
 * @tc.desc: Test JsonToBool works
 * @tc.type: FUNC
 */
HWTEST_F(JsonUtilsTest, JsonToBool_0200, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "JsonToBool_0200 start.");

    const std::string jsonStr = R"({
        "key1": true
    })";
    nlohmann::json jsonObj = nlohmann::json::parse(jsonStr);
    bool result = JsonUtils::GetInstance().JsonToBool(jsonObj, "key2", false);
    EXPECT_EQ(result, false);

    TAG_LOGI(AAFwkTag::TEST, "JsonToBool_0200 end.");
}

/**
 * @tc.number: JsonToBool_0300
 * @tc.desc: Test JsonToBool works
 * @tc.type: FUNC
 */
HWTEST_F(JsonUtilsTest, JsonToBool_0300, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "JsonToBool_0300 start.");

    const std::string jsonStr = R"({
        "key1": "invalid_value"
    })";
    nlohmann::json jsonObj = nlohmann::json::parse(jsonStr);
    bool result = JsonUtils::GetInstance().JsonToBool(jsonObj, "key1", true);
    EXPECT_EQ(result, true);

    TAG_LOGI(AAFwkTag::TEST, "JsonToBool_0300 end.");
}

/**
 * @tc.number: JsonToUnorderedStrSet_0100
 * @tc.desc: Test JsonToUnorderedStrSet works
 * @tc.type: FUNC
 */
HWTEST_F(JsonUtilsTest, JsonToUnorderedStrSet_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "JsonToUnorderedStrSet_0100 start.");

    const std::string jsonStr = R"({
        "key1": ["value1", "value2"]
    })";
    nlohmann::json jsonObj = nlohmann::json::parse(jsonStr);
    std::unordered_set<std::string> set;
    JsonUtils::GetInstance().JsonToUnorderedStrSet(jsonObj, "key2", set);
    EXPECT_EQ(set.size(), 0);

    TAG_LOGI(AAFwkTag::TEST, "JsonToUnorderedStrSet_0100 end.");
}

/**
 * @tc.number: JsonToUnorderedStrSet_0200
 * @tc.desc: Test JsonToUnorderedStrSet works
 * @tc.type: FUNC
 */
HWTEST_F(JsonUtilsTest, JsonToUnorderedStrSet_0200, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "JsonToUnorderedStrSet_0200 start.");

    const std::string jsonStr = R"({
        "key1": "invalid_array"
    })";
    nlohmann::json jsonObj = nlohmann::json::parse(jsonStr);
    std::unordered_set<std::string> set;
    JsonUtils::GetInstance().JsonToUnorderedStrSet(jsonObj, "key1", set);
    EXPECT_EQ(set.size(), 0);

    TAG_LOGI(AAFwkTag::TEST, "JsonToUnorderedStrSet_0200 end.");
}

/**
 * @tc.number: JsonToUnorderedStrSet_0300
 * @tc.desc: Test JsonToUnorderedStrSet works
 * @tc.type: FUNC
 */
HWTEST_F(JsonUtilsTest, JsonToUnorderedStrSet_0300, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "JsonToUnorderedStrSet_0300 start.");

    const std::string jsonStr = R"({
        "key1": ["value1", "value2", "value3"]
    })";
    nlohmann::json jsonObj = nlohmann::json::parse(jsonStr);
    std::unordered_set<std::string> set;
    JsonUtils::GetInstance().JsonToUnorderedStrSet(jsonObj, "key1", set);
    EXPECT_EQ(set.size(), 3);

    TAG_LOGI(AAFwkTag::TEST, "JsonToUnorderedStrSet_0300 end.");
}

/**
 * @tc.number: JsonToUnorderedStrSet_0400
 * @tc.desc: Test JsonToUnorderedStrSet works
 * @tc.type: FUNC
 */
HWTEST_F(JsonUtilsTest, JsonToUnorderedStrSet_0400, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "JsonToUnorderedStrSet_0400 start.");

    const std::string jsonStr = R"({
        "key1": ["value1", 2, "value3"]
    })";
    nlohmann::json jsonObj = nlohmann::json::parse(jsonStr);
    std::unordered_set<std::string> set;
    JsonUtils::GetInstance().JsonToUnorderedStrSet(jsonObj, "key1", set);
    EXPECT_EQ(set.size(), 2);

    TAG_LOGI(AAFwkTag::TEST, "JsonToUnorderedStrSet_0400 end.");
}
}  // namespace AbilityRuntime
}  // namespace OHOS
