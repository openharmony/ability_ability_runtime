/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include <unordered_set>
#include <vector>

#include "tool_util.h"
#include "cli_error_code.h"

using namespace testing::ext;
using namespace OHOS::CliTool;

namespace OHOS {
namespace CliTool {

class ToolUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ToolUtilTest::SetUpTestCase(void)
{
    // Initialize test environment
}

void ToolUtilTest::TearDownTestCase(void)
{
    // Cleanup test environment
}

void ToolUtilTest::SetUp()
{
    // Reset state before each test
}

void ToolUtilTest::TearDown()
{
    // Cleanup after each test
}

/**
 * @tc.name: ToolUtil_ValidateInputSchemaProperties_0100
 * @tc.desc: Test ValidateInputSchemaProperties with empty schema
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, ValidateInputSchemaProperties_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0100 start";

    std::string emptySchema = "";
    std::string subcommand = "";
    std::map<std::string, std::string> args;

    int32_t result = ToolUtil::ValidateInputSchemaProperties(emptySchema, subcommand, args);

    EXPECT_EQ(result, ERR_TOOL_NOT_EXIST);

    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0100 end";
}

/**
 * @tc.name: ToolUtil_ValidateInputSchemaProperties_0200
 * @tc.desc: Test ValidateInputSchemaProperties with invalid JSON schema
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, ValidateInputSchemaProperties_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0200 start";

    std::string invalidSchema = "{invalid json}";
    std::string subcommand = "";
    std::map<std::string, std::string> args;

    int32_t result = ToolUtil::ValidateInputSchemaProperties(invalidSchema, subcommand, args);

    EXPECT_EQ(result, ERR_TOOL_NOT_EXIST);

    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0200 end";
}

/**
 * @tc.name: ToolUtil_ValidateInputSchemaProperties_0300
 * @tc.desc: Test ValidateInputSchemaProperties with schema missing properties
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, ValidateInputSchemaProperties_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0300 start";

    std::string schema = R"({"type": "object"})";
    std::string subcommand = "";
    std::map<std::string, std::string> args;

    int32_t result = ToolUtil::ValidateInputSchemaProperties(schema, subcommand, args);

    EXPECT_EQ(result, ERR_TOOL_NOT_EXIST);

    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0300 end";
}

/**
 * @tc.name: ToolUtil_ValidateInputSchemaProperties_0400
 * @tc.desc: Test ValidateInputSchemaProperties with valid schema and no args
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, ValidateInputSchemaProperties_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0400 start";

    std::string schema = R"({"properties": {"help": {"type": "boolean"}}})";
    std::string subcommand = "";
    std::map<std::string, std::string> args;

    int32_t result = ToolUtil::ValidateInputSchemaProperties(schema, subcommand, args);

    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0400 end";
}

/**
 * @tc.name: ToolUtil_ValidateInputSchemaProperties_0500
 * @tc.desc: Test ValidateInputSchemaProperties with valid args
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, ValidateInputSchemaProperties_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0500 start";

    std::string schema = R"({
        "properties": {
            "help": {"type": "boolean"},
            "verbose": {"type": "boolean"}
        }
    })";
    std::string subcommand = "";
    std::map<std::string, std::string> args;
    args["help"] = "true";
    args["verbose"] = "false";

    int32_t result = ToolUtil::ValidateInputSchemaProperties(schema, subcommand, args);

    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0500 end";
}

/**
 * @tc.name: ToolUtil_ValidateInputSchemaProperties_0600
 * @tc.desc: Test ValidateInputSchemaProperties with invalid arg not in schema
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, ValidateInputSchemaProperties_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0600 start";

    std::string schema = R"({"properties": {"help": {"type": "boolean"}}})";
    std::string subcommand = "";
    std::map<std::string, std::string> args;
    args["invalid_arg"] = "value";

    int32_t result = ToolUtil::ValidateInputSchemaProperties(schema, subcommand, args);

    EXPECT_EQ(result, ERR_INVALID_PARAM);

    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0600 end";
}

/**
 * @tc.name: ToolUtil_ValidateInputSchemaProperties_0700
 * @tc.desc: Test ValidateInputSchemaProperties with valid subcommand
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, ValidateInputSchemaProperties_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0700 start";

    std::string schema = R"({
        "properties": {
            "build": {
                "type": "object",
                "description": "Build subcommand"
            },
            "clean": {
                "type": "object",
                "description": "Clean subcommand"
            }
        }
    })";
    std::string subcommand = "build";
    std::map<std::string, std::string> args;

    int32_t result = ToolUtil::ValidateInputSchemaProperties(schema, subcommand, args);

    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0700 end";
}

/**
 * @tc.name: ToolUtil_ValidateInputSchemaProperties_0800
 * @tc.desc: Test ValidateInputSchemaProperties with invalid subcommand
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, ValidateInputSchemaProperties_0800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0800 start";

    std::string schema = R"({
        "properties": {
            "build": {
                "type": "object",
                "description": "Build subcommand"
            }
        }
    })";
    std::string subcommand = "invalid_subcmd";
    std::map<std::string, std::string> args;

    int32_t result = ToolUtil::ValidateInputSchemaProperties(schema, subcommand, args);

    EXPECT_EQ(result, ERR_TOOL_NOT_EXIST);

    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0800 end";
}

/**
 * @tc.name: ToolUtil_ValidateInputSchemaProperties_0900
 * @tc.desc: Test ValidateInputSchemaProperties with subcommand and args
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, ValidateInputSchemaProperties_0900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0900 start";

    std::string schema = R"({
        "properties": {
            "build": {"type": "object"},
            "help": {"type": "boolean"}
        }
    })";
    std::string subcommand = "build";
    std::map<std::string, std::string> args;
    args["help"] = "true";

    int32_t result = ToolUtil::ValidateInputSchemaProperties(schema, subcommand, args);

    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_0900 end";
}

/**
 * @tc.name: ToolUtil_ValidateInputSchemaProperties_1000
 * @tc.desc: Test ValidateInputSchemaProperties with complex schema
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, ValidateInputSchemaProperties_1000, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_1000 start";

    std::string schema = R"({
        "properties": {
            "deploy": {
                "type": "object",
                "description": "Deploy subcommand"
            },
            "verbose": {"type": "boolean"},
            "output": {"type": "string"},
            "force": {"type": "boolean"}
        }
    })";
    std::string subcommand = "deploy";
    std::map<std::string, std::string> args;
    args["verbose"] = "true";
    args["output"] = "/tmp/deploy.log";

    int32_t result = ToolUtil::ValidateInputSchemaProperties(schema, subcommand, args);

    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_1000 end";
}

/**
 * @tc.name: ToolUtil_GenerateCliSessionId_0100
 * @tc.desc: Test GenerateCliSessionId with basic name
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, GenerateCliSessionId_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_0100 start";

    std::string name = "test_tool";
    std::string sessionId = ToolUtil::GenerateCliSessionId(name);

    EXPECT_FALSE(sessionId.empty());
    EXPECT_GE(sessionId.length(), name.length());

    // Check format: name_timestamp_random
    size_t firstUnderscore = sessionId.find('_');
    size_t lastUnderscore = sessionId.rfind('_');
    EXPECT_NE(firstUnderscore, std::string::npos);
    EXPECT_NE(lastUnderscore, std::string::npos);
    EXPECT_GT(lastUnderscore, firstUnderscore);

    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_0100 end";
}

/**
 * @tc.name: ToolUtil_GenerateCliSessionId_0200
 * @tc.desc: Test GenerateCliSessionId generates unique IDs
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, GenerateCliSessionId_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_0200 start";

    std::string name = "unique_tool";
    std::string sessionId1 = ToolUtil::GenerateCliSessionId(name);
    std::string sessionId2 = ToolUtil::GenerateCliSessionId(name);

    EXPECT_NE(sessionId1, sessionId2);

    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_0200 end";
}

/**
 * @tc.name: ToolUtil_GenerateCliSessionId_0300
 * @tc.desc: Test GenerateCliSessionId with empty name
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, GenerateCliSessionId_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_0300 start";

    std::string emptyName = "";
    std::string sessionId = ToolUtil::GenerateCliSessionId(emptyName);

    // Should still generate a valid ID with format _timestamp_random
    EXPECT_FALSE(sessionId.empty());
    EXPECT_GE(sessionId.length(), 2); // At least "_X"

    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_0300 end";
}

/**
 * @tc.name: ToolUtil_GenerateCliSessionId_0400
 * @tc.desc: Test GenerateCliSessionId with special characters in name
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, GenerateCliSessionId_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_0400 start";

    std::string name = "test-tool.special@name";
    std::string sessionId = ToolUtil::GenerateCliSessionId(name);

    EXPECT_FALSE(sessionId.empty());
    EXPECT_TRUE(sessionId.find(name) == 0); // Should start with the name

    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_0400 end";
}

/**
 * @tc.name: ToolUtil_GenerateCliSessionId_0500
 * @tc.desc: Test GenerateCliSessionId format consistency
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, GenerateCliSessionId_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_0500 start";

    std::string name = "formatTest";
    std::string sessionId = ToolUtil::GenerateCliSessionId(name);

    // Verify format: name_timestamp_random
    size_t firstUnderscore = sessionId.find('_');
    size_t lastUnderscore = sessionId.rfind('_');

    ASSERT_NE(firstUnderscore, std::string::npos);
    ASSERT_NE(lastUnderscore, std::string::npos);
    ASSERT_GT(lastUnderscore, firstUnderscore);

    std::string prefix = sessionId.substr(0, firstUnderscore);
    std::string middle = sessionId.substr(firstUnderscore + 1, lastUnderscore - firstUnderscore - 1);
    std::string suffix = sessionId.substr(lastUnderscore + 1);

    EXPECT_EQ(prefix, name);

    // Verify middle (timestamp) is numeric
    for (char c : middle) {
        EXPECT_TRUE(std::isdigit(c));
    }

    // Verify suffix (random) is numeric
    for (char c : suffix) {
        EXPECT_TRUE(std::isdigit(c));
    }

    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_0500 end";
}

/**
 * @tc.name: ToolUtil_GenerateCliSessionId_0600
 * @tc.desc: Test GenerateCliSessionId with very long name
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, GenerateCliSessionId_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_0600 start";

    std::string longName(1000, 'a'); // 1000 character name
    std::string sessionId = ToolUtil::GenerateCliSessionId(longName);

    EXPECT_FALSE(sessionId.empty());
    EXPECT_TRUE(sessionId.find(longName) == 0);

    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_0600 end";
}

/**
 * @tc.name: ToolUtil_GenerateSandboxConfig_0100
 * @tc.desc: Test GenerateSandboxConfig with challenge
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, GenerateSandboxConfig_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_GenerateSandboxConfig_0100 start";

    std::string challenge = "test_challenge_123";
    std::string sandboxConfig;

    bool result = ToolUtil::GenerateSandboxConfig(challenge, sandboxConfig);

    // In test environment, this will likely fail because we're not a HAP
    // Expected: return false, sandboxConfig may be empty or unchanged
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ToolUtil_GenerateSandboxConfig_0100 end";
}

/**
 * @tc.name: ToolUtil_ValidateInputSchemaProperties_EdgeCase_0100
 * @tc.desc: Test ValidateInputSchemaProperties with nested properties
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, ValidateInputSchemaProperties_EdgeCase_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_EdgeCase_0100 start";

    std::string schema = R"({
        "properties": {
            "option1": {
                "type": "object",
                "properties": {
                    "nested": {"type": "string"}
                }
            }
        }
    })";
    std::string subcommand = "";
    std::map<std::string, std::string> args;
    args["option1"] = "value";

    int32_t result = ToolUtil::ValidateInputSchemaProperties(schema, subcommand, args);

    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_EdgeCase_0100 end";
}

/**
 * @tc.name: ToolUtil_ValidateInputSchemaProperties_EdgeCase_0200
 * @tc.desc: Test ValidateInputSchemaProperties with properties as array (invalid)
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, ValidateInputSchemaProperties_EdgeCase_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_EdgeCase_0200 start";

    std::string schema = R"({"properties": ["item1", "item2"]})";
    std::string subcommand = "";
    std::map<std::string, std::string> args;

    int32_t result = ToolUtil::ValidateInputSchemaProperties(schema, subcommand, args);

    EXPECT_EQ(result, ERR_TOOL_NOT_EXIST);

    GTEST_LOG_(INFO) << "ToolUtil_ValidateInputSchemaProperties_EdgeCase_0200 end";
}

/**
 * @tc.name: ToolUtil_GenerateCliSessionId_EdgeCase_0100
 * @tc.desc: Test GenerateCliSessionId uniqueness in rapid succession
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, GenerateCliSessionId_EdgeCase_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_EdgeCase_0100 start";

    std::string name = "rapid_test";
    std::vector<std::string> sessionIds;

    // Generate multiple IDs rapidly
    for (int i = 0; i < 10; i++) {
        std::string sessionId = ToolUtil::GenerateCliSessionId(name);
        sessionIds.push_back(sessionId);
    }

    // All should be unique (at least very likely due to random component)
    std::unordered_set<std::string> uniqueIds(sessionIds.begin(), sessionIds.end());
    EXPECT_GE(uniqueIds.size(), 9); // Allow for potential collision but very unlikely

    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_EdgeCase_0100 end";
}

/**
 * @tc.name: ToolUtil_GenerateCliSessionId_EdgeCase_0200
 * @tc.desc: Test GenerateCliSessionId with underscore in name
 * @tc.type: FUNC
 */
HWTEST_F(ToolUtilTest, GenerateCliSessionId_EdgeCase_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_EdgeCase_0200 start";

    std::string name = "test_tool_name";
    std::string sessionId = ToolUtil::GenerateCliSessionId(name);

    EXPECT_FALSE(sessionId.empty());
    EXPECT_TRUE(sessionId.find(name) == 0);

    GTEST_LOG_(INFO) << "ToolUtil_GenerateCliSessionId_EdgeCase_0200 end";
}

} // namespace CliTool
} // namespace OHOS
