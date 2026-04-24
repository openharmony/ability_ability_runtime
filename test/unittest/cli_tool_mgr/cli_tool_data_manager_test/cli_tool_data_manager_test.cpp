/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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
#include <gtest/gtest-death-test.h>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

#include "cli_tool_data_manager.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace CliTool {

class CliToolDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static constexpr const char* TEST_JSON_FILE = "/data/test_cli_tools.json";
};

void CliToolDataManagerTest::SetUpTestCase()
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManagerTest::SetUpTestCase");

    // Create test JSON file
    std::ofstream file(TEST_JSON_FILE);
    file << R"([
        {
            "name": "test_tool1",
            "version": "1.0.0",
            "description": "Test tool 1",
            "executablePath": "/bin/test1",
            "requirePermissions": ["ohos.permission.INTERNET"],
            "inputSchema": {},
            "outputSchema": {},
            "argMapping": {"type": "flag", "separator": " "},
            "eventSchemas": {"stdout": {"type": "string"}},
            "timeout": 30000,
            "eventTypes": ["stdout", "stderr"],
            "hasSubCommand": false,
            "subcommands": {}
        },
        {
            "name": "test_tool2",
            "version": "2.0.0",
            "description": "Test tool 2",
            "executablePath": "/bin/test2",
            "requirePermissions": ["ohos.permission.READ_STORAGE"],
            "inputSchema": {},
            "outputSchema": {},
            "argMapping": {"type": "positional", "order": "arg1,arg2"},
            "eventSchemas": {"stdout": {"type": "string"}},
            "timeout": 60000,
            "eventTypes": ["exit"],
            "hasSubCommand": true,
            "subcommands": {
                "subcmd1": {
                    "description": "Subcommand 1",
                    "inputSchema": {},
                    "outputSchema": {}
                }
            }
        }
    ])";
    file.close();
}

void CliToolDataManagerTest::TearDownTestCase()
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManagerTest::TearDownTestCase");
    // Clean up test file
    std::remove(TEST_JSON_FILE);
}

void CliToolDataManagerTest::SetUp()
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManagerTest::SetUp");
}

void CliToolDataManagerTest::TearDown()
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManagerTest::TearDown");
}

/**
 * @tc.name: CliToolDataManager_ParseJsonFile_001
 * @tc.desc: Test parsing JSON file successfully
 * @tc.type: FUNC
 */
HWTEST_F(CliToolDataManagerTest, CliToolDataManager_ParseJsonFile_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManager_ParseJsonFile_001 start");

    auto& dataManager = CliToolDataManager::GetInstance();
    std::vector<ToolInfo> tools;
    int32_t ret = dataManager.ParseJsonFile(TEST_JSON_FILE, tools);

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(tools.size(), 2u);
    EXPECT_EQ(tools[0].name, "test_tool1");
    EXPECT_EQ(tools[1].name, "test_tool2");

    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManager_ParseJsonFile_001 end");
}

/**
 * @tc.name: CliToolDataManager_ParseJsonFile_002
 * @tc.desc: Test parsing non-existent JSON file
 * @tc.type: FUNC
 */
HWTEST_F(CliToolDataManagerTest, CliToolDataManager_ParseJsonFile_002, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManager_ParseJsonFile_002 start");

    auto& dataManager = CliToolDataManager::GetInstance();
    std::vector<ToolInfo> tools;
    int32_t ret = dataManager.ParseJsonFile("/nonexistent/file.json", tools);

    EXPECT_NE(ret, 0);
    EXPECT_EQ(tools.size(), 0u);

    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManager_ParseJsonFile_002 end");
}

/**
 * @tc.name: CliToolDataManager_JsonArrayToTools_001
 * @tc.desc: Test parsing JSON array to tools vector
 * @tc.type: FUNC
 */
HWTEST_F(CliToolDataManagerTest, CliToolDataManager_JsonArrayToTools_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManager_JsonArrayToTools_001 start");

    auto& dataManager = CliToolDataManager::GetInstance();
    std::string jsonStr = R"([
        {"name": "array_tool1", "version": "1.0", "description": "Array tool 1", "executablePath": "/bin/at1"},
        {"name": "array_tool2", "version": "2.0", "description": "Array tool 2", "executablePath": "/bin/at2"}
    ])";

    std::vector<ToolInfo> tools;
    int32_t ret = dataManager.JsonArrayToTools(jsonStr, tools);

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(tools.size(), 2u);
    EXPECT_EQ(tools[0].name, "array_tool1");
    EXPECT_EQ(tools[1].name, "array_tool2");

    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManager_JsonArrayToTools_001 end");
}

// ==================== ToolInfo ParseToJson Tests ====================

/**
 * @tc.name: ToolInfo_ParseToJson_001
 * @tc.desc: Test converting ToolInfo to JSON
 * @tc.type: FUNC
 */
HWTEST_F(CliToolDataManagerTest, ToolInfo_ParseToJson_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ToolInfo_ParseToJson_001 start");

    ToolInfo tool;
    tool.name = "test_tool";
    tool.version = "1.0.0";
    tool.description = "Test description";
    tool.executablePath = "/bin/test";
    tool.requirePermissions = {"ohos.permission.INTERNET"};
    tool.argMapping = std::make_shared<ArgMapping>();
    tool.argMapping->type = ArgMappingType::FLAG;
    tool.argMapping->separator = " ";
    tool.timeout = 30000;
    tool.hasSubCommand = false;

    nlohmann::json json = tool.ParseToJson();
    std::string jsonStr = json.dump();

    EXPECT_FALSE(jsonStr.empty());
    EXPECT_NE(jsonStr.find("test_tool"), std::string::npos);
    EXPECT_NE(jsonStr.find("1.0.0"), std::string::npos);

    TAG_LOGI(AAFwkTag::ABILITYMGR, "ToolInfo_ParseToJson_001 end");
}

/**
 * @tc.name: ToolInfo_ParseToJson_002
 * @tc.desc: Test converting ToolInfo with subcommands to JSON
 * @tc.type: FUNC
 */
HWTEST_F(CliToolDataManagerTest, ToolInfo_ParseToJson_002, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ToolInfo_ParseToJson_002 start");

    ToolInfo tool;
    tool.name = "tool_with_subcmds";
    tool.version = "2.0.0";
    tool.hasSubCommand = true;

    SubCommandInfo subCmd;
    subCmd.description = "Test subcommand";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    tool.subcommands["sub1"] = subCmd;

    nlohmann::json json = tool.ParseToJson();

    EXPECT_TRUE(json.contains("subcommands"));
    EXPECT_TRUE(json["subcommands"].contains("sub1"));

    TAG_LOGI(AAFwkTag::ABILITYMGR, "ToolInfo_ParseToJson_002 end");
}

// ==================== ToolInfo ParseFromJson Tests ====================

/**
 * @tc.name: ToolInfo_ParseFromJson_001
 * @tc.desc: Test parsing JSON to ToolInfo
 * @tc.type: FUNC
 */
HWTEST_F(CliToolDataManagerTest, ToolInfo_ParseFromJson_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ToolInfo_ParseFromJson_001 start");

    nlohmann::json json = R"({
        "name": "json_tool",
        "version": "1.0.0",
        "description": "JSON test tool",
        "executablePath": "/bin/jsontest",
        "requirePermissions": ["ohos.permission.INTERNET"],
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag", "separator": " "},
        "eventSchemas": {"stdout": {"type": "string"}},
        "timeout": 30000,
        "eventTypes": ["stdout"],
        "hasSubCommand": false,
        "subcommands": {}
    })"_json;

    ToolInfo tool = ToolInfo::ParseFromJson(json);

    EXPECT_EQ(tool.name, "json_tool");
    EXPECT_EQ(tool.version, "1.0.0");
    EXPECT_EQ(tool.description, "JSON test tool");
    EXPECT_EQ(tool.executablePath, "/bin/jsontest");
    EXPECT_EQ(tool.timeout, 30000);
    EXPECT_EQ(tool.hasSubCommand, false);
    EXPECT_TRUE(tool.argMapping != nullptr);
    EXPECT_EQ(tool.argMapping->type, ArgMappingType::FLAG);

    TAG_LOGI(AAFwkTag::ABILITYMGR, "ToolInfo_ParseFromJson_001 end");
}

/**
 * @tc.name: ToolInfo_ParseFromJson_002
 * @tc.desc: Test parsing JSON with subcommands to ToolInfo
 * @tc.type: FUNC
 */
HWTEST_F(CliToolDataManagerTest, ToolInfo_ParseFromJson_002, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ToolInfo_ParseFromJson_002 start");

    nlohmann::json json = R"({
        "name": "tool_with_subs",
        "version": "1.0.0",
        "description": "Tool with subcommands",
        "executablePath": "/bin/tool",
        "hasSubCommand": true,
        "subcommands": {
            "build": {
                "description": "Build subcommand",
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "string"}
            },
            "run": {
                "description": "Run subcommand"
            }
        }
    })"_json;

    ToolInfo tool = ToolInfo::ParseFromJson(json);

    EXPECT_EQ(tool.name, "tool_with_subs");
    EXPECT_TRUE(tool.hasSubCommand);
    EXPECT_EQ(tool.subcommands.size(), 2u);
    EXPECT_EQ(tool.subcommands["build"].description, "Build subcommand");

    TAG_LOGI(AAFwkTag::ABILITYMGR, "ToolInfo_ParseFromJson_002 end");
}

/**
 * @tc.name: ToolInfo_ParseFromJson_003
 * @tc.desc: Test parsing empty JSON to ToolInfo
 * @tc.type: FUNC
 */
HWTEST_F(CliToolDataManagerTest, ToolInfo_ParseFromJson_003, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ToolInfo_ParseFromJson_003 start");

    nlohmann::json json;

    ToolInfo tool = ToolInfo::ParseFromJson(json);

    EXPECT_TRUE(tool.name.empty());
    EXPECT_TRUE(tool.version.empty());
    EXPECT_EQ(tool.argMapping, nullptr);
    EXPECT_FALSE(tool.hasSubCommand);

    TAG_LOGI(AAFwkTag::ABILITYMGR, "ToolInfo_ParseFromJson_003 end");
}

// ==================== ToolInfo ParseFromJson/ParseToJson Round Trip Tests ====================

/**
 * @tc.name: ToolInfo_ParseFromJson_ParseToJson_RoundTrip_001
 * @tc.desc: Test ToolInfo ParseFromJson and ParseToJson round trip
 * @tc.type: FUNC
 */
HWTEST_F(CliToolDataManagerTest, ToolInfo_ParseFromJson_ParseToJson_RoundTrip_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ToolInfo_ParseFromJson_ParseToJson_RoundTrip_001 start");

    nlohmann::json originalJson = R"({
        "name": "roundtrip_tool",
        "version": "3.0.0",
        "description": "Round trip test",
        "executablePath": "/bin/roundtrip",
        "requirePermissions": ["ohos.permission.CAMERA"],
        "inputSchema": {"type": "object", "properties": {"input": {"type": "string"}}},
        "outputSchema": {"type": "array"},
        "argMapping": {"type": "positional", "order": "arg1,arg2"},
        "eventSchemas": {"exit": {"type": "number"}},
        "timeout": 60000,
        "eventTypes": ["stdout", "stderr", "exit"],
        "hasSubCommand": true,
        "subcommands": {
            "sub1": {
                "description": "Sub 1",
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "string"}
            }
        }
    })"_json;

    ToolInfo tool = ToolInfo::ParseFromJson(originalJson);
    nlohmann::json resultJson = tool.ParseToJson();

    EXPECT_EQ(resultJson["name"], originalJson["name"]);
    EXPECT_EQ(resultJson["version"], originalJson["version"]);
    EXPECT_EQ(resultJson["description"], originalJson["description"]);
    EXPECT_EQ(resultJson["executablePath"], originalJson["executablePath"]);
    EXPECT_EQ(resultJson["timeout"], originalJson["timeout"]);
    EXPECT_EQ(resultJson["hasSubCommand"], originalJson["hasSubCommand"]);
    EXPECT_EQ(resultJson["eventTypes"], originalJson["eventTypes"]);

    TAG_LOGI(AAFwkTag::ABILITYMGR, "ToolInfo_ParseFromJson_ParseToJson_RoundTrip_001 end");
}

} // namespace CliTool
} // namespace OHOS
