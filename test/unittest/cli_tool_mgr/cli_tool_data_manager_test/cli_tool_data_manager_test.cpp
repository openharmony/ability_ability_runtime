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
#include <gtest/gtest-death-test.h>
#include <fstream>
#include <iostream>

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
            "inputSchema": "{}",
            "outputSchema": "{}",
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
            "inputSchema": "{}",
            "outputSchema": "{}",
            "argMapping": {"type": "positional", "order": "arg1,arg2"},
            "eventSchemas": {"stdout": {"type": "string"}},
            "timeout": 60000,
            "eventTypes": ["exit"],
            "hasSubCommand": true,
            "subcommands": {
                "subcmd1": {
                    "description": "Subcommand 1",
                    "inputSchema": "{}",
                    "outputSchema": "{}"
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
 * @tc.name: CliToolDataManager_ToolInfoToJson_001
 * @tc.desc: Test converting ToolInfo to JSON string
 * @tc.type: FUNC
 */
HWTEST_F(CliToolDataManagerTest, CliToolDataManager_ToolInfoToJson_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManager_ToolInfoToJson_001 start");

    auto& dataManager = CliToolDataManager::GetInstance();
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

    std::string jsonStr = dataManager.ToolInfoToJson(tool);

    EXPECT_FALSE(jsonStr.empty());
    EXPECT_NE(jsonStr.find("test_tool"), std::string::npos);
    EXPECT_NE(jsonStr.find("1.0.0"), std::string::npos);

    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManager_ToolInfoToJson_001 end");
}

/**
 * @tc.name: CliToolDataManager_JsonToToolInfo_001
 * @tc.desc: Test parsing JSON string to ToolInfo
 * @tc.type: FUNC
 */
HWTEST_F(CliToolDataManagerTest, CliToolDataManager_JsonToToolInfo_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManager_JsonToToolInfo_001 start");

    auto& dataManager = CliToolDataManager::GetInstance();
    std::string jsonStr = R"({
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
    })";

    ToolInfo tool;
    int32_t ret = dataManager.JsonToToolInfo(jsonStr, tool);

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(tool.name, "json_tool");
    EXPECT_EQ(tool.version, "1.0.0");
    EXPECT_EQ(tool.description, "JSON test tool");
    EXPECT_EQ(tool.executablePath, "/bin/jsontest");
    EXPECT_EQ(tool.timeout, 30000);
    EXPECT_EQ(tool.hasSubCommand, false);
    EXPECT_TRUE(tool.argMapping != nullptr);
    EXPECT_EQ(tool.argMapping->type, ArgMappingType::FLAG);

    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManager_JsonToToolInfo_001 end");
}

/**
 * @tc.name: CliToolDataManager_JsonToToolInfo_002
 * @tc.desc: Test parsing invalid JSON string
 * @tc.type: FUNC
 */
HWTEST_F(CliToolDataManagerTest, CliToolDataManager_JsonToToolInfo_002, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManager_JsonToToolInfo_002 start");

    auto& dataManager = CliToolDataManager::GetInstance();
    std::string invalidJson = "invalid json {";

    ToolInfo tool;
    int32_t ret = dataManager.JsonToToolInfo(invalidJson, tool);

    EXPECT_NE(ret, 0);

    TAG_LOGI(AAFwkTag::ABILITYMGR, "CliToolDataManager_JsonToToolInfo_002 end");
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
} // namespace CliTool
} // namespace OHOS
