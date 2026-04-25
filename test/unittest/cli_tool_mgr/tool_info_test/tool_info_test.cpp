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
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>
#include <parcel.h>

#include "tool_info.h"

using namespace testing::ext;

namespace OHOS {
namespace CliTool {

class ToolInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ToolInfoTest::SetUpTestCase(void) {}
void ToolInfoTest::TearDownTestCase(void) {}
void ToolInfoTest::SetUp() {}
void ToolInfoTest::TearDown() {}

// ==================== ToolInfo Tests ====================

/**
 * @tc.name: ToolInfo_Marshalling_0100
 * @tc.desc: Test ToolInfo Marshalling with argMapping
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_Marshalling_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_Marshalling_0100 start";

    ToolInfo tool;
    tool.name = "test_tool";
    tool.version = "1.0.0";
    tool.description = "Test tool";
    tool.executablePath = "/bin/test";
    tool.requirePermissions = {"ohos.permission.INTERNET"};
    tool.inputSchema = "{}";
    tool.outputSchema = "{}";
    tool.argMapping = std::make_shared<ArgMapping>();
    tool.argMapping->type = ArgMappingType::FLAG;
    tool.eventSchemas = "{}";
    tool.timeout = 30000;
    tool.eventTypes = {"stdout"};
    tool.hasSubCommand = false;

    Parcel parcel;
    bool ret = tool.Marshalling(parcel);

    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "ToolInfo_Marshalling_0100 end";
}

/**
 * @tc.name: ToolInfo_Marshalling_0200
 * @tc.desc: Test ToolInfo Marshalling without argMapping
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_Marshalling_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_Marshalling_0200 start";

    ToolInfo tool;
    tool.name = "test_tool_no_arg";
    tool.version = "2.0.0";
    tool.description = "Tool without argMapping";
    tool.executablePath = "/bin/test2";
    tool.requirePermissions = {};
    tool.inputSchema = "{}";
    tool.outputSchema = "{}";
    tool.argMapping = nullptr;
    tool.eventSchemas = "{}";
    tool.timeout = 0;
    tool.eventTypes = {};
    tool.hasSubCommand = true;
    SubCommandInfo subCmd;
    subCmd.description = "sub1";
    tool.subcommands["sub1"] = subCmd;

    Parcel parcel;
    bool ret = tool.Marshalling(parcel);

    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "ToolInfo_Marshalling_0200 end";
}

/**
 * @tc.name: ToolInfo_Unmarshalling_0100
 * @tc.desc: Test ToolInfo Unmarshalling with argMapping
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_Unmarshalling_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_Unmarshalling_0100 start";

    ToolInfo original;
    original.name = "original_tool";
    original.version = "3.0.0";
    original.description = "Original tool description";
    original.executablePath = "/usr/bin/original";
    original.requirePermissions = {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"};
    original.inputSchema = R"({"type": "object", "properties": {"input": {"type": "string"}}})";
    original.outputSchema = R"({"type": "string"})";
    original.argMapping = std::make_shared<ArgMapping>();
    original.argMapping->type = ArgMappingType::POSITIONAL;
    original.argMapping->separator = "";
    original.argMapping->order = "arg1,arg2,arg3";
    original.argMapping->templates = "{}";
    original.eventSchemas = "{}";
    original.timeout = 60000;
    original.eventTypes = {"stdout", "stderr", "exit"};
    original.hasSubCommand = true;
    SubCommandInfo buildSubCmd;
    buildSubCmd.description = "Build subcommand";
    original.subcommands["build"] = buildSubCmd;

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    ToolInfo *result = ToolInfo::Unmarshalling(parcel);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->name, "original_tool");
    EXPECT_EQ(result->version, "3.0.0");
    EXPECT_EQ(result->requirePermissions.size(), 2u);
    EXPECT_TRUE(result->argMapping != nullptr);
    EXPECT_EQ(result->argMapping->type, ArgMappingType::POSITIONAL);
    EXPECT_EQ(result->timeout, 60000);
    EXPECT_TRUE(result->hasSubCommand);
    EXPECT_EQ(result->subcommands.size(), 1u);

    delete result;

    GTEST_LOG_(INFO) << "ToolInfo_Unmarshalling_0100 end";
}

/**
 * @tc.name: ToolInfo_Unmarshalling_0200
 * @tc.desc: Test ToolInfo Unmarshalling without argMapping
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_Unmarshalling_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_Unmarshalling_0200 start";

    ToolInfo original;
    original.name = "simple_tool";
    original.version = "1.0.0";
    original.description = "Simple tool";
    original.executablePath = "/bin/simple";
    original.requirePermissions = {};
    original.inputSchema = "{}";
    original.outputSchema = "{}";
    original.argMapping = nullptr;
    original.eventSchemas = "{}";
    original.timeout = 0;
    original.eventTypes = {};
    original.hasSubCommand = false;

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    ToolInfo *result = ToolInfo::Unmarshalling(parcel);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->name, "simple_tool");
    EXPECT_TRUE(result->argMapping == nullptr);
    EXPECT_FALSE(result->hasSubCommand);

    delete result;

    GTEST_LOG_(INFO) << "ToolInfo_Unmarshalling_0200 end";
}

/**
 * @tc.name: ToolInfo_Unmarshalling_0300
 * @tc.desc: Test ToolInfo Unmarshalling fail with empty parcel
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_Unmarshalling_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_Unmarshalling_0300 start";

    Parcel parcel;
    ToolInfo *result = ToolInfo::Unmarshalling(parcel);

    EXPECT_EQ(result, nullptr);

    GTEST_LOG_(INFO) << "ToolInfo_Unmarshalling_0300 end";
}

// ==================== ToolsRawData Tests ====================

/**
 * @tc.name: ToolsRawData_Marshalling_0100
 * @tc.desc: Test ToolsRawData Marshalling success
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolsRawData_Marshalling_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolsRawData_Marshalling_0100 start";

    ToolsRawData rawData;
    rawData.data = {1, 2, 3, 4, 5};

    Parcel parcel;
    bool ret = rawData.Marshalling(parcel);

    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "ToolsRawData_Marshalling_0100 end";
}

/**
 * @tc.name: ToolsRawData_Marshalling_0200
 * @tc.desc: Test ToolsRawData Marshalling with empty data
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolsRawData_Marshalling_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolsRawData_Marshalling_0200 start";

    ToolsRawData rawData;
    rawData.data = {};

    Parcel parcel;
    bool ret = rawData.Marshalling(parcel);

    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "ToolsRawData_Marshalling_0200 end";
}

/**
 * @tc.name: ToolsRawData_Unmarshalling_0100
 * @tc.desc: Test ToolsRawData Unmarshalling success
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolsRawData_Unmarshalling_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolsRawData_Unmarshalling_0100 start";

    ToolsRawData original;
    original.data = {10, 20, 30, 40, 50, 60};

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    ToolsRawData *result = ToolsRawData::Unmarshalling(parcel);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->data.size(), 6u);
    EXPECT_EQ(result->data[0], 10u);
    EXPECT_EQ(result->data[5], 60u);

    delete result;

    GTEST_LOG_(INFO) << "ToolsRawData_Unmarshalling_0100 end";
}

/**
 * @tc.name: ToolsRawData_Unmarshalling_0200
 * @tc.desc: Test ToolsRawData Unmarshalling with empty data
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolsRawData_Unmarshalling_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolsRawData_Unmarshalling_0200 start";

    ToolsRawData original;
    original.data = {};

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    ToolsRawData *result = ToolsRawData::Unmarshalling(parcel);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->data.size(), 0u);

    delete result;

    GTEST_LOG_(INFO) << "ToolsRawData_Unmarshalling_0200 end";
}

// ==================== ToolInfo ParseToJson Tests ====================

/**
 * @tc.name: ToolInfo_ParseToJson_0100
 * @tc.desc: Test ToolInfo ParseToJson with full data
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseToJson_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0100 start";

    ToolInfo tool;
    tool.name = "json_tool";
    tool.version = "1.0.0";
    tool.description = "JSON test tool";
    tool.executablePath = "/bin/json";
    tool.requirePermissions = {"ohos.permission.INTERNET"};
    tool.inputSchema = R"({"type": "object"})";
    tool.outputSchema = R"({"type": "string"})";
    tool.argMapping = std::make_shared<ArgMapping>();
    tool.argMapping->type = ArgMappingType::FLAG;
    tool.eventSchemas = R"({"stdout": {"type": "string"}})";
    tool.timeout = 30000;
    tool.eventTypes = {"stdout", "stderr"};
    tool.hasSubCommand = false;

    nlohmann::json json = tool.ParseToJson();

    EXPECT_EQ(json["name"], "json_tool");
    EXPECT_EQ(json["version"], "1.0.0");
    EXPECT_EQ(json["description"], "JSON test tool");
    EXPECT_EQ(json["executablePath"], "/bin/json");
    EXPECT_EQ(json["timeout"], 30000);
    EXPECT_TRUE(json.contains("argMapping"));

    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0100 end";
}

/**
 * @tc.name: ToolInfo_ParseToJson_0200
 * @tc.desc: Test ToolInfo ParseToJson without argMapping
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseToJson_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0200 start";

    ToolInfo tool;
    tool.name = "no_arg_tool";
    tool.argMapping = nullptr;

    nlohmann::json json = tool.ParseToJson();

    EXPECT_EQ(json["name"], "no_arg_tool");
    EXPECT_FALSE(json.contains("argMapping"));

    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0200 end";
}

/**
 * @tc.name: ToolInfo_ParseToJson_0300
 * @tc.desc: Test ToolInfo ParseToJson with subcommands
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseToJson_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0300 start";

    ToolInfo tool;
    tool.name = "tool_with_subs";
    tool.hasSubCommand = true;

    SubCommandInfo subCmd;
    subCmd.description = "Test subcommand";
    subCmd.inputSchema = R"({"type": "object"})";
    tool.subcommands["sub1"] = subCmd;

    nlohmann::json json = tool.ParseToJson();

    EXPECT_TRUE(json.contains("subcommands"));
    EXPECT_TRUE(json["subcommands"].contains("sub1"));
    EXPECT_EQ(json["subcommands"]["sub1"]["description"], "Test subcommand");

    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0300 end";
}

// ==================== ToolInfo ParseFromJson Tests ====================

/**
 * @tc.name: ToolInfo_ParseFromJson_0100
 * @tc.desc: Test ToolInfo ParseFromJson with full data
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_0100 start";

    nlohmann::json json = R"({
        "name": "parsed_tool",
        "version": "2.0.0",
        "description": "Parsed from JSON",
        "executablePath": "/bin/parsed",
        "requirePermissions": ["ohos.permission.CAMERA"],
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "array"},
        "argMapping": {"type": "positional", "order": "arg1,arg2"},
        "eventSchemas": {"exit": {"type": "number"}},
        "timeout": 60000,
        "eventTypes": ["stdout", "exit"],
        "hasSubCommand": false
    })"_json;

    ToolInfo tool = ToolInfo::ParseFromJson(json);

    EXPECT_EQ(tool.name, "parsed_tool");
    EXPECT_EQ(tool.version, "2.0.0");
    EXPECT_EQ(tool.description, "Parsed from JSON");
    EXPECT_EQ(tool.executablePath, "/bin/parsed");
    EXPECT_EQ(tool.requirePermissions.size(), 1u);
    EXPECT_EQ(tool.timeout, 60000);
    EXPECT_FALSE(tool.hasSubCommand);
    ASSERT_NE(tool.argMapping, nullptr);
    EXPECT_EQ(tool.argMapping->type, ArgMappingType::POSITIONAL);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_0100 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_0200
 * @tc.desc: Test ToolInfo ParseFromJson with subcommands
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_0200 start";

    nlohmann::json json = R"({
        "name": "tool_with_subcommands",
        "version": "1.0.0",
        "hasSubCommand": true,
        "subcommands": {
            "build": {
                "description": "Build the project",
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "string"}
            },
            "run": {
                "description": "Run the project"
            }
        }
    })"_json;

    ToolInfo tool = ToolInfo::ParseFromJson(json);

    EXPECT_EQ(tool.name, "tool_with_subcommands");
    EXPECT_TRUE(tool.hasSubCommand);
    EXPECT_EQ(tool.subcommands.size(), 2u);
    EXPECT_EQ(tool.subcommands["build"].description, "Build the project");

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_0200 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_0300
 * @tc.desc: Test ToolInfo ParseFromJson with empty JSON
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_0300 start";

    nlohmann::json json;

    ToolInfo tool = ToolInfo::ParseFromJson(json);

    EXPECT_TRUE(tool.name.empty());
    EXPECT_TRUE(tool.version.empty());
    EXPECT_EQ(tool.argMapping, nullptr);
    EXPECT_FALSE(tool.hasSubCommand);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_0300 end";
}

// ==================== ToolInfo ParseFromJson/ParseToJson Round Trip Tests ====================

/**
 * @tc.name: ToolInfo_ParseFromJson_ParseToJson_RoundTrip_0100
 * @tc.desc: Test ToolInfo ParseFromJson and ParseToJson round trip
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_ParseToJson_RoundTrip_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_ParseToJson_RoundTrip_0100 start";

    nlohmann::json originalJson = R"({
        "name": "roundtrip_tool",
        "version": "3.0.0",
        "description": "Round trip test",
        "executablePath": "/bin/roundtrip",
        "requirePermissions": ["ohos.permission.INTERNET", "ohos.permission.CAMERA"],
        "inputSchema": {"type": "object", "properties": {"input": {"type": "string"}}},
        "outputSchema": {"type": "array"},
        "argMapping": {"type": "mixed", "separator": ",", "order": "a,b"},
        "eventSchemas": {"stdout": {"type": "string"}},
        "timeout": 45000,
        "eventTypes": ["stdout", "stderr"],
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

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_ParseToJson_RoundTrip_0100 end";
}

} // namespace CliTool
} // namespace OHOS