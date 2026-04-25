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

/**
 * @tc.name: ToolInfo_Unmarshalling_0400
 * @tc.desc: Test ToolInfo Unmarshalling with full subcommands data
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_Unmarshalling_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_Unmarshalling_0400 start";

    ToolInfo original;
    original.name = "tool_with_full_subcommands";
    original.version = "1.0.0";
    original.description = "Tool with full subcommands";
    original.executablePath = "/bin/tool";
    original.hasSubCommand = true;

    SubCommandInfo subCmd;
    subCmd.description = "Full subcommand";
    subCmd.requirePermissions = {"ohos.permission.INTERNET"};
    subCmd.inputSchema = R"({"type": "object", "properties": {"arg": {"type": "string"}}})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();
    subCmd.argMapping->type = ArgMappingType::MIXED;
    subCmd.argMapping->separator = ",";
    subCmd.argMapping->order = "arg1,arg2";
    subCmd.argMapping->templates = R"({"arg1": "--input=${value}"})";
    subCmd.eventTypes = {"stdout", "stderr"};
    subCmd.eventSchemas = R"({"stdout": {"type": "string"}})";

    original.subcommands["run"] = subCmd;

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    ToolInfo *result = ToolInfo::Unmarshalling(parcel);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->name, "tool_with_full_subcommands");
    EXPECT_TRUE(result->hasSubCommand);
    EXPECT_EQ(result->subcommands.size(), 1u);
    EXPECT_TRUE(result->subcommands.contains("run"));

    const auto &resultSubCmd = result->subcommands["run"];
    EXPECT_EQ(resultSubCmd.description, "Full subcommand");
    EXPECT_EQ(resultSubCmd.requirePermissions.size(), 1u);
    EXPECT_EQ(resultSubCmd.requirePermissions[0], "ohos.permission.INTERNET");
    EXPECT_EQ(resultSubCmd.inputSchema, R"({"type": "object", "properties": {"arg": {"type": "string"}}})");
    EXPECT_EQ(resultSubCmd.outputSchema, R"({"type": "string"})");
    ASSERT_NE(resultSubCmd.argMapping, nullptr);
    EXPECT_EQ(resultSubCmd.argMapping->type, ArgMappingType::MIXED);
    EXPECT_EQ(resultSubCmd.argMapping->separator, ",");
    EXPECT_EQ(resultSubCmd.argMapping->order, "arg1,arg2");
    EXPECT_EQ(resultSubCmd.argMapping->templates, R"({"arg1": "--input=${value}"})");
    EXPECT_EQ(resultSubCmd.eventTypes.size(), 2u);
    EXPECT_EQ(resultSubCmd.eventSchemas, R"({"stdout": {"type": "string"}})");

    delete result;

    GTEST_LOG_(INFO) << "ToolInfo_Unmarshalling_0400 end";
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
        "name": "ohos-parsed_tool",
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

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_TRUE(result);
    EXPECT_EQ(tool.name, "ohos-parsed_tool");
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
        "name": "hms-tool_with_sub",
        "version": "1.0.0",
        "description": "Tool with subcommands",
        "executablePath": "/bin/tool",
        "hasSubCommand": true,
        "subcommands": {
            "build": {
                "description": "Build the project",
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "string"},
                "argMapping": {"type": "flag"}
            },
            "run": {
                "description": "Run the project",
                "argMapping": {"type": "positional", "order": "arg1"}
            }
        }
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_TRUE(result);
    EXPECT_EQ(tool.name, "hms-tool_with_sub");
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

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);
    EXPECT_TRUE(tool.name.empty());

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
        "name": "ohos-roundtrip_tool",
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
                "outputSchema": {"type": "string"},
                "argMapping": {"type": "flag"}
            }
        }
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(originalJson, tool);
    EXPECT_TRUE(result);
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

/**
 * @tc.name: ToolInfo_ParseToJson_0400
 * @tc.desc: Test ToolInfo ParseToJson with invalid inputSchema JSON string
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseToJson_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0400 start";

    ToolInfo tool;
    tool.name = "invalid_input_schema";
    tool.description = "Invalid inputSchema test";
    tool.inputSchema = "not a valid json";
    tool.outputSchema = R"({"type": "string"})";
    tool.eventSchemas = R"({"stdout": {"type": "string"}})";

    nlohmann::json json = tool.ParseToJson();

    EXPECT_EQ(json["name"], "invalid_input_schema");
    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_EQ(json["inputSchema"], "not a valid json");
    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_TRUE(json.contains("eventSchemas"));

    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0400 end";
}

/**
 * @tc.name: ToolInfo_ParseToJson_0500
 * @tc.desc: Test ToolInfo ParseToJson with invalid outputSchema JSON string
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseToJson_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0500 start";

    ToolInfo tool;
    tool.name = "invalid_output_schema";
    tool.description = "Invalid outputSchema test";
    tool.inputSchema = R"({"type": "object"})";
    tool.outputSchema = "{broken json}";
    tool.eventSchemas = "{}";

    nlohmann::json json = tool.ParseToJson();

    EXPECT_EQ(json["name"], "invalid_output_schema");
    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_EQ(json["outputSchema"], "{broken json}");

    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0500 end";
}

/**
 * @tc.name: ToolInfo_ParseToJson_0600
 * @tc.desc: Test ToolInfo ParseToJson with invalid eventSchemas JSON string
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseToJson_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0600 start";

    ToolInfo tool;
    tool.name = "invalid_event_schemas";
    tool.description = "Invalid eventSchemas test";
    tool.inputSchema = R"({"type": "object"})";
    tool.outputSchema = R"({"type": "string"})";
    tool.eventSchemas = "invalid event schemas";

    nlohmann::json json = tool.ParseToJson();

    EXPECT_EQ(json["name"], "invalid_event_schemas");
    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_TRUE(json.contains("eventSchemas"));
    EXPECT_EQ(json["eventSchemas"], "invalid event schemas");

    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0600 end";
}

/**
 * @tc.name: ToolInfo_ParseToJson_0700
 * @tc.desc: Test ToolInfo ParseToJson with complex valid schemas
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseToJson_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0700 start";

    ToolInfo tool;
    tool.name = "complex_schemas";
    tool.description = "Complex schema test";
    tool.inputSchema = R"({
        "type": "object",
        "properties": {
            "command": {"type": "string", "enum": ["start", "stop", "restart"]},
            "options": {
                "type": "array",
                "items": {"type": "string"}
            },
            "config": {
                "type": "object",
                "properties": {
                    "debug": {"type": "boolean"},
                    "verbose": {"type": "boolean"}
                }
            }
        },
        "required": ["command"]
    })";
    tool.outputSchema = R"({
        "type": "object",
        "properties": {
            "success": {"type": "boolean"},
            "message": {"type": "string"},
            "data": {"type": "array", "items": {"type": "object"}}
        }
    })";
    tool.eventSchemas = R"({
        "stdout": {"type": "string", "description": "Standard output"},
        "stderr": {"type": "string", "description": "Standard error"},
        "exit": {"type": "number", "description": "Exit code"},
        "progress": {"type": "object", "properties": {"percent": {"type": "number"}}}
    })";

    nlohmann::json json = tool.ParseToJson();

    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_TRUE(json["inputSchema"].is_object());
    EXPECT_TRUE(json["inputSchema"].contains("properties"));
    EXPECT_TRUE(json["inputSchema"]["properties"].contains("command"));
    EXPECT_TRUE(json["inputSchema"]["properties"]["command"].contains("enum"));

    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_TRUE(json["outputSchema"].is_object());
    EXPECT_TRUE(json["outputSchema"]["properties"].contains("success"));

    EXPECT_TRUE(json.contains("eventSchemas"));
    EXPECT_TRUE(json["eventSchemas"].is_object());
    EXPECT_TRUE(json["eventSchemas"].contains("stdout"));
    EXPECT_TRUE(json["eventSchemas"].contains("progress"));

    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0700 end";
}

/**
 * @tc.name: ToolInfo_ParseToJson_0800
 * @tc.desc: Test ToolInfo ParseToJson with all invalid schemas
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseToJson_0800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0800 start";

    ToolInfo tool;
    tool.name = "all_invalid_schemas";
    tool.description = "All invalid schemas test";
    tool.inputSchema = "invalid input";
    tool.outputSchema = "invalid output";
    tool.eventSchemas = "invalid events";

    nlohmann::json json = tool.ParseToJson();

    EXPECT_EQ(json["name"], "all_invalid_schemas");
    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_EQ(json["inputSchema"], "invalid input");
    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_EQ(json["outputSchema"], "invalid output");
    EXPECT_TRUE(json.contains("eventSchemas"));
    EXPECT_EQ(json["eventSchemas"], "invalid events");

    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0800 end";
}

/**
 * @tc.name: ToolInfo_ParseToJson_0900
 * @tc.desc: Test ToolInfo ParseToJson with empty inputSchema
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseToJson_0900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0900 start";

    ToolInfo tool;
    tool.name = "empty_input_schema";
    tool.description = "Empty inputSchema test";
    tool.inputSchema = "";
    tool.outputSchema = R"({"type": "string"})";
    tool.eventSchemas = "{}";

    nlohmann::json json = tool.ParseToJson();

    EXPECT_EQ(json["name"], "empty_input_schema");
    EXPECT_FALSE(json.contains("inputSchema"));
    EXPECT_TRUE(json.contains("outputSchema"));

    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_0900 end";
}

/**
 * @tc.name: ToolInfo_ParseToJson_1000
 * @tc.desc: Test ToolInfo ParseToJson with empty outputSchema
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseToJson_1000, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_1000 start";

    ToolInfo tool;
    tool.name = "empty_output_schema";
    tool.description = "Empty outputSchema test";
    tool.inputSchema = R"({"type": "object"})";
    tool.outputSchema = "";
    tool.eventSchemas = "{}";

    nlohmann::json json = tool.ParseToJson();

    EXPECT_EQ(json["name"], "empty_output_schema");
    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_FALSE(json.contains("outputSchema"));

    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_1000 end";
}

/**
 * @tc.name: ToolInfo_ParseToJson_1100
 * @tc.desc: Test ToolInfo ParseToJson with empty eventSchemas
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseToJson_1100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_1100 start";

    ToolInfo tool;
    tool.name = "empty_event_schemas";
    tool.description = "Empty eventSchemas test";
    tool.inputSchema = R"({"type": "object"})";
    tool.outputSchema = R"({"type": "string"})";
    tool.eventSchemas = "";

    nlohmann::json json = tool.ParseToJson();

    EXPECT_EQ(json["name"], "empty_event_schemas");
    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_FALSE(json.contains("eventSchemas"));

    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_1100 end";
}

/**
 * @tc.name: ToolInfo_ParseToJson_1200
 * @tc.desc: Test ToolInfo ParseToJson with subcommands containing schemas
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseToJson_1200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_1200 start";

    ToolInfo tool;
    tool.name = "tool_with_subcmd_schemas";
    tool.hasSubCommand = true;

    SubCommandInfo subCmd1;
    subCmd1.description = "Subcommand with valid schemas";
    subCmd1.inputSchema = R"({"type": "object", "properties": {"arg": {"type": "string"}}})";
    subCmd1.outputSchema = R"({"type": "number"})";
    subCmd1.eventSchemas = R"({"result": {"type": "string"}})";

    SubCommandInfo subCmd2;
    subCmd2.description = "Subcommand with invalid schemas";
    subCmd2.inputSchema = "invalid";
    subCmd2.outputSchema = "also invalid";
    subCmd2.eventSchemas = "invalid too";

    tool.subcommands["valid"] = subCmd1;
    tool.subcommands["invalid"] = subCmd2;

    nlohmann::json json = tool.ParseToJson();

    EXPECT_TRUE(json.contains("subcommands"));
    EXPECT_TRUE(json["subcommands"].contains("valid"));
    EXPECT_TRUE(json["subcommands"].contains("invalid"));

    EXPECT_TRUE(json["subcommands"]["valid"].contains("inputSchema"));
    EXPECT_TRUE(json["subcommands"]["valid"]["inputSchema"].is_object());
    EXPECT_TRUE(json["subcommands"]["valid"].contains("outputSchema"));
    EXPECT_TRUE(json["subcommands"]["valid"].contains("eventSchemas"));

    EXPECT_TRUE(json["subcommands"]["invalid"].contains("inputSchema"));
    EXPECT_EQ(json["subcommands"]["invalid"]["inputSchema"], "invalid");
    EXPECT_TRUE(json["subcommands"]["invalid"].contains("outputSchema"));
    EXPECT_EQ(json["subcommands"]["invalid"]["outputSchema"], "also invalid");
    EXPECT_TRUE(json["subcommands"]["invalid"].contains("eventSchemas"));
    EXPECT_EQ(json["subcommands"]["invalid"]["eventSchemas"], "invalid too");

    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_1200 end";
}

/**
 * @tc.name: ToolInfo_ParseToJson_1300
 * @tc.desc: Test ToolInfo ParseToJson with primitive type schemas
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseToJson_1300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_1300 start";

    ToolInfo tool;
    tool.name = "primitive_schemas";
    tool.description = "Primitive type schema test";
    tool.inputSchema = R"({"type": "string", "minLength": 1, "maxLength": 100})";
    tool.outputSchema = R"({"type": "number", "minimum": 0, "maximum": 100})";
    tool.eventSchemas = R"({"status": {"type": "boolean"}})";

    nlohmann::json json = tool.ParseToJson();

    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_EQ(json["inputSchema"]["type"], "string");
    EXPECT_TRUE(json["inputSchema"].contains("minLength"));

    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_EQ(json["outputSchema"]["type"], "number");
    EXPECT_TRUE(json["outputSchema"].contains("minimum"));

    EXPECT_TRUE(json.contains("eventSchemas"));
    EXPECT_EQ(json["eventSchemas"]["status"]["type"], "boolean");

    GTEST_LOG_(INFO) << "ToolInfo_ParseToJson_1300 end";
}

// ==================== ValidateName Tests ====================

/**
 * @tc.name: ToolInfo_ValidateName_0100
 * @tc.desc: Test ToolInfo ValidateName with valid ohos- prefix
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ValidateName_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ValidateName_0100 start";

    EXPECT_TRUE(ToolInfo::ValidateName("ohos-ls"));
    EXPECT_TRUE(ToolInfo::ValidateName("ohos-test"));
    EXPECT_TRUE(ToolInfo::ValidateName("ohos-abc"));
    EXPECT_TRUE(ToolInfo::ValidateName("ohos-1234567890123456"));  // 16 chars suffix

    GTEST_LOG_(INFO) << "ToolInfo_ValidateName_0100 end";
}

/**
 * @tc.name: ToolInfo_ValidateName_0200
 * @tc.desc: Test ToolInfo ValidateName with valid hms- prefix
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ValidateName_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ValidateName_0200 start";

    EXPECT_TRUE(ToolInfo::ValidateName("hms-ls"));
    EXPECT_TRUE(ToolInfo::ValidateName("hms-test"));
    EXPECT_TRUE(ToolInfo::ValidateName("hms-abc"));
    EXPECT_TRUE(ToolInfo::ValidateName("hms-1234567890123456"));  // 16 chars suffix

    GTEST_LOG_(INFO) << "ToolInfo_ValidateName_0200 end";
}

/**
 * @tc.name: ToolInfo_ValidateName_0300
 * @tc.desc: Test ToolInfo ValidateName with invalid prefix
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ValidateName_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ValidateName_0300 start";

    EXPECT_FALSE(ToolInfo::ValidateName("ls"));  // no prefix
    EXPECT_FALSE(ToolInfo::ValidateName("test-tool"));  // wrong prefix
    EXPECT_FALSE(ToolInfo::ValidateName("OHOS-ls"));  // uppercase prefix
    EXPECT_FALSE(ToolInfo::ValidateName("HMS-ls"));  // uppercase prefix
    EXPECT_FALSE(ToolInfo::ValidateName("ohos_ls"));  // underscore instead of dash
    EXPECT_FALSE(ToolInfo::ValidateName("hms_ls"));  // underscore instead of dash
    EXPECT_FALSE(ToolInfo::ValidateName("ohos"));  // no suffix
    EXPECT_FALSE(ToolInfo::ValidateName("hms"));  // no suffix

    GTEST_LOG_(INFO) << "ToolInfo_ValidateName_0300 end";
}

/**
 * @tc.name: ToolInfo_ValidateName_0400
 * @tc.desc: Test ToolInfo ValidateName with suffix exceeding 16 chars
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ValidateName_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ValidateName_0400 start";

    EXPECT_FALSE(ToolInfo::ValidateName("ohos-12345678901234567"));  // 17 chars suffix
    EXPECT_FALSE(ToolInfo::ValidateName("hms-abcdefghijklmnopq"));  // 17 chars suffix
    EXPECT_FALSE(ToolInfo::ValidateName("ohos-thisisaverylongname"));  // long suffix

    GTEST_LOG_(INFO) << "ToolInfo_ValidateName_0400 end";
}

/**
 * @tc.name: ToolInfo_ValidateName_0500
 * @tc.desc: Test ToolInfo ValidateName with empty name
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ValidateName_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ValidateName_0500 start";

    EXPECT_FALSE(ToolInfo::ValidateName(""));
    EXPECT_FALSE(ToolInfo::ValidateName("ohos-"));  // empty suffix
    EXPECT_FALSE(ToolInfo::ValidateName("hms-"));  // empty suffix

    GTEST_LOG_(INFO) << "ToolInfo_ValidateName_0500 end";
}

/**
 * @tc.name: ToolInfo_ValidateName_0600
 * @tc.desc: Test ToolInfo ValidateName with edge cases
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ValidateName_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ValidateName_0600 start";

    // Valid edge cases
    EXPECT_TRUE(ToolInfo::ValidateName("ohos-a"));  // 1 char suffix
    EXPECT_TRUE(ToolInfo::ValidateName("hms-x"));  // 1 char suffix
    EXPECT_TRUE(ToolInfo::ValidateName("ohos-1234567890abcdef"));  // exactly 16 chars
    EXPECT_TRUE(ToolInfo::ValidateName("hms-abcdefghijklmnop"));  // exactly 16 chars

    // Invalid edge cases
    EXPECT_FALSE(ToolInfo::ValidateName("ohos-1234567890abcdefg"));  // 17 chars
    EXPECT_FALSE(ToolInfo::ValidateName("ohos-"));  // 0 chars suffix

    GTEST_LOG_(INFO) << "ToolInfo_ValidateName_0600 end";
}

// ==================== ValidateExecutablePath Tests ====================

/**
 * @tc.name: ToolInfo_ValidateExecutablePath_0100
 * @tc.desc: Test ToolInfo ValidateExecutablePath with valid absolute paths
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ValidateExecutablePath_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ValidateExecutablePath_0100 start";

    EXPECT_TRUE(ToolInfo::ValidateExecutablePath("/bin/ls"));
    EXPECT_TRUE(ToolInfo::ValidateExecutablePath("/usr/bin/test"));
    EXPECT_TRUE(ToolInfo::ValidateExecutablePath("/system/bin/tool"));
    EXPECT_TRUE(ToolInfo::ValidateExecutablePath("/"));
    EXPECT_TRUE(ToolInfo::ValidateExecutablePath("/a"));

    GTEST_LOG_(INFO) << "ToolInfo_ValidateExecutablePath_0100 end";
}

/**
 * @tc.name: ToolInfo_ValidateExecutablePath_0200
 * @tc.desc: Test ToolInfo ValidateExecutablePath with invalid paths
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ValidateExecutablePath_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ValidateExecutablePath_0200 start";

    EXPECT_FALSE(ToolInfo::ValidateExecutablePath(""));  // empty
    EXPECT_FALSE(ToolInfo::ValidateExecutablePath("bin/ls"));  // relative path
    EXPECT_FALSE(ToolInfo::ValidateExecutablePath("./test"));  // relative path
    EXPECT_FALSE(ToolInfo::ValidateExecutablePath("../tool"));  // relative path
    EXPECT_FALSE(ToolInfo::ValidateExecutablePath("test"));  // no path

    GTEST_LOG_(INFO) << "ToolInfo_ValidateExecutablePath_0200 end";
}

// ==================== ParseFromJson Name Validation Tests ====================

/**
 * @tc.name: ToolInfo_ParseFromJson_NameValidation_0100
 * @tc.desc: Test ToolInfo ParseFromJson with invalid name (no prefix)
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_NameValidation_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_NameValidation_0100 start";

    nlohmann::json json = R"({
        "name": "invalid_tool",
        "version": "1.0.0"
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);
    EXPECT_TRUE(tool.name.empty());

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_NameValidation_0100 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_NameValidation_0200
 * @tc.desc: Test ToolInfo ParseFromJson with invalid name (suffix too long)
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_NameValidation_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_NameValidation_0200 start";

    nlohmann::json json = R"({
        "name": "ohos-thisisaverylongtoolname",
        "version": "1.0.0"
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_NameValidation_0200 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_NameValidation_0300
 * @tc.desc: Test ToolInfo ParseFromJson without name field
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_NameValidation_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_NameValidation_0300 start";

    nlohmann::json json = R"({
        "version": "1.0.0",
        "description": "Tool without name"
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_NameValidation_0300 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_NameValidation_0400
 * @tc.desc: Test ToolInfo ParseFromJson with name not string
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_NameValidation_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_NameValidation_0400 start";

    nlohmann::json json = R"({
        "name": 123,
        "version": "1.0.0"
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_NameValidation_0400 end";
}

// ==================== ParseFromJson Required Fields Validation Tests ====================

/**
 * @tc.name: ToolInfo_ParseFromJson_RequiredFields_0100
 * @tc.desc: Test ToolInfo ParseFromJson without version field
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_RequiredFields_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0100 start";

    nlohmann::json json = R"({
        "name": "ohos-test",
        "description": "Tool without version",
        "executablePath": "/bin/test"
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0100 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_RequiredFields_0200
 * @tc.desc: Test ToolInfo ParseFromJson with version not string
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_RequiredFields_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0200 start";

    nlohmann::json json = R"({
        "name": "ohos-test",
        "version": 123,
        "description": "Tool",
        "executablePath": "/bin/test"
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0200 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_RequiredFields_0220
 * @tc.desc: Test ToolInfo ParseFromJson with empty version
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_RequiredFields_0220, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0220 start";

    nlohmann::json json = R"({
        "name": "ohos-test",
        "version": "",
        "description": "Tool",
        "executablePath": "/bin/test"
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0220 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_RequiredFields_0300
 * @tc.desc: Test ToolInfo ParseFromJson without description field
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_RequiredFields_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0300 start";

    nlohmann::json json = R"({
        "name": "ohos-test",
        "version": "1.0.0",
        "executablePath": "/bin/test"
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0300 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_RequiredFields_0400
 * @tc.desc: Test ToolInfo ParseFromJson with description not string
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_RequiredFields_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0400 start";

    nlohmann::json json = R"({
        "name": "ohos-test",
        "version": "1.0.0",
        "description": 123,
        "executablePath": "/bin/test"
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0400 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_RequiredFields_0420
 * @tc.desc: Test ToolInfo ParseFromJson with empty description
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_RequiredFields_0420, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0420 start";

    nlohmann::json json = R"({
        "name": "ohos-test",
        "version": "1.0.0",
        "description": "",
        "executablePath": "/bin/test"
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0420 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_RequiredFields_0500
 * @tc.desc: Test ToolInfo ParseFromJson without executablePath field
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_RequiredFields_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0500 start";

    nlohmann::json json = R"({
        "name": "ohos-test",
        "version": "1.0.0",
        "description": "Tool without path"
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0500 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_RequiredFields_0600
 * @tc.desc: Test ToolInfo ParseFromJson with executablePath not string
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_RequiredFields_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0600 start";

    nlohmann::json json = R"({
        "name": "ohos-test",
        "version": "1.0.0",
        "description": "Tool",
        "executablePath": 123
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0600 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_RequiredFields_0700
 * @tc.desc: Test ToolInfo ParseFromJson with relative executablePath
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_RequiredFields_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0700 start";

    nlohmann::json json = R"({
        "name": "ohos-test",
        "version": "1.0.0",
        "description": "Tool",
        "executablePath": "bin/test"
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0700 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_RequiredFields_0800
 * @tc.desc: Test ToolInfo ParseFromJson with empty executablePath
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_RequiredFields_0800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0800 start";

    nlohmann::json json = R"({
        "name": "ohos-test",
        "version": "1.0.0",
        "description": "Tool",
        "executablePath": ""
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0800 end";
}

/**
 * @tc.name: ToolInfo_ParseFromJson_RequiredFields_0900
 * @tc.desc: Test ToolInfo ParseFromJson with all required fields valid
 * @tc.type: FUNC
 */
HWTEST_F(ToolInfoTest, ToolInfo_ParseFromJson_RequiredFields_0900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0900 start";

    nlohmann::json json = R"({
        "name": "ohos-testtool",
        "version": "1.0.0",
        "description": "A valid tool",
        "executablePath": "/bin/test"
    })"_json;

    ToolInfo tool;
    bool result = ToolInfo::ParseFromJson(json, tool);

    EXPECT_TRUE(result);
    EXPECT_EQ(tool.name, "ohos-testtool");
    EXPECT_EQ(tool.version, "1.0.0");
    EXPECT_EQ(tool.description, "A valid tool");
    EXPECT_EQ(tool.executablePath, "/bin/test");

    GTEST_LOG_(INFO) << "ToolInfo_ParseFromJson_RequiredFields_0900 end";
}

} // namespace CliTool
} // namespace OHOS