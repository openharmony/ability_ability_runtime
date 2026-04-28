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
#include <parcel.h>

#include "sub_command_info.h"

using namespace testing::ext;

namespace OHOS {
namespace CliTool {

class SubCommandInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SubCommandInfoTest::SetUpTestCase(void) {}
void SubCommandInfoTest::TearDownTestCase(void) {}
void SubCommandInfoTest::SetUp() {}
void SubCommandInfoTest::TearDown() {}

/**
 * @tc.name: SubCommandInfo_Marshalling_0100
 * @tc.desc: Test SubCommandInfo Marshalling with argMapping
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Marshalling_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Marshalling_0100 start";

    SubCommandInfo subCmd;
    subCmd.description = "Test subcommand";
    subCmd.requirePermissions = {"ohos.permission.INTERNET"};
    subCmd.inputSchema = "{}";
    subCmd.outputSchema = "{}";
    subCmd.argMapping = std::make_shared<ArgMapping>();
    subCmd.argMapping->type = ArgMappingType::FLAG;
    subCmd.eventTypes = {"stdout", "stderr"};
    subCmd.eventSchemas = "{}";

    Parcel parcel;
    bool ret = subCmd.Marshalling(parcel);

    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "SubCommandInfo_Marshalling_0100 end";
}

/**
 * @tc.name: SubCommandInfo_Marshalling_0200
 * @tc.desc: Test SubCommandInfo Marshalling without argMapping
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Marshalling_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Marshalling_0200 start";

    SubCommandInfo subCmd;
    subCmd.description = "Test subcommand without argMapping";
    subCmd.requirePermissions = {};
    subCmd.inputSchema = "{}";
    subCmd.outputSchema = "{}";
    subCmd.argMapping = nullptr;
    subCmd.eventTypes = {};
    subCmd.eventSchemas = "{}";

    Parcel parcel;
    bool ret = subCmd.Marshalling(parcel);

    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "SubCommandInfo_Marshalling_0200 end";
}

/**
 * @tc.name: SubCommandInfo_Marshalling_0300
 * @tc.desc: Test SubCommandInfo Marshalling with multiple permissions
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Marshalling_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Marshalling_0300 start";

    SubCommandInfo subCmd;
    subCmd.description = "Test with multiple permissions";
    subCmd.requirePermissions = {"ohos.permission.INTERNET", "ohos.permission.CAMERA", "ohos.permission.READ_STORAGE"};
    subCmd.inputSchema = R"({"type": "object", "properties": {"input": {"type": "string"}}})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();
    subCmd.argMapping->type = ArgMappingType::POSITIONAL;
    subCmd.argMapping->order = "arg1,arg2";
    subCmd.eventTypes = {"stdout", "stderr", "exit"};
    subCmd.eventSchemas = R"({"stdout": {"type": "string"}, "stderr": {"type": "string"}})";

    Parcel parcel;
    bool ret = subCmd.Marshalling(parcel);

    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "SubCommandInfo_Marshalling_0300 end";
}

/**
 * @tc.name: SubCommandInfo_Marshalling_0400
 * @tc.desc: Test SubCommandInfo Marshalling with all ArgMapping types
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Marshalling_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Marshalling_0400 start";

    // Test FLAG type
    SubCommandInfo subCmdFlag;
    subCmdFlag.argMapping = std::make_shared<ArgMapping>();
    subCmdFlag.argMapping->type = ArgMappingType::FLAG;
    Parcel parcelFlag;
    EXPECT_TRUE(subCmdFlag.Marshalling(parcelFlag));

    // Test POSITIONAL type
    SubCommandInfo subCmdPos;
    subCmdPos.argMapping = std::make_shared<ArgMapping>();
    subCmdPos.argMapping->type = ArgMappingType::POSITIONAL;
    Parcel parcelPos;
    EXPECT_TRUE(subCmdPos.Marshalling(parcelPos));

    // Test FLATTENED type
    SubCommandInfo subCmdFlat;
    subCmdFlat.argMapping = std::make_shared<ArgMapping>();
    subCmdFlat.argMapping->type = ArgMappingType::FLATTENED;
    Parcel parcelFlat;
    EXPECT_TRUE(subCmdFlat.Marshalling(parcelFlat));

    // Test JSONSTRING type
    SubCommandInfo subCmdJson;
    subCmdJson.argMapping = std::make_shared<ArgMapping>();
    subCmdJson.argMapping->type = ArgMappingType::JSONSTRING;
    Parcel parcelJson;
    EXPECT_TRUE(subCmdJson.Marshalling(parcelJson));

    // Test MIXED type
    SubCommandInfo subCmdMixed;
    subCmdMixed.argMapping = std::make_shared<ArgMapping>();
    subCmdMixed.argMapping->type = ArgMappingType::MIXED;
    Parcel parcelMixed;
    EXPECT_TRUE(subCmdMixed.Marshalling(parcelMixed));

    GTEST_LOG_(INFO) << "SubCommandInfo_Marshalling_0400 end";
}

/**
 * @tc.name: SubCommandInfo_Unmarshalling_0100
 * @tc.desc: Test SubCommandInfo Unmarshalling with argMapping
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Unmarshalling_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Unmarshalling_0100 start";

    SubCommandInfo original;
    original.description = "Original subcommand";
    original.requirePermissions = {"ohos.permission.READ_STORAGE"};
    original.inputSchema = R"({"type": "object"})";
    original.outputSchema = R"({"type": "string"})";
    original.argMapping = std::make_shared<ArgMapping>();
    original.argMapping->type = ArgMappingType::JSONSTRING;
    original.argMapping->separator = "";
    original.argMapping->order = "";
    original.argMapping->templates = "{}";
    original.eventTypes = {"exit"};
    original.eventSchemas = R"({"exit": {"type": "object"}})";

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    SubCommandInfo *result = SubCommandInfo::Unmarshalling(parcel);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->description, "Original subcommand");
    EXPECT_EQ(result->requirePermissions.size(), 1u);
    EXPECT_TRUE(result->argMapping != nullptr);
    EXPECT_EQ(result->argMapping->type, ArgMappingType::JSONSTRING);

    delete result;

    GTEST_LOG_(INFO) << "SubCommandInfo_Unmarshalling_0100 end";
}

/**
 * @tc.name: SubCommandInfo_Unmarshalling_0200
 * @tc.desc: Test SubCommandInfo Unmarshalling without argMapping
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Unmarshalling_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Unmarshalling_0200 start";

    SubCommandInfo original;
    original.description = "No argMapping";
    original.requirePermissions = {};
    original.inputSchema = "{}";
    original.outputSchema = "{}";
    original.argMapping = nullptr;
    original.eventTypes = {};
    original.eventSchemas = "{}";

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    SubCommandInfo *result = SubCommandInfo::Unmarshalling(parcel);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->description, "No argMapping");
    EXPECT_TRUE(result->argMapping == nullptr);

    delete result;

    GTEST_LOG_(INFO) << "SubCommandInfo_Unmarshalling_0200 end";
}

/**
 * @tc.name: SubCommandInfo_Unmarshalling_0300
 * @tc.desc: Test SubCommandInfo Unmarshalling fail with empty parcel
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Unmarshalling_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Unmarshalling_0300 start";

    Parcel parcel;
    SubCommandInfo *result = SubCommandInfo::Unmarshalling(parcel);

    EXPECT_EQ(result, nullptr);

    GTEST_LOG_(INFO) << "SubCommandInfo_Unmarshalling_0300 end";
}

/**
 * @tc.name: SubCommandInfo_Unmarshalling_0400
 * @tc.desc: Test SubCommandInfo Unmarshalling with full data
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Unmarshalling_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Unmarshalling_0400 start";

    SubCommandInfo original;
    original.description = "Full test subcommand";
    original.requirePermissions = {"ohos.permission.INTERNET", "ohos.permission.CAMERA"};
    original.inputSchema =
        R"({"type": "object", "properties": {"arg1": {"type": "string"}, "arg2": {"type": "number"}}})";
    original.outputSchema = R"({"type": "object", "properties": {"result": {"type": "string"}}})";
    original.argMapping = std::make_shared<ArgMapping>();
    original.argMapping->type = ArgMappingType::MIXED;
    original.argMapping->separator = ",";
    original.argMapping->order = "arg1,arg2,arg3";
    original.argMapping->templates = R"({"arg1": "--input=${value}", "arg2": "-o ${value}"})";
    original.eventTypes = {"stdout", "stderr", "exit", "error"};
    original.eventSchemas =
        R"({"stdout": {"type": "string"}, "stderr": {"type": "string"}, "exit": {"type": "number"}})";

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    SubCommandInfo *result = SubCommandInfo::Unmarshalling(parcel);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->description, "Full test subcommand");
    EXPECT_EQ(result->requirePermissions.size(), 2u);
    EXPECT_EQ(result->requirePermissions[0], "ohos.permission.INTERNET");
    EXPECT_EQ(result->requirePermissions[1], "ohos.permission.CAMERA");
    ASSERT_NE(result->argMapping, nullptr);
    EXPECT_EQ(result->argMapping->type, ArgMappingType::MIXED);
    EXPECT_EQ(result->argMapping->separator, ",");
    EXPECT_EQ(result->argMapping->order, "arg1,arg2,arg3");
    EXPECT_EQ(result->eventTypes.size(), 4u);

    delete result;

    GTEST_LOG_(INFO) << "SubCommandInfo_Unmarshalling_0400 end";
}

/**
 * @tc.name: SubCommandInfo_Marshalling_Unmarshalling_RoundTrip_0100
 * @tc.desc: Test SubCommandInfo Marshalling and Unmarshalling round trip
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Marshalling_Unmarshalling_RoundTrip_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Marshalling_Unmarshalling_RoundTrip_0100 start";

    SubCommandInfo original;
    original.description = "Round trip test";
    original.requirePermissions = {"ohos.permission.WRITE_STORAGE"};
    original.inputSchema = R"({"type": "object"})";
    original.outputSchema = R"({"type": "array"})";
    original.argMapping = std::make_shared<ArgMapping>();
    original.argMapping->type = ArgMappingType::FLATTENED;
    original.argMapping->separator = "|";
    original.argMapping->order = "a,b,c";
    original.argMapping->templates = "{}";
    original.eventTypes = {"event1", "event2"};
    original.eventSchemas = R"({"event1": {}, "event2": {}})";

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    SubCommandInfo *result = SubCommandInfo::Unmarshalling(parcel);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->description, original.description);
    EXPECT_EQ(result->requirePermissions, original.requirePermissions);
    EXPECT_EQ(result->inputSchema, original.inputSchema);
    EXPECT_EQ(result->outputSchema, original.outputSchema);
    ASSERT_NE(result->argMapping, nullptr);
    EXPECT_EQ(result->argMapping->type, original.argMapping->type);
    EXPECT_EQ(result->argMapping->separator, original.argMapping->separator);
    EXPECT_EQ(result->argMapping->order, original.argMapping->order);
    EXPECT_EQ(result->eventTypes, original.eventTypes);
    EXPECT_EQ(result->eventSchemas, original.eventSchemas);

    delete result;

    GTEST_LOG_(INFO) << "SubCommandInfo_Marshalling_Unmarshalling_RoundTrip_0100 end";
}

/**
 * @tc.name: SubCommandInfo_DefaultConstructor_0100
 * @tc.desc: Test SubCommandInfo default constructor
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_DefaultConstructor_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_DefaultConstructor_0100 start";

    SubCommandInfo subCmd;

    EXPECT_TRUE(subCmd.description.empty());
    EXPECT_TRUE(subCmd.requirePermissions.empty());
    EXPECT_TRUE(subCmd.inputSchema.empty());
    EXPECT_TRUE(subCmd.outputSchema.empty());
    EXPECT_EQ(subCmd.argMapping, nullptr);
    EXPECT_TRUE(subCmd.eventTypes.empty());
    EXPECT_TRUE(subCmd.eventSchemas.empty());

    GTEST_LOG_(INFO) << "SubCommandInfo_DefaultConstructor_0100 end";
}

// ==================== ParseFromJson Tests ====================

/**
 * @tc.name: SubCommandInfo_ParseFromJson_0100
 * @tc.desc: Test SubCommandInfo ParseFromJson with full data
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_0100 start";

    nlohmann::json json = R"({
        "description": "Test subcommand from JSON",
        "requirePermissions": ["ohos.permission.INTERNET", "ohos.permission.CAMERA"],
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "positional", "order": "arg1,arg2"},
        "eventTypes": ["stdout", "stderr"],
        "eventSchemas": {"stdout": {"type": "string"}}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_TRUE(result);
    EXPECT_EQ(subCmd.description, "Test subcommand from JSON");
    EXPECT_EQ(subCmd.requirePermissions.size(), 2u);
    EXPECT_EQ(subCmd.requirePermissions[0], "ohos.permission.INTERNET");
    EXPECT_EQ(subCmd.requirePermissions[1], "ohos.permission.CAMERA");
    EXPECT_FALSE(subCmd.inputSchema.empty());
    EXPECT_FALSE(subCmd.outputSchema.empty());
    ASSERT_NE(subCmd.argMapping, nullptr);
    EXPECT_EQ(subCmd.argMapping->type, ArgMappingType::POSITIONAL);
    EXPECT_EQ(subCmd.argMapping->order, "arg1,arg2");
    EXPECT_EQ(subCmd.eventTypes.size(), 2u);
    EXPECT_FALSE(subCmd.eventSchemas.empty());

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_0100 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_0200
 * @tc.desc: Test SubCommandInfo ParseFromJson with empty JSON (required fields missing)
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_0200 start";

    nlohmann::json json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // required fields missing

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_0200 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_0300
 * @tc.desc: Test SubCommandInfo ParseFromJson without argMapping (argMapping is required)
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_0300 start";

    nlohmann::json json = R"({
        "description": "No argMapping",
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "array"}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // argMapping is required

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_0300 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_0400
 * @tc.desc: Test SubCommandInfo ParseFromJson with invalid argMapping
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_0400 start";

    nlohmann::json json = R"({
        "description": "Invalid argMapping",
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "invalid_type"}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // argMapping parse failed

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_0400 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_0500
 * @tc.desc: Test SubCommandInfo ParseFromJson with argMapping missing type
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_0500 start";

    nlohmann::json json = R"({
        "description": "argMapping without type",
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"separator": ","}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // argMapping type is required

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_0500 end";
}

// ==================== ParseToJson Tests ====================

/**
 * @tc.name: SubCommandInfo_ParseToJson_0100
 * @tc.desc: Test SubCommandInfo ParseToJson with full data
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseToJson_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0100 start";

    SubCommandInfo subCmd;
    subCmd.description = "Test to JSON";
    subCmd.requirePermissions = {"ohos.permission.READ_STORAGE"};
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();
    subCmd.argMapping->type = ArgMappingType::FLAG;
    subCmd.eventTypes = {"event1"};
    subCmd.eventSchemas = R"({"event1": {"type": "object"}})";

    nlohmann::json json = subCmd.ParseToJson();

    EXPECT_EQ(json["description"], "Test to JSON");
    EXPECT_EQ(json["requirePermissions"].size(), 1u);
    EXPECT_EQ(json["inputSchema"], R"({"type": "object"})");
    EXPECT_EQ(json["outputSchema"], R"({"type": "string"})");
    EXPECT_TRUE(json.contains("argMapping"));
    EXPECT_EQ(json["eventTypes"].size(), 1u);
    EXPECT_EQ(json["eventSchemas"], R"({"event1": {"type": "object"}})");

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0100 end";
}

/**
 * @tc.name: SubCommandInfo_ParseToJson_0200
 * @tc.desc: Test SubCommandInfo ParseToJson without argMapping
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseToJson_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0200 start";

    SubCommandInfo subCmd;
    subCmd.description = "No argMapping to JSON";
    subCmd.requirePermissions = {};
    subCmd.inputSchema = "{}";
    subCmd.outputSchema = "{}";
    subCmd.argMapping = nullptr;
    subCmd.eventTypes = {};
    subCmd.eventSchemas = "{}";

    nlohmann::json json = subCmd.ParseToJson();

    EXPECT_EQ(json["description"], "No argMapping to JSON");
    EXPECT_FALSE(json.contains("argMapping"));

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0200 end";
}

/**
 * @tc.name: SubCommandInfo_ParseToJson_0300
 * @tc.desc: Test SubCommandInfo ParseToJson with empty data
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseToJson_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0300 start";

    SubCommandInfo subCmd;

    nlohmann::json json = subCmd.ParseToJson();

    EXPECT_TRUE(json.contains("description"));
    EXPECT_TRUE(json["description"].is_string());
    EXPECT_TRUE(json["description"].get<std::string>().empty());
    EXPECT_TRUE(json.contains("requirePermissions"));
    EXPECT_TRUE(json["requirePermissions"].is_array());
    EXPECT_TRUE(json["requirePermissions"].empty());
    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_TRUE(json["inputSchema"].is_string());
    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_TRUE(json["outputSchema"].is_string());
    EXPECT_TRUE(json.contains("eventTypes"));
    EXPECT_TRUE(json["eventTypes"].is_array());
    EXPECT_TRUE(json["eventTypes"].empty());
    EXPECT_TRUE(json.contains("eventSchemas"));
    EXPECT_TRUE(json["eventSchemas"].is_string());
    EXPECT_FALSE(json.contains("argMapping"));

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0300 end";
}

// ==================== ParseFromJson/ParseToJson Round Trip Tests ====================

/**
 * @tc.name: SubCommandInfo_ParseFromJson_ParseToJson_RoundTrip_0100
 * @tc.desc: Test SubCommandInfo ParseFromJson and ParseToJson round trip
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_ParseToJson_RoundTrip_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_ParseToJson_RoundTrip_0100 start";

    nlohmann::json originalJson = R"({
        "description": "Round trip test",
        "requirePermissions": ["ohos.permission.INTERNET"],
        "inputSchema": {"type": "object", "properties": {"input": {"type": "string"}}},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "mixed", "separator": ",", "order": "a,b", "templates": "{}"},
        "eventTypes": ["stdout", "stderr", "exit"],
        "eventSchemas": {"stdout": {"type": "string"}, "exit": {"type": "number"}}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(originalJson, subCmd);
    EXPECT_TRUE(result);
    nlohmann::json resultJson = subCmd.ParseToJson();

    EXPECT_EQ(resultJson["description"], originalJson["description"]);
    EXPECT_EQ(resultJson["requirePermissions"], originalJson["requirePermissions"]);
    EXPECT_EQ(resultJson["eventTypes"], originalJson["eventTypes"]);

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_ParseToJson_RoundTrip_0100 end";
}

/**
 * @tc.name: SubCommandInfo_ParseToJson_0400
 * @tc.desc: Test SubCommandInfo ParseToJson with invalid inputSchema JSON string
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseToJson_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0400 start";

    SubCommandInfo subCmd;
    subCmd.description = "Invalid inputSchema test";
    subCmd.inputSchema = "invalid json string";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.eventSchemas = R"({"event1": {"type": "object"}})";

    nlohmann::json json = subCmd.ParseToJson();

    EXPECT_EQ(json["description"], "Invalid inputSchema test");
    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_EQ(json["inputSchema"], "invalid json string");
    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_EQ(json["outputSchema"], R"({"type": "string"})");
    EXPECT_TRUE(json.contains("eventSchemas"));

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0400 end";
}

/**
 * @tc.name: SubCommandInfo_ParseToJson_0500
 * @tc.desc: Test SubCommandInfo ParseToJson with invalid outputSchema JSON string
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseToJson_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0500 start";

    SubCommandInfo subCmd;
    subCmd.description = "Invalid outputSchema test";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = "{invalid json}";
    subCmd.eventSchemas = "{}";

    nlohmann::json json = subCmd.ParseToJson();

    EXPECT_EQ(json["description"], "Invalid outputSchema test");
    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_EQ(json["inputSchema"], R"({"type": "object"})");
    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_EQ(json["outputSchema"], "{invalid json}");

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0500 end";
}

/**
 * @tc.name: SubCommandInfo_ParseToJson_0600
 * @tc.desc: Test SubCommandInfo ParseToJson with invalid eventSchemas JSON string
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseToJson_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0600 start";

    SubCommandInfo subCmd;
    subCmd.description = "Invalid eventSchemas test";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.eventSchemas = "not a valid json";

    nlohmann::json json = subCmd.ParseToJson();

    EXPECT_EQ(json["description"], "Invalid eventSchemas test");
    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_TRUE(json.contains("eventSchemas"));
    EXPECT_EQ(json["eventSchemas"], "not a valid json");

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0600 end";
}

/**
 * @tc.name: SubCommandInfo_ParseToJson_0700
 * @tc.desc: Test SubCommandInfo ParseToJson with complex valid inputSchema
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseToJson_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0700 start";

    SubCommandInfo subCmd;
    subCmd.description = "Complex schema test";
    subCmd.inputSchema = R"({
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "User name"},
            "age": {"type": "number", "minimum": 0},
            "address": {
                "type": "object",
                "properties": {
                    "city": {"type": "string"},
                    "country": {"type": "string"}
                },
                "required": ["city"]
            }
        },
        "required": ["name"]
    })";
    subCmd.outputSchema = R"({"type": "array", "items": {"type": "string"}})";
    subCmd.eventSchemas = R"({
        "stdout": {"type": "string"},
        "stderr": {"type": "string"},
        "exit": {"type": "number"}
    })";

    nlohmann::json json = subCmd.ParseToJson();

    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_TRUE(json["inputSchema"].is_object());
    EXPECT_TRUE(json["inputSchema"].contains("properties"));
    EXPECT_TRUE(json["inputSchema"]["properties"].contains("name"));
    EXPECT_TRUE(json["inputSchema"]["properties"].contains("address"));

    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_TRUE(json["outputSchema"].is_object());
    EXPECT_EQ(json["outputSchema"]["type"], "array");

    EXPECT_TRUE(json.contains("eventSchemas"));
    EXPECT_TRUE(json["eventSchemas"].is_object());
    EXPECT_TRUE(json["eventSchemas"].contains("stdout"));
    EXPECT_TRUE(json["eventSchemas"].contains("exit"));

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0700 end";
}

/**
 * @tc.name: SubCommandInfo_ParseToJson_0800
 * @tc.desc: Test SubCommandInfo ParseToJson with all invalid schemas
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseToJson_0800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0800 start";

    SubCommandInfo subCmd;
    subCmd.description = "All invalid schemas";
    subCmd.inputSchema = "invalid";
    subCmd.outputSchema = "also invalid";
    subCmd.eventSchemas = "invalid too";

    nlohmann::json json = subCmd.ParseToJson();

    EXPECT_EQ(json["description"], "All invalid schemas");
    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_EQ(json["inputSchema"], "invalid");
    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_EQ(json["outputSchema"], "also invalid");
    EXPECT_TRUE(json.contains("eventSchemas"));
    EXPECT_EQ(json["eventSchemas"], "invalid too");

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0800 end";
}

/**
 * @tc.name: SubCommandInfo_ParseToJson_0900
 * @tc.desc: Test SubCommandInfo ParseToJson with empty inputSchema
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseToJson_0900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0900 start";

    SubCommandInfo subCmd;
    subCmd.description = "Empty inputSchema test";
    subCmd.inputSchema = "";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.eventSchemas = "{}";

    nlohmann::json json = subCmd.ParseToJson();

    EXPECT_EQ(json["description"], "Empty inputSchema test");
    EXPECT_FALSE(json.contains("inputSchema"));
    EXPECT_TRUE(json.contains("outputSchema"));

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_0900 end";
}

/**
 * @tc.name: SubCommandInfo_ParseToJson_1000
 * @tc.desc: Test SubCommandInfo ParseToJson with empty outputSchema
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseToJson_1000, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_1000 start";

    SubCommandInfo subCmd;
    subCmd.description = "Empty outputSchema test";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = "";
    subCmd.eventSchemas = "{}";

    nlohmann::json json = subCmd.ParseToJson();

    EXPECT_EQ(json["description"], "Empty outputSchema test");
    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_FALSE(json.contains("outputSchema"));

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_1000 end";
}

/**
 * @tc.name: SubCommandInfo_ParseToJson_1100
 * @tc.desc: Test SubCommandInfo ParseToJson with empty eventSchemas
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseToJson_1100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_1100 start";

    SubCommandInfo subCmd;
    subCmd.description = "Empty eventSchemas test";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.eventSchemas = "";

    nlohmann::json json = subCmd.ParseToJson();

    EXPECT_EQ(json["description"], "Empty eventSchemas test");
    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_FALSE(json.contains("eventSchemas"));

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_1100 end";
}

/**
 * @tc.name: SubCommandInfo_ParseToJson_1200
 * @tc.desc: Test SubCommandInfo ParseToJson with array type schemas
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseToJson_1200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_1200 start";

    SubCommandInfo subCmd;
    subCmd.description = "Array schema test";
    subCmd.inputSchema = R"({"type": "array", "items": {"type": "number"}})";
    subCmd.outputSchema = R"({"type": "array", "items": {"type": "object"}})";
    subCmd.eventSchemas = R"({"events": {"type": "array"}})";

    nlohmann::json json = subCmd.ParseToJson();

    EXPECT_TRUE(json.contains("inputSchema"));
    EXPECT_TRUE(json["inputSchema"].is_object());
    EXPECT_EQ(json["inputSchema"]["type"], "array");

    EXPECT_TRUE(json.contains("outputSchema"));
    EXPECT_TRUE(json["outputSchema"].is_object());
    EXPECT_EQ(json["outputSchema"]["type"], "array");

    EXPECT_TRUE(json.contains("eventSchemas"));
    EXPECT_TRUE(json["eventSchemas"].is_object());

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseToJson_1200 end";
}

// ==================== ParseFromJson Validation Tests ====================

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_0100
 * @tc.desc: Test SubCommandInfo ParseFromJson with empty description (description is required)
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0100 start";

    nlohmann::json json = R"({
        "description": "",
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // description must be non-empty

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0100 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_0200
 * @tc.desc: Test SubCommandInfo ParseFromJson without description (description is required)
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0200 start";

    nlohmann::json json = R"({
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // description is required

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0200 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_0300
 * @tc.desc: Test SubCommandInfo ParseFromJson with duplicate requirePermissions (duplicates are allowed)
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0300 start";

    nlohmann::json json = R"({
        "description": "Duplicate permissions",
        "requirePermissions": ["ohos.permission.INTERNET", "ohos.permission.INTERNET"],
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_TRUE(result);  // duplicate permissions are now allowed

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0300 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_0400
 * @tc.desc: Test SubCommandInfo ParseFromJson with non-string requirePermissions
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0400 start";

    nlohmann::json json = R"({
        "description": "Non-string permission",
        "requirePermissions": ["ohos.permission.INTERNET", 123],
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // all permissions must be strings

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0400 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_0401
 * @tc.desc: Test SubCommandInfo ParseFromJson with empty string in requirePermissions (empty strings are skipped)
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_0401, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0401 start";

    nlohmann::json json = R"({
        "description": "Empty string permission",
        "requirePermissions": ["ohos.permission.INTERNET", "", "ohos.permission.CAMERA"],
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_TRUE(result);  // empty strings are skipped
    EXPECT_EQ(subCmd.requirePermissions.size(), 2u);  // only non-empty permissions stored
    EXPECT_EQ(subCmd.requirePermissions[0], "ohos.permission.INTERNET");
    EXPECT_EQ(subCmd.requirePermissions[1], "ohos.permission.CAMERA");

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0401 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_0500
 * @tc.desc: Test SubCommandInfo ParseFromJson with requirePermissions not array
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0500 start";

    nlohmann::json json = R"({
        "description": "Permissions not array",
        "requirePermissions": "ohos.permission.INTERNET",
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // requirePermissions must be array

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0500 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_0600
 * @tc.desc: Test SubCommandInfo ParseFromJson without inputSchema (inputSchema is required)
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0600 start";

    nlohmann::json json = R"({
        "description": "No inputSchema",
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // inputSchema is required

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0600 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_0700
 * @tc.desc: Test SubCommandInfo ParseFromJson with inputSchema not object
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0700 start";

    nlohmann::json json = R"({
        "description": "inputSchema not object",
        "inputSchema": "not an object",
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // inputSchema must be object

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0700 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_0800
 * @tc.desc: Test SubCommandInfo ParseFromJson without outputSchema (outputSchema is required)
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_0800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0800 start";

    nlohmann::json json = R"({
        "description": "No outputSchema",
        "inputSchema": {"type": "object"},
        "argMapping": {"type": "flag"}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // outputSchema is required

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0800 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_0900
 * @tc.desc: Test SubCommandInfo ParseFromJson with outputSchema not object
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_0900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0900 start";

    nlohmann::json json = R"({
        "description": "outputSchema not object",
        "inputSchema": {"type": "object"},
        "outputSchema": 123,
        "argMapping": {"type": "flag"}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // outputSchema must be object

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_0900 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_1000
 * @tc.desc: Test SubCommandInfo ParseFromJson with duplicate eventTypes (duplicates are allowed)
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_1000, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1000 start";

    nlohmann::json json = R"({
        "description": "Duplicate eventTypes",
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"},
        "eventTypes": ["stdout", "stdout"]
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_TRUE(result);  // duplicate eventTypes are now allowed

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1000 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_1100
 * @tc.desc: Test SubCommandInfo ParseFromJson with non-string eventTypes
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_1100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1100 start";

    nlohmann::json json = R"({
        "description": "Non-string eventType",
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"},
        "eventTypes": ["stdout", 123]
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // all eventTypes must be strings

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1100 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_1101
 * @tc.desc: Test SubCommandInfo ParseFromJson with empty string in eventTypes (empty strings are skipped)
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_1101, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1101 start";

    nlohmann::json json = R"({
        "description": "Empty string eventType",
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"},
        "eventTypes": ["stdout", "", "stderr"]
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_TRUE(result);  // empty strings are skipped
    EXPECT_EQ(subCmd.eventTypes.size(), 2u);  // only non-empty eventTypes stored
    EXPECT_EQ(subCmd.eventTypes[0], "stdout");
    EXPECT_EQ(subCmd.eventTypes[1], "stderr");

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1101 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_1200
 * @tc.desc: Test SubCommandInfo ParseFromJson with eventTypes not array
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_1200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1200 start";

    nlohmann::json json = R"({
        "description": "eventTypes not array",
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"},
        "eventTypes": "stdout"
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // eventTypes must be array

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1200 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_1300
 * @tc.desc: Test SubCommandInfo ParseFromJson with eventSchemas not object
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_1300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1300 start";

    nlohmann::json json = R"({
        "description": "eventSchemas not object",
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"},
        "eventSchemas": "not an object"
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_FALSE(result);  // eventSchemas must be object

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1300 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_1400
 * @tc.desc: Test SubCommandInfo ParseFromJson with valid minimal data
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_1400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1400 start";

    nlohmann::json json = R"({
        "description": "Minimal valid subcommand",
        "inputSchema": {},
        "outputSchema": {},
        "argMapping": {"type": "flag"}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_TRUE(result);
    EXPECT_EQ(subCmd.description, "Minimal valid subcommand");
    EXPECT_TRUE(subCmd.requirePermissions.empty());
    EXPECT_TRUE(subCmd.eventTypes.empty());
    EXPECT_TRUE(subCmd.eventSchemas.empty());

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1400 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_1500
 * @tc.desc: Test SubCommandInfo ParseFromJson with unique requirePermissions
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_1500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1500 start";

    nlohmann::json json = R"({
        "description": "Unique permissions",
        "requirePermissions": ["ohos.permission.INTERNET", "ohos.permission.CAMERA", "ohos.permission.READ_STORAGE"],
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_TRUE(result);
    EXPECT_EQ(subCmd.requirePermissions.size(), 3u);

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1500 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_1600
 * @tc.desc: Test SubCommandInfo ParseFromJson with unique eventTypes
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_1600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1600 start";

    nlohmann::json json = R"({
        "description": "Unique eventTypes",
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"},
        "eventTypes": ["stdout", "stderr", "exit"]
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_TRUE(result);
    EXPECT_EQ(subCmd.eventTypes.size(), 3u);

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1600 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_Validation_1700
 * @tc.desc: Test SubCommandInfo ParseFromJson with valid eventSchemas object
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_Validation_1700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1700 start";

    nlohmann::json json = R"({
        "description": "Valid eventSchemas",
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "string"},
        "argMapping": {"type": "flag"},
        "eventSchemas": {"stdout": {"type": "string"}, "exit": {"type": "number"}}
    })"_json;

    SubCommandInfo subCmd;
    bool result = SubCommandInfo::ParseFromJson(json, subCmd);

    EXPECT_TRUE(result);
    EXPECT_FALSE(subCmd.eventSchemas.empty());

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_Validation_1700 end";
}

// ==================== Validate Tests ====================

/**
 * @tc.name: SubCommandInfo_Validate_0100
 * @tc.desc: Test SubCommandInfo::Validate with valid data
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0100 start";

    SubCommandInfo subCmd;
    subCmd.description = "Valid subcommand";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();
    subCmd.argMapping->type = ArgMappingType::FLAG;

    EXPECT_TRUE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0100 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_0200
 * @tc.desc: Test SubCommandInfo::Validate with empty description
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0200 start";

    SubCommandInfo subCmd;
    subCmd.description = "";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();

    EXPECT_FALSE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0200 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_0300
 * @tc.desc: Test SubCommandInfo::Validate with duplicate requirePermissions (duplicates are allowed)
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0300 start";

    SubCommandInfo subCmd;
    subCmd.description = "Duplicate permissions";
    subCmd.requirePermissions = {"ohos.permission.INTERNET", "ohos.permission.INTERNET"};
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();

    EXPECT_TRUE(SubCommandInfo::Validate(subCmd));  // duplicate permissions are now allowed

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0300 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_0400
 * @tc.desc: Test SubCommandInfo::Validate with unique requirePermissions
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0400 start";

    SubCommandInfo subCmd;
    subCmd.description = "Unique permissions";
    subCmd.requirePermissions = {"ohos.permission.INTERNET", "ohos.permission.CAMERA"};
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();

    EXPECT_TRUE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0400 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_0500
 * @tc.desc: Test SubCommandInfo::Validate with empty inputSchema
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0500 start";

    SubCommandInfo subCmd;
    subCmd.description = "Empty inputSchema";
    subCmd.inputSchema = "";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();

    EXPECT_FALSE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0500 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_0600
 * @tc.desc: Test SubCommandInfo::Validate with invalid inputSchema JSON
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0600 start";

    SubCommandInfo subCmd;
    subCmd.description = "Invalid inputSchema";
    subCmd.inputSchema = "not a valid json";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();

    EXPECT_FALSE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0600 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_0700
 * @tc.desc: Test SubCommandInfo::Validate with inputSchema not object
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0700 start";

    SubCommandInfo subCmd;
    subCmd.description = "inputSchema not object";
    subCmd.inputSchema = R"("just a string")";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();

    EXPECT_FALSE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0700 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_0800
 * @tc.desc: Test SubCommandInfo::Validate with empty outputSchema
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_0800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0800 start";

    SubCommandInfo subCmd;
    subCmd.description = "Empty outputSchema";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = "";
    subCmd.argMapping = std::make_shared<ArgMapping>();

    EXPECT_FALSE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0800 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_0900
 * @tc.desc: Test SubCommandInfo::Validate with invalid outputSchema JSON
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_0900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0900 start";

    SubCommandInfo subCmd;
    subCmd.description = "Invalid outputSchema";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = "{invalid json}";
    subCmd.argMapping = std::make_shared<ArgMapping>();

    EXPECT_FALSE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_0900 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_1000
 * @tc.desc: Test SubCommandInfo::Validate with outputSchema not object
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_1000, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1000 start";

    SubCommandInfo subCmd;
    subCmd.description = "outputSchema not object";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = "123";
    subCmd.argMapping = std::make_shared<ArgMapping>();

    EXPECT_FALSE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1000 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_1100
 * @tc.desc: Test SubCommandInfo::Validate with null argMapping
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_1100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1100 start";

    SubCommandInfo subCmd;
    subCmd.description = "Null argMapping";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = nullptr;

    EXPECT_FALSE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1100 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_1200
 * @tc.desc: Test SubCommandInfo::Validate with invalid argMapping
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_1200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1200 start";

    SubCommandInfo subCmd;
    subCmd.description = "Invalid argMapping";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();
    subCmd.argMapping->type = static_cast<ArgMappingType>(-1);  // invalid type

    EXPECT_FALSE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1200 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_1300
 * @tc.desc: Test SubCommandInfo::Validate with duplicate eventTypes (duplicates are allowed)
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_1300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1300 start";

    SubCommandInfo subCmd;
    subCmd.description = "Duplicate eventTypes";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();
    subCmd.eventTypes = {"stdout", "stdout"};

    EXPECT_TRUE(SubCommandInfo::Validate(subCmd));  // duplicate eventTypes are now allowed

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1300 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_1400
 * @tc.desc: Test SubCommandInfo::Validate with unique eventTypes
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_1400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1400 start";

    SubCommandInfo subCmd;
    subCmd.description = "Unique eventTypes";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();
    subCmd.eventTypes = {"stdout", "stderr", "exit"};

    EXPECT_TRUE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1400 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_1500
 * @tc.desc: Test SubCommandInfo::Validate with invalid eventSchemas JSON
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_1500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1500 start";

    SubCommandInfo subCmd;
    subCmd.description = "Invalid eventSchemas";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();
    subCmd.eventSchemas = "not a valid json";

    EXPECT_FALSE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1500 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_1600
 * @tc.desc: Test SubCommandInfo::Validate with eventSchemas not object
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_1600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1600 start";

    SubCommandInfo subCmd;
    subCmd.description = "eventSchemas not object";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();
    subCmd.eventSchemas = R"("just a string")";

    EXPECT_FALSE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1600 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_1700
 * @tc.desc: Test SubCommandInfo::Validate with valid eventSchemas object
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_1700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1700 start";

    SubCommandInfo subCmd;
    subCmd.description = "Valid eventSchemas";
    subCmd.inputSchema = R"({"type": "object"})";
    subCmd.outputSchema = R"({"type": "string"})";
    subCmd.argMapping = std::make_shared<ArgMapping>();
    subCmd.eventSchemas = R"({"stdout": {"type": "string"}})";

    EXPECT_TRUE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1700 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_1800
 * @tc.desc: Test SubCommandInfo::Validate with all valid fields
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_1800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1800 start";

    SubCommandInfo subCmd;
    subCmd.description = "All valid fields";
    subCmd.requirePermissions = {"ohos.permission.INTERNET", "ohos.permission.CAMERA"};
    subCmd.inputSchema = R"({"type": "object", "properties": {"input": {"type": "string"}}})";
    subCmd.outputSchema = R"({"type": "array", "items": {"type": "string"}})";
    subCmd.argMapping = std::make_shared<ArgMapping>();
    subCmd.argMapping->type = ArgMappingType::POSITIONAL;
    subCmd.argMapping->order = "arg1,arg2";
    subCmd.eventTypes = {"stdout", "stderr", "exit"};
    subCmd.eventSchemas = R"({"stdout": {"type": "string"}, "exit": {"type": "number"}})";

    EXPECT_TRUE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1800 end";
}

/**
 * @tc.name: SubCommandInfo_Validate_1900
 * @tc.desc: Test SubCommandInfo::Validate with minimal valid data
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_Validate_1900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1900 start";

    SubCommandInfo subCmd;
    subCmd.description = "Minimal";
    subCmd.inputSchema = "{}";
    subCmd.outputSchema = "{}";
    subCmd.argMapping = std::make_shared<ArgMapping>();

    EXPECT_TRUE(SubCommandInfo::Validate(subCmd));

    GTEST_LOG_(INFO) << "SubCommandInfo_Validate_1900 end";
}

} // namespace CliTool
} // namespace OHOS
