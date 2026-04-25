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

    SubCommandInfo subCmd = SubCommandInfo::ParseFromJson(json);

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
 * @tc.desc: Test SubCommandInfo ParseFromJson with empty JSON
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_0200 start";

    nlohmann::json json;

    SubCommandInfo subCmd = SubCommandInfo::ParseFromJson(json);

    EXPECT_TRUE(subCmd.description.empty());
    EXPECT_TRUE(subCmd.requirePermissions.empty());
    EXPECT_TRUE(subCmd.inputSchema.empty());
    EXPECT_TRUE(subCmd.outputSchema.empty());
    EXPECT_EQ(subCmd.argMapping, nullptr);
    EXPECT_TRUE(subCmd.eventTypes.empty());
    EXPECT_TRUE(subCmd.eventSchemas.empty());

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_0200 end";
}

/**
 * @tc.name: SubCommandInfo_ParseFromJson_0300
 * @tc.desc: Test SubCommandInfo ParseFromJson without argMapping
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandInfoTest, SubCommandInfo_ParseFromJson_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_0300 start";

    nlohmann::json json = R"({
        "description": "No argMapping",
        "requirePermissions": [],
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "array"},
        "eventTypes": []
    })"_json;

    SubCommandInfo subCmd = SubCommandInfo::ParseFromJson(json);

    EXPECT_EQ(subCmd.description, "No argMapping");
    EXPECT_EQ(subCmd.argMapping, nullptr);

    GTEST_LOG_(INFO) << "SubCommandInfo_ParseFromJson_0300 end";
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

    SubCommandInfo subCmd = SubCommandInfo::ParseFromJson(originalJson);
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

} // namespace CliTool
} // namespace OHOS
