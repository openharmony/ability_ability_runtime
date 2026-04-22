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

#include "arg_mapping.h"

using namespace testing::ext;

namespace OHOS {
namespace CliTool {

class ArgMappingTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ArgMappingTest::SetUpTestCase(void) {}
void ArgMappingTest::TearDownTestCase(void) {}
void ArgMappingTest::SetUp() {}
void ArgMappingTest::TearDown() {}

// ==================== ArgMappingType Tests ====================

/**
 * @tc.name: ArgMappingType_Value_0100
 * @tc.desc: Test ArgMappingType enum values
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMappingType_Value_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMappingType_Value_0100 start";

    EXPECT_EQ(static_cast<int32_t>(ArgMappingType::FLAG), 0);
    EXPECT_EQ(static_cast<int32_t>(ArgMappingType::POSITIONAL), 1);
    EXPECT_EQ(static_cast<int32_t>(ArgMappingType::FLATTENED), 2);
    EXPECT_EQ(static_cast<int32_t>(ArgMappingType::JSONSTRING), 3);
    EXPECT_EQ(static_cast<int32_t>(ArgMappingType::MIXED), 4);

    GTEST_LOG_(INFO) << "ArgMappingType_Value_0100 end";
}

// ==================== ArgMapping Marshalling Tests ====================

/**
 * @tc.name: ArgMapping_Marshalling_0100
 * @tc.desc: Test ArgMapping Marshalling with FLAG type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_Marshalling_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_Marshalling_0100 start";

    ArgMapping mapping;
    mapping.type = ArgMappingType::FLAG;
    mapping.separator = " ";
    mapping.order = "";
    mapping.templates = R"({"key": "value"})";

    Parcel parcel;
    bool ret = mapping.Marshalling(parcel);

    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "ArgMapping_Marshalling_0100 end";
}

/**
 * @tc.name: ArgMapping_Marshalling_0200
 * @tc.desc: Test ArgMapping Marshalling with POSITIONAL type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_Marshalling_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_Marshalling_0200 start";

    ArgMapping mapping;
    mapping.type = ArgMappingType::POSITIONAL;
    mapping.separator = ",";
    mapping.order = "arg1,arg2,arg3";
    mapping.templates = "{}";

    Parcel parcel;
    bool ret = mapping.Marshalling(parcel);

    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "ArgMapping_Marshalling_0200 end";
}

/**
 * @tc.name: ArgMapping_Marshalling_0300
 * @tc.desc: Test ArgMapping Marshalling with FLATTENED type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_Marshalling_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_Marshalling_0300 start";

    ArgMapping mapping;
    mapping.type = ArgMappingType::FLATTENED;
    mapping.separator = ";";
    mapping.order = "";
    mapping.templates = R"({"args": "--arg={value}"})";

    Parcel parcel;
    bool ret = mapping.Marshalling(parcel);

    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "ArgMapping_Marshalling_0300 end";
}

/**
 * @tc.name: ArgMapping_Marshalling_0400
 * @tc.desc: Test ArgMapping Marshalling with JSONSTRING type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_Marshalling_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_Marshalling_0400 start";

    ArgMapping mapping;
    mapping.type = ArgMappingType::JSONSTRING;
    mapping.separator = "";
    mapping.order = "";
    mapping.templates = R"({"input": {"type": "object"}})";

    Parcel parcel;
    bool ret = mapping.Marshalling(parcel);

    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "ArgMapping_Marshalling_0400 end";
}

/**
 * @tc.name: ArgMapping_Marshalling_0500
 * @tc.desc: Test ArgMapping Marshalling with MIXED type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_Marshalling_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_Marshalling_0500 start";

    ArgMapping mapping;
    mapping.type = ArgMappingType::MIXED;
    mapping.separator = "|";
    mapping.order = "verbose,output";
    mapping.templates = R"({"verbose": {"if_true": "-v"}})";

    Parcel parcel;
    bool ret = mapping.Marshalling(parcel);

    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "ArgMapping_Marshalling_0500 end";
}

/**
 * @tc.name: ArgMapping_Marshalling_0600
 * @tc.desc: Test ArgMapping Marshalling with empty strings
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_Marshalling_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_Marshalling_0600 start";

    ArgMapping mapping;
    mapping.type = ArgMappingType::FLAG;
    mapping.separator = "";
    mapping.order = "";
    mapping.templates = "";

    Parcel parcel;
    bool ret = mapping.Marshalling(parcel);

    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "ArgMapping_Marshalling_0600 end";
}

/**
 * @tc.name: ArgMapping_Marshalling_0700
 * @tc.desc: Test ArgMapping Marshalling with all types in loop
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_Marshalling_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_Marshalling_0700 start";

    std::vector<ArgMappingType> types = {
        ArgMappingType::FLAG,
        ArgMappingType::POSITIONAL,
        ArgMappingType::FLATTENED,
        ArgMappingType::JSONSTRING,
        ArgMappingType::MIXED
    };

    for (auto type : types) {
        ArgMapping mapping;
        mapping.type = type;
        mapping.separator = ",";
        mapping.order = "a,b,c";
        mapping.templates = "{}";

        Parcel parcel;
        bool ret = mapping.Marshalling(parcel);
        EXPECT_TRUE(ret);
    }

    GTEST_LOG_(INFO) << "ArgMapping_Marshalling_0700 end";
}

// ==================== ArgMapping Unmarshalling Tests ====================

/**
 * @tc.name: ArgMapping_Unmarshalling_0100
 * @tc.desc: Test ArgMapping Unmarshalling success with FLAG type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_Unmarshalling_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_Unmarshalling_0100 start";

    ArgMapping original;
    original.type = ArgMappingType::FLAG;
    original.separator = " ";
    original.order = "";
    original.templates = R"({"key": "value"})";

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    ArgMapping *result = ArgMapping::Unmarshalling(parcel);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->type, ArgMappingType::FLAG);
    EXPECT_EQ(result->separator, " ");
    EXPECT_EQ(result->order, "");
    EXPECT_EQ(result->templates, R"({"key": "value"})");

    delete result;

    GTEST_LOG_(INFO) << "ArgMapping_Unmarshalling_0100 end";
}

/**
 * @tc.name: ArgMapping_Unmarshalling_0200
 * @tc.desc: Test ArgMapping Unmarshalling success with POSITIONAL type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_Unmarshalling_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_Unmarshalling_0200 start";

    ArgMapping original;
    original.type = ArgMappingType::POSITIONAL;
    original.separator = ",";
    original.order = "arg1,arg2";
    original.templates = R"({"target": "--target={value}"})";

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    ArgMapping *result = ArgMapping::Unmarshalling(parcel);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->type, ArgMappingType::POSITIONAL);
    EXPECT_EQ(result->separator, ",");
    EXPECT_EQ(result->order, "arg1,arg2");
    EXPECT_EQ(result->templates, R"({"target": "--target={value}"})");

    delete result;

    GTEST_LOG_(INFO) << "ArgMapping_Unmarshalling_0200 end";
}

/**
 * @tc.name: ArgMapping_Unmarshalling_0300
 * @tc.desc: Test ArgMapping Unmarshalling fail with empty parcel
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_Unmarshalling_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_Unmarshalling_0300 start";

    Parcel parcel;
    ArgMapping *result = ArgMapping::Unmarshalling(parcel);

    EXPECT_EQ(result, nullptr);

    GTEST_LOG_(INFO) << "ArgMapping_Unmarshalling_0300 end";
}

/**
 * @tc.name: ArgMapping_Unmarshalling_0400
 * @tc.desc: Test ArgMapping Unmarshalling fail with partial data (missing type)
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_Unmarshalling_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_Unmarshalling_0400 start";

    Parcel parcel;
    // Only write separator, not type
    parcel.WriteString("separator");

    parcel.RewindRead(0);
    ArgMapping *result = ArgMapping::Unmarshalling(parcel);

    EXPECT_EQ(result, nullptr);

    GTEST_LOG_(INFO) << "ArgMapping_Unmarshalling_0400 end";
}

/**
 * @tc.name: ArgMapping_Unmarshalling_0500
 * @tc.desc: Test ArgMapping Unmarshalling fail with partial data (missing templates)
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_Unmarshalling_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_Unmarshalling_0500 start";

    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(ArgMappingType::FLAG));
    parcel.WriteString(" ");
    parcel.WriteString("");

    parcel.RewindRead(0);
    ArgMapping *result = ArgMapping::Unmarshalling(parcel);

    EXPECT_EQ(result, nullptr);

    GTEST_LOG_(INFO) << "ArgMapping_Unmarshalling_0500 end";
}

// ==================== ArgMapping Round Trip Tests ====================

/**
 * @tc.name: ArgMapping_RoundTrip_0100
 * @tc.desc: Test ArgMapping Marshalling and Unmarshalling round trip with MIXED type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_RoundTrip_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_RoundTrip_0100 start";

    ArgMapping original;
    original.type = ArgMappingType::MIXED;
    original.separator = "|";
    original.order = "x,y,z";
    original.templates = R"({"verbose": {"if_true": "-v", "if_false": ""}})";

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    ArgMapping *restored = ArgMapping::Unmarshalling(parcel);

    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->type, original.type);
    EXPECT_EQ(restored->separator, original.separator);
    EXPECT_EQ(restored->order, original.order);
    EXPECT_EQ(restored->templates, original.templates);

    delete restored;

    GTEST_LOG_(INFO) << "ArgMapping_RoundTrip_0100 end";
}

/**
 * @tc.name: ArgMapping_RoundTrip_0200
 * @tc.desc: Test ArgMapping round trip with FLATTENED type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_RoundTrip_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_RoundTrip_0200 start";

    ArgMapping original;
    original.type = ArgMappingType::FLATTENED;
    original.separator = ";";
    original.order = "input,output";
    original.templates = R"({"input": "--input={value}", "output": "--output={value}"})";

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    ArgMapping *restored = ArgMapping::Unmarshalling(parcel);

    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->type, original.type);
    EXPECT_EQ(restored->separator, original.separator);
    EXPECT_EQ(restored->order, original.order);
    EXPECT_EQ(restored->templates, original.templates);

    delete restored;

    GTEST_LOG_(INFO) << "ArgMapping_RoundTrip_0200 end";
}

/**
 * @tc.name: ArgMapping_RoundTrip_0300
 * @tc.desc: Test ArgMapping round trip with JSONSTRING type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_RoundTrip_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_RoundTrip_0300 start";

    ArgMapping original;
    original.type = ArgMappingType::JSONSTRING;
    original.separator = "";
    original.order = "";
    original.templates = R"({"complex": {"nested": {"key": "value"}}})";

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    ArgMapping *restored = ArgMapping::Unmarshalling(parcel);

    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->type, original.type);
    EXPECT_EQ(restored->separator, original.separator);
    EXPECT_EQ(restored->order, original.order);
    EXPECT_EQ(restored->templates, original.templates);

    delete restored;

    GTEST_LOG_(INFO) << "ArgMapping_RoundTrip_0300 end";
}

/**
 * @tc.name: ArgMapping_RoundTrip_0400
 * @tc.desc: Test ArgMapping round trip with empty strings
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_RoundTrip_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_RoundTrip_0400 start";

    ArgMapping original;
    original.type = ArgMappingType::FLAG;
    original.separator = "";
    original.order = "";
    original.templates = "";

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    parcel.RewindRead(0);
    ArgMapping *restored = ArgMapping::Unmarshalling(parcel);

    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->type, original.type);
    EXPECT_EQ(restored->separator, original.separator);
    EXPECT_EQ(restored->order, original.order);
    EXPECT_EQ(restored->templates, original.templates);

    delete restored;

    GTEST_LOG_(INFO) << "ArgMapping_RoundTrip_0400 end";
}

/**
 * @tc.name: ArgMapping_RoundTrip_0500
 * @tc.desc: Test ArgMapping round trip with all types
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_RoundTrip_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_RoundTrip_0500 start";

    std::vector<ArgMappingType> types = {
        ArgMappingType::FLAG,
        ArgMappingType::POSITIONAL,
        ArgMappingType::FLATTENED,
        ArgMappingType::JSONSTRING,
        ArgMappingType::MIXED
    };

    for (auto type : types) {
        ArgMapping original;
        original.type = type;
        original.separator = ",";
        original.order = "a,b,c";
        original.templates = "{}";

        Parcel parcel;
        ASSERT_TRUE(original.Marshalling(parcel));

        parcel.RewindRead(0);
        ArgMapping *restored = ArgMapping::Unmarshalling(parcel);

        ASSERT_NE(restored, nullptr);
        EXPECT_EQ(restored->type, original.type);
        EXPECT_EQ(restored->separator, original.separator);
        EXPECT_EQ(restored->order, original.order);
        EXPECT_EQ(restored->templates, original.templates);

        delete restored;
    }

    GTEST_LOG_(INFO) << "ArgMapping_RoundTrip_0500 end";
}

// ==================== ArgMapping Default Values Tests ====================

/**
 * @tc.name: ArgMapping_DefaultValues_0100
 * @tc.desc: Test ArgMapping default values
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_DefaultValues_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_DefaultValues_0100 start";

    ArgMapping mapping;

    EXPECT_EQ(mapping.type, ArgMappingType::FLAG);
    EXPECT_EQ(mapping.separator, "");
    EXPECT_EQ(mapping.order, "");
    EXPECT_EQ(mapping.templates, "");

    GTEST_LOG_(INFO) << "ArgMapping_DefaultValues_0100 end";
}

// ==================== ArgMapping ParseFromJson Tests ====================

/**
 * @tc.name: ArgMapping_ParseFromJson_0100
 * @tc.desc: Test ArgMapping_ParseFromJson with FLAG type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_ParseFromJson_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_ParseFromJson_0100 start";

    nlohmann::json json = {
        {"type", "flag"},
        {"separator", " "},
        {"order", "arg1,arg2"},
        {"templates", {{"key", "value"}}}
    };

    auto result = ArgMapping::ParseFromJson(json);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->type, ArgMappingType::FLAG);
    EXPECT_EQ(result->separator, " ");
    EXPECT_EQ(result->order, "arg1,arg2");

    GTEST_LOG_(INFO) << "ArgMapping_ParseFromJson_0100 end";
}

/**
 * @tc.name: ArgMapping_ParseFromJson_0200
 * @tc.desc: Test ArgMapping_ParseFromJson with POSITIONAL type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_ParseFromJson_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_ParseFromJson_0200 start";

    nlohmann::json json = {
        {"type", "positional"},
        {"separator", ","},
        {"order", "a,b,c"}
    };

    auto result = ArgMapping::ParseFromJson(json);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->type, ArgMappingType::POSITIONAL);
    EXPECT_EQ(result->separator, ",");
    EXPECT_EQ(result->order, "a,b,c");

    GTEST_LOG_(INFO) << "ArgMapping_ParseFromJson_0200 end";
}

/**
 * @tc.name: ArgMapping_ParseFromJson_0300
 * @tc.desc: Test ArgMapping_ParseFromJson with FLATTENED type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_ParseFromJson_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_ParseFromJson_0300 start";

    nlohmann::json json = {
        {"type", "flattened"},
        {"separator", ";"}
    };

    auto result = ArgMapping::ParseFromJson(json);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->type, ArgMappingType::FLATTENED);
    EXPECT_EQ(result->separator, ";");

    GTEST_LOG_(INFO) << "ArgMapping_ParseFromJson_0300 end";
}

/**
 * @tc.name: ArgMapping_ParseFromJson_0400
 * @tc.desc: Test ArgMapping_ParseFromJson with JSONSTRING type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_ParseFromJson_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_ParseFromJson_0400 start";

    nlohmann::json json = {
        {"type", "jsonString"}
    };

    auto result = ArgMapping::ParseFromJson(json);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->type, ArgMappingType::JSONSTRING);

    GTEST_LOG_(INFO) << "ArgMapping_ParseFromJson_0400 end";
}

/**
 * @tc.name: ArgMapping_ParseFromJson_0500
 * @tc.desc: Test ArgMapping_ParseFromJson with MIXED type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_ParseFromJson_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_ParseFromJson_0500 start";

    nlohmann::json json = {
        {"type", "mixed"},
        {"separator", "|"},
        {"order", "x,y,z"}
    };

    auto result = ArgMapping::ParseFromJson(json);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->type, ArgMappingType::MIXED);
    EXPECT_EQ(result->separator, "|");
    EXPECT_EQ(result->order, "x,y,z");

    GTEST_LOG_(INFO) << "ArgMapping_ParseFromJson_0500 end";
}

/**
 * @tc.name: ArgMapping_ParseFromJson_0600
 * @tc.desc: Test ArgMapping_ParseFromJson with empty json
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_ParseFromJson_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_ParseFromJson_0600 start";

    nlohmann::json json = {};

    auto result = ArgMapping::ParseFromJson(json);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->type, ArgMappingType::FLAG);  // default value
    EXPECT_EQ(result->separator, "");
    EXPECT_EQ(result->order, "");

    GTEST_LOG_(INFO) << "ArgMapping_ParseFromJson_0600 end";
}

/**
 * @tc.name: ArgMapping_ParseFromJson_0700
 * @tc.desc: Test ArgMapping_ParseFromJson with templates as object
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_ParseFromJson_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_ParseFromJson_0700 start";

    nlohmann::json json = {
        {"type", "flag"},
        {"templates", {{"verbose", {{"if_true", "-v"}}}}}
    };

    auto result = ArgMapping::ParseFromJson(json);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->type, ArgMappingType::FLAG);
    EXPECT_FALSE(result->templates.empty());

    GTEST_LOG_(INFO) << "ArgMapping_ParseFromJson_0700 end";
}

// ==================== ArgMapping ParseToJson Tests ====================

/**
 * @tc.name: ArgMapping_ParseToJson_0100
 * @tc.desc: Test ArgMapping::ParseToJson with FLAG type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_ParseToJson_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_ParseToJson_0100 start";

    ArgMapping mapping;
    mapping.type = ArgMappingType::FLAG;
    mapping.separator = " ";
    mapping.order = "arg1";
    mapping.templates = R"({"key": "value"})";

    nlohmann::json json = mapping.ParseToJson();

    EXPECT_TRUE(json.contains("type"));
    EXPECT_EQ(json["type"], "flag");
    EXPECT_TRUE(json.contains("separator"));
    EXPECT_EQ(json["separator"], " ");
    EXPECT_TRUE(json.contains("order"));
    EXPECT_EQ(json["order"], "arg1");

    GTEST_LOG_(INFO) << "ArgMapping_ParseToJson_0100 end";
}

/**
 * @tc.name: ArgMapping_ParseToJson_0200
 * @tc.desc: Test ArgMapping_ParseToJson with POSITIONAL type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_ParseToJson_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_ParseToJson_0200 start";

    ArgMapping mapping;
    mapping.type = ArgMappingType::POSITIONAL;
    mapping.separator = ",";
    mapping.order = "a,b,c";

    nlohmann::json json = mapping.ParseToJson();

    EXPECT_EQ(json["type"], "positional");
    EXPECT_EQ(json["separator"], ",");
    EXPECT_EQ(json["order"], "a,b,c");

    GTEST_LOG_(INFO) << "ArgMapping_ParseToJson_0200 end";
}

/**
 * @tc.name: ArgMapping_ParseToJson_0300
 * @tc.desc: Test ArgMapping_ParseToJson with FLATTENED type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_ParseToJson_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_ParseToJson_0300 start";

    ArgMapping mapping;
    mapping.type = ArgMappingType::FLATTENED;
    mapping.separator = ";";

    nlohmann::json json = mapping.ParseToJson();

    EXPECT_EQ(json["type"], "flattened");
    EXPECT_EQ(json["separator"], ";");

    GTEST_LOG_(INFO) << "ArgMapping_ParseToJson_0300 end";
}

/**
 * @tc.name: ArgMapping_ParseToJson_0400
 * @tc.desc: Test ArgMapping_ParseToJson with JSONSTRING type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_ParseToJson_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_ParseToJson_0400 start";

    ArgMapping mapping;
    mapping.type = ArgMappingType::JSONSTRING;

    nlohmann::json json = mapping.ParseToJson();

    EXPECT_EQ(json["type"], "jsonString");

    GTEST_LOG_(INFO) << "ArgMapping_ParseToJson_0400 end";
}

/**
 * @tc.name: ArgMapping_ParseToJson_0500
 * @tc.desc: Test ArgMapping_ParseToJson with MIXED type
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_ParseToJson_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_ParseToJson_0500 start";

    ArgMapping mapping;
    mapping.type = ArgMappingType::MIXED;
    mapping.separator = "|";
    mapping.order = "x,y,z";

    nlohmann::json json = mapping.ParseToJson();

    EXPECT_EQ(json["type"], "mixed");
    EXPECT_EQ(json["separator"], "|");
    EXPECT_EQ(json["order"], "x,y,z");

    GTEST_LOG_(INFO) << "ArgMapping_ParseToJson_0500 end";
}

/**
 * @tc.name: ArgMapping_ParseToJson_0600
 * @tc.desc: Test ArgMapping_ParseToJson with empty fields
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_ParseToJson_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_ParseToJson_0600 start";

    ArgMapping mapping;
    mapping.type = ArgMappingType::FLAG;
    mapping.separator = "";
    mapping.order = "";
    mapping.templates = "";

    nlohmann::json json = mapping.ParseToJson();

    EXPECT_EQ(json["type"], "flag");
    EXPECT_FALSE(json.contains("separator"));  // empty string not included
    EXPECT_FALSE(json.contains("order"));      // empty string not included
    EXPECT_FALSE(json.contains("templates"));  // empty string not included

    GTEST_LOG_(INFO) << "ArgMapping_ParseToJson_0600 end";
}

/**
 * @tc.name: ArgMapping_ParseToJson_0700
 * @tc.desc: Test ArgMapping_ParseToJson with templates as JSON object
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_ParseToJson_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_ParseToJson_0700 start";

    ArgMapping mapping;
    mapping.type = ArgMappingType::FLAG;
    mapping.templates = R"({"verbose": {"if_true": "-v"}})";

    nlohmann::json json = mapping.ParseToJson();

    EXPECT_EQ(json["type"], "flag");
    EXPECT_TRUE(json.contains("templates"));
    EXPECT_TRUE(json["templates"].is_object());

    GTEST_LOG_(INFO) << "ArgMapping_ParseToJson_0700 end";
}

// ==================== ArgMapping_ParseFromJson and ArgMapping_ParseToJson Round Trip Tests ====================

/**
 * @tc.name: ArgMapping_JsonRoundTrip_0100
 * @tc.desc: Test ArgMapping_ParseFromJson and ArgMapping_ParseToJson round trip
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_JsonRoundTrip_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_JsonRoundTrip_0100 start";

    ArgMapping original;
    original.type = ArgMappingType::MIXED;
    original.separator = "|";
    original.order = "x,y,z";
    original.templates = R"({"verbose": {"if_true": "-v"}})";

    nlohmann::json json = original.ParseToJson();
    auto restored = ArgMapping::ParseFromJson(json);

    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->type, original.type);
    EXPECT_EQ(restored->separator, original.separator);
    EXPECT_EQ(restored->order, original.order);

    GTEST_LOG_(INFO) << "ArgMapping_JsonRoundTrip_0100 end";
}

/**
 * @tc.name: ArgMapping_JsonRoundTrip_0200
 * @tc.desc: Test ArgMapping_ParseFromJson and ArgMapping_ParseToJson round trip with all types
 * @tc.type: FUNC
 */
HWTEST_F(ArgMappingTest, ArgMapping_JsonRoundTrip_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ArgMapping_JsonRoundTrip_0200 start";

    std::vector<ArgMappingType> types = {
        ArgMappingType::FLAG,
        ArgMappingType::POSITIONAL,
        ArgMappingType::FLATTENED,
        ArgMappingType::JSONSTRING,
        ArgMappingType::MIXED
    };

    for (auto type : types) {
        ArgMapping original;
        original.type = type;
        original.separator = ",";
        original.order = "a,b,c";
        original.templates = R"({"key": "value"})";

        nlohmann::json json = original.ParseToJson();
        auto restored = ArgMapping::ParseFromJson(json);

        ASSERT_NE(restored, nullptr);
        EXPECT_EQ(restored->type, original.type);
        EXPECT_EQ(restored->separator, original.separator);
        EXPECT_EQ(restored->order, original.order);
    }

    GTEST_LOG_(INFO) << "ArgMapping_JsonRoundTrip_0200 end";
}

} // namespace CliTool
} // namespace OHOS