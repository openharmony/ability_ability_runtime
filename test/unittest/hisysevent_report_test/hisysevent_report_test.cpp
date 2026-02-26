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

#include "hisysevent_report.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace AAFwk {
class HisyseventReportTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HisyseventReportTest::SetUpTestCase() {}

void HisyseventReportTest::TearDownTestCase() {}

void HisyseventReportTest::SetUp() {}

void HisyseventReportTest::TearDown() {}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_Bool
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_Bool_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_Bool_001 start";
    HisyseventReport report(64);
    report.InsertParam("bool_param", true);
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_Bool_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_Bool
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_Bool_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_Bool_002 start";
    HisyseventReport report(64);
    report.InsertParam("bool_param", false);
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_Bool_002 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_Int8
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_Int8_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_Int8_001 start";
    HisyseventReport report(64);
    report.InsertParam("int8_param", static_cast<int8_t>(100));
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_Int8_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_Uint8
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_Uint8_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_Uint8_001 start";
    HisyseventReport report(64);
    report.InsertParam("uint8_param", static_cast<uint8_t>(200));
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_Uint8_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_Int16
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_Int16_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_Int16_001 start";
    HisyseventReport report(64);
    report.InsertParam("int16_param", static_cast<int16_t>(1000));
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_Int16_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_Uint16
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_Uint16_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_Uint16_001 start";
    HisyseventReport report(64);
    report.InsertParam("uint16_param", static_cast<uint16_t>(2000));
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_Uint16_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_Int32
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_Int32_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_Int32_001 start";
    HisyseventReport report(64);
    report.InsertParam("int32_param", static_cast<int32_t>(100000));
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_Int32_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_Uint32
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_Uint32_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_Uint32_001 start";
    HisyseventReport report(64);
    report.InsertParam("uint32_param", static_cast<uint32_t>(200000));
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_Uint32_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_Int64
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_Int64_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_Int64_001 start";
    HisyseventReport report(64);
    report.InsertParam("int64_param", static_cast<int64_t>(1000000000LL));
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_Int64_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_Uint64
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_Uint64_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_Uint64_001 start";
    HisyseventReport report(64);
    report.InsertParam("uint64_param", static_cast<uint64_t>(2000000000ULL));
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_Uint64_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_Float
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_Float_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_Float_001 start";
    HisyseventReport report(64);
    report.InsertParam("float_param", 3.14f);
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_Float_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_Double
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_Double_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_Double_001 start";
    HisyseventReport report(64);
    report.InsertParam("double_param", 3.14159);
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_Double_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_String
 * SubFunction: NA
 * FunctionPoints: HisyseventReportable InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_String_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_String_001 start";
    HisyseventReport report(64);
    report.InsertParam("string_param", "test_string");
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_String_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_CharPtr
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_CharPtr_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_CharPtr_001 start";
    HisyseventReport report(64);
    char testStr[] = "test_char_ptr";
    report.InsertParam("char_ptr_param", testStr);
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_CharPtr_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_ConstCharPtr
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_ConstCharPtr_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_ConstCharPtr_001 start";
    HisyseventReport report(64);
    const char* constTestStr = "test_const_char_ptr";
    report.InsertParam("const_char_ptr_param", constTestStr);
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_ConstCharPtr_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_Int32Vector
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_Int32Vector_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_Int32Vector_001 start";
    HisyseventReport report(64);
    std::vector<int32_t> int32Vec = {1, 2, 3};
    report.InsertParam("int32_vector_param", int32Vec);
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_Int32Vector_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_Uint64Vector
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_Uint64Vector_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_Uint64Vector_001 start";
    HisyseventReport report(64);
    std::vector<uint64_t> uint64Vec = {1ULL, 2ULL, 3ULL};
    report.InsertParam("uint64_vector_param", uint64Vec);
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_Uint64Vector_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_CharPtrVector
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_CharPtrVector_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_CharPtrVector_001 start";
    HisyseventReport report(64);
    std::vector<char*> charPtrVec;
    char str1[] = "str1";
    char str2[] = "str2";
    charPtrVec.push_back(str1);
    charPtrVec.push_back(str2);
    report.InsertParam("char_ptr_vector_param", charPtrVec);
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_CharPtrVector_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_MultipleParams_001
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_MultipleParams_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_MultipleParams_001 start";
    HisyseventReport report(64);
    report.InsertParam("bool_param", true);
    report.InsertParam("int32_param", static_cast<int32_t>(100));
    report.InsertParam("string_param", "test_string");
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_MultipleParams_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: InsertParam_ExceedLimit_001
 * SubFunction: NA
 * FunctionPoints: HisyseventReport InsertParam
 */
HWTEST_F(HisyseventReportTest, InsertParam_ExceedLimit_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsertParam_ExceedLimit_001 start";
    HisyseventReport report(2);
    report.InsertParam("param1", true);
    report.InsertParam("param2", false);
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "InsertParam_ExceedLimit_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: Report
 * SubFunction: NA
 * FunctionPoints: HisyseventReport Report
 */
HWTEST_F(HisyseventReportTest, Report_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Report_001 start";
    HisyseventReport report(64);
    report.InsertParam("test_param", 100);
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "Report_001 end";
}

/**
 * Feature: HisyseventReport
 * Function: Report
 * SubFunction: NA
 * FunctionPoints: HisyseventReport Report
 */
HWTEST_F(HisyseventReportTest, Report_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Report_002 start";
    HisyseventReport report(64);
    report.InsertParam("test_param", 200);
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_SECURITY);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "Report_002 end";
}

/**
 * Feature: HisyseventReport
 * Function: Report
 * SubFunction: NA
 * FunctionPoints: HisyseventReport Report
 */
HWTEST_F(HisyseventReportTest, Report_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Report_003 start";
    HisyseventReport report(64);
    report.InsertParam("test_param", "test_value");
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_STATISTIC);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "Report_003 end";
}

/**
 * Feature: HisyseventReport
 * Function: Report_NoParams_001
 * SubFunction: NA
 * FunctionPoints: HisyseventReport Report
 */
HWTEST_F(HisyseventReportTest, Report_NoParams_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Report_NoParams_001 start";
    HisyseventReport report(64);
    int32_t ret = report.Report("test_domain", "test_event", HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "Report_NoParams_001 end";
}
}  // namespace AAFwk
}  // namespace OHOS
