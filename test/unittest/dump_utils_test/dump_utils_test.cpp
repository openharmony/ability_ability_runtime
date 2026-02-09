/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "utils/dump_utils.h"
#include "hilog_tag_wrapper.h"
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class DumpUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DumpUtilsTest::SetUpTestCase() {}

void DumpUtilsTest::TearDownTestCase() {}

void DumpUtilsTest::SetUp() {}

void DumpUtilsTest::TearDown() {}

/*
 * Feature: DumpUtils
 * Function: DumpMapOne
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpMapOne
 */
HWTEST_F(DumpUtilsTest, DumpMapOne_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_001 start");
    DumpUtils info;
    std::string argString ="-a";
    auto result = info.DumpMapOne(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_ALL);
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_001 end");
}

/*
 * Feature: DumpUtils
 * Function: DumpMapOne
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpMapOne
 */
HWTEST_F(DumpUtilsTest, DumpMapOne_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_002 start");
    DumpUtils info;
    std::string argString ="--stack-list";
    auto result = info.DumpMapOne(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_STACK_LIST);
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_002 end");
}

/*
 * Feature: DumpUtils
 * Function: DumpMapOne
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpMapOne
 */
HWTEST_F(DumpUtilsTest, DumpMapOne_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_003 start");
    DumpUtils info;
    std::string argString ="--stack";
    auto result = info.DumpMapOne(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_STACK);
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_003 end");
}

/*
 * Feature: DumpUtils
 * Function: DumpMapOne
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpMapOne
 */
HWTEST_F(DumpUtilsTest, DumpMapOne_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_004 start");
    DumpUtils info;
    std::string argString ="--mission";
    auto result = info.DumpMapOne(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_MISSION);
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_004 end");
}

/*
 * Feature: DumpUtils
 * Function: DumpMapOne
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpMapOne
 */
HWTEST_F(DumpUtilsTest, DumpMapOne_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_005 start");
    DumpUtils info;
    std::string argString ="--top";
    auto result = info.DumpMapOne(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_TOP_ABILITY);
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_005 end");
}

/*
 * Feature: DumpUtils
 * Function: DumpMapOne
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpMapOne
 */
HWTEST_F(DumpUtilsTest, DumpMapOne_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_006 start");
    DumpUtils info;
    std::string argString ="--waiting-queue";
    auto result = info.DumpMapOne(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_WAIT_QUEUE);
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_006 end");
}

/*
 * Feature: DumpUtils
 * Function: DumpMapOne
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpMapOne
 */
HWTEST_F(DumpUtilsTest, DumpMapOne_007, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_007 start");
    DumpUtils info;
    std::string argString ="-e";
    auto result = info.DumpMapOne(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_SERVICE);
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_007 end");
}

/*
 * Feature: DumpUtils
 * Function: DumpMapOne
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpMapOne
 */
HWTEST_F(DumpUtilsTest, DumpMapOne_008, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_008 start");
    DumpUtils info;
    std::string argString ="--data";
    auto result = info.DumpMapOne(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_DATA);
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_008 end");
}

/*
 * Feature: DumpUtils
 * Function: DumpMapOne
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpMapOne
 */
HWTEST_F(DumpUtilsTest, DumpMapOne_009, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_009 start");
    DumpUtils info;
    std::string argString ="-focus";
    auto result = info.DumpMapOne(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_FOCUS_ABILITY);
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapOne_009 end");
}

/*
 * Feature: DumpUtils
 * Function: DumpMapTwo
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpMapTwo
 */
HWTEST_F(DumpUtilsTest, DumpMapTwo_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapTwo_001 start");
    DumpUtils info;
    std::string argString ="-z";
    auto result = info.DumpMapTwo(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_WINDOW_MODE);
    
    argString ="-L";
    result = info.DumpMapTwo(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_MISSION_LIST);

    argString ="-S";
    result = info.DumpMapTwo(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_MISSION_INFOS);
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMapTwo_001 end");
}

/*
 * Feature: DumpUtils
 * Function: DumpsysMap
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpsysMap
 */
HWTEST_F(DumpUtilsTest, DumpsysMap_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpsysMap_001 start");
    DumpUtils info;
    std::string argString ="-a";
    auto result = info.DumpsysMap(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_SYS_ALL);
    
    argString ="-l";
    result = info.DumpsysMap(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_SYS_MISSION_LIST);

    argString ="-i";
    result = info.DumpsysMap(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_SYS_ABILITY);
    
    argString ="-e";
    result = info.DumpsysMap(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_SYS_SERVICE);
    
    argString ="-p";
    result = info.DumpsysMap(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_SYS_PENDING);
    
    argString ="-r";
    result = info.DumpsysMap(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_SYS_PROCESS);
    
    argString ="-d";
    result = info.DumpsysMap(argString);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, DumpUtils::KEY_DUMP_SYS_DATA);
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpsysMap_001 end");
}

/*
 * Feature: DumpUtils
 * Function: DumpMap
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpMap
 */
HWTEST_F(DumpUtilsTest, DumpMap_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMap_001 start");
    DumpUtils info;
    std::string argString ="-a";
    auto result = info.DumpMap(argString);
    EXPECT_TRUE(result.first);
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMap_001 end");
}

/*
 * Feature: DumpUtils
 * Function: DumpMap
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpMap
 */
HWTEST_F(DumpUtilsTest, DumpMap_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMap_002 start");
    DumpUtils info;
    std::string argString ="-z";
    auto result = info.DumpMap(argString);
    EXPECT_TRUE(result.first);
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMap_002 end");
}

/*
 * Feature: DumpUtils
 * Function: DumpMap
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpMap
 */
HWTEST_F(DumpUtilsTest, DumpMap_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMap_003 start");
    DumpUtils info;
    std::string argString ="-b";
    auto result = info.DumpMap(argString);
    EXPECT_FALSE(result.first);
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest DumpMap_003 end");
}

/*
 * Feature: DumpUtils
 * Function: ShowHelp
 * SubFunction: NA
 * FunctionPoints: DumpUtils ShowHelp
 */
HWTEST_F(DumpUtilsTest, ShowHelp_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest ShowHelp_001 start");
    std::string result;
    DumpUtils::ShowHelp(result);

    // Check that help text contains expected content
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("Usage:"), std::string::npos);
    EXPECT_NE(result.find("-h"), std::string::npos);
    EXPECT_NE(result.find("help text for the tool"), std::string::npos);
    EXPECT_NE(result.find("-a"), std::string::npos);
    EXPECT_NE(result.find("-l"), std::string::npos);
    EXPECT_NE(result.find("-i"), std::string::npos);
    EXPECT_NE(result.find("-e"), std::string::npos);
    EXPECT_NE(result.find("-p"), std::string::npos);
    EXPECT_NE(result.find("-r"), std::string::npos);
    EXPECT_NE(result.find("-d"), std::string::npos);

    // Verify that "information" is spelled correctly (not "infomation")
    EXPECT_EQ(result.find("infomation"), std::string::npos);
    EXPECT_NE(result.find("information"), std::string::npos);

    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest ShowHelp_001 end");
}

/*
 * Feature: DumpUtils
 * Function: ShowHelp
 * SubFunction: NA
 * FunctionPoints: DumpUtils ShowHelp
 */
HWTEST_F(DumpUtilsTest, ShowHelp_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest ShowHelp_002 start");
    std::string result = "Initial content\n";
    DumpUtils::ShowHelp(result);

    // Check that help text is appended to existing content
    EXPECT_NE(result.find("Initial content"), std::string::npos);
    EXPECT_NE(result.find("Usage:"), std::string::npos);

    TAG_LOGI(AAFwkTag::TEST, "DumpUtilsTest ShowHelp_002 end");
}
} // namespace AAFwk
} // namespace OHOS