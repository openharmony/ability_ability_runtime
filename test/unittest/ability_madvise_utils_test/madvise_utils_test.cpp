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

#include "hilog_tag_wrapper.h"
#include "madvise_utils.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace AbilityRuntime {
class MadviseUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void MadviseUtilsTest::SetUpTestCase(void)
{}

void MadviseUtilsTest::TearDownTestCase(void)
{}

void MadviseUtilsTest::SetUp()
{}

void MadviseUtilsTest::TearDown()
{}

/**
 * @tc.number: MadviseSingleLibrary_0100
 * @tc.desc: Test MadviseSingleLibrary works
 * @tc.type: FUNC
 */
HWTEST_F(MadviseUtilsTest, MadviseSingleLibrary_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "MadviseSingleLibrary_0100 start.");

    const char* libName = "";
    bool result = MadviseUtil::MadviseSingleLibrary(libName);
    EXPECT_EQ(result, false);

    TAG_LOGI(AAFwkTag::TEST, "MadviseSingleLibrary_0100 end.");
}

/**
 * @tc.number: MadviseSingleLibrary_0200
 * @tc.desc: Test MadviseSingleLibrary works
 * @tc.type: FUNC
 */
HWTEST_F(MadviseUtilsTest, MadviseSingleLibrary_0200, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "MadviseSingleLibrary_0200 start.");

    const char* libName = "testtest.so";
    bool result = MadviseUtil::MadviseSingleLibrary(libName);
    EXPECT_EQ(result, false);

    TAG_LOGI(AAFwkTag::TEST, "MadviseSingleLibrary_0200 end.");
}

/**
 * @tc.number: MadviseGeneralFiles_0100
 * @tc.desc: Test MadviseGeneralFiles works
 * @tc.type: FUNC
 */
HWTEST_F(MadviseUtilsTest, MadviseGeneralFiles_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "MadviseGeneralFiles_0100 start.");

    std::vector<std::string> filenames ;
    int32_t result = MadviseUtil::MadviseGeneralFiles(filenames);
    EXPECT_EQ(result, 0);

    TAG_LOGI(AAFwkTag::TEST, "MadviseGeneralFiles_0100 end.");
}

/**
 * @tc.number: MadviseGeneralFiles_0200
 * @tc.desc: Test MadviseGeneralFiles works
 * @tc.type: FUNC
 */
HWTEST_F(MadviseUtilsTest, MadviseGeneralFiles_0200, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "MadviseGeneralFiles_0200 start.");

    std::vector<std::string> filenames = { "testtest.hsp" };
    int32_t result = MadviseUtil::MadviseGeneralFiles(filenames);
    EXPECT_EQ(result, 0);

    TAG_LOGI(AAFwkTag::TEST, "MadviseGeneralFiles_0200 end.");
}

/**
 * @tc.number: MadviseWithConfigFile_0100
 * @tc.desc: Test MadviseWithConfigFile works
 * @tc.type: FUNC
 */
HWTEST_F(MadviseUtilsTest, MadviseWithConfigFile_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "MadviseWithConfigFile_0100 start.");

    const char* bundleName = "";
    int32_t result = MadviseUtil::MadviseWithConfigFile(bundleName);
    EXPECT_EQ(result, -1);

    TAG_LOGI(AAFwkTag::TEST, "MadviseWithConfigFile_0100 end.");
}
}  // namespace AbilityRuntime
}  // namespace OHOS
