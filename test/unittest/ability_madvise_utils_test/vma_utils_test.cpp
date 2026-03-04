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
#include "vma_utils.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace AbilityRuntime {
class VmaUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void VmaUtilsTest::SetUpTestCase(void)
{}

void VmaUtilsTest::TearDownTestCase(void)
{}

void VmaUtilsTest::SetUp()
{}

void VmaUtilsTest::TearDown()
{}

/**
 * @tc.number: GetFileVmas_0100
 * @tc.desc: Test GetFileVmas with vector of filenames
 * @tc.type: FUNC
 */
HWTEST_F(VmaUtilsTest, GetFileVmas_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "GetFileVmas_0100 start.");

    std::vector<std::string> filenames;
    std::vector<VmaUtil::VMARegion> result = VmaUtil::GetFileVmas(filenames);
    EXPECT_EQ(result.size(), 0);

    TAG_LOGI(AAFwkTag::TEST, "GetFileVmas_0100 end.");
}

/**
 * @tc.number: GetFileVmas_0200
 * @tc.desc: Test GetFileVmas with vector of filenames
 * @tc.type: FUNC
 */
HWTEST_F(VmaUtilsTest, GetFileVmas_0200, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "GetFileVmas_0200 start.");

    std::vector<std::string> filenames = { "testtest.hsp" };
    std::vector<VmaUtil::VMARegion> result = VmaUtil::GetFileVmas(filenames);
    EXPECT_EQ(result.size(), 0);

    TAG_LOGI(AAFwkTag::TEST, "GetFileVmas_0200 end.");
}
}  // namespace AbilityRuntime
}  // namespace OHOS
