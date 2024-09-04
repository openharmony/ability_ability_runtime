/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hilog_tag_wrapper.h"
#include "want.h"
#include "want_params_wrapper.h"
#include "insight_intent_utils.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#include "bundle_mgr_helper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class InsightIntentUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void InsightIntentUtilsTest::SetUpTestCase(void)
{}

void InsightIntentUtilsTest::TearDownTestCase(void)
{}

void InsightIntentUtilsTest::SetUp()
{}

void InsightIntentUtilsTest::TearDown()
{}

/**
 * @tc.name: GetSrcEntry_0100
 * @tc.desc: basic function test of get caller info.
 * @tc.type: FUNC
 * @tc.require: issueI91RLM
 */
HWTEST_F(InsightIntentUtilsTest, GetSrcEntry_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST,  "InsightIntentUtilsTest GetSrcEntry_0100 start");
    AbilityRuntime::InsightIntentUtils utils;
    std::string bundleName;
    std::string moduleName;
    std::string intentName;
    auto result = utils.GetSrcEntry(bundleName, moduleName, intentName);
    EXPECT_EQ(result, "");
    TAG_LOGI(AAFwkTag::TEST, "InsightIntentUtilsTest GetSrcEntry_0100 end.");
}

/**
 * @tc.name: GetSrcEntry_0200
 * @tc.desc: basic function test of get caller info.
 * @tc.type: FUNC
 * @tc.require: issueI91RLM
 */
HWTEST_F(InsightIntentUtilsTest, GetSrcEntry_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST,  "InsightIntentUtilsTest GetSrcEntry_0200 start");
    AbilityRuntime::InsightIntentUtils utils;
    std::string bundleName = "bundleName";
    std::string moduleName = "moudleName";
    std::string intentName = "intentName";
    auto result = utils.GetSrcEntry(bundleName, moduleName, intentName);
    EXPECT_EQ(result, "");
    TAG_LOGI(AAFwkTag::TEST, "InsightIntentUtilsTest GetSrcEntry_0200 end.");
}
} // namespace AAFwk
} // namespace OHOS
