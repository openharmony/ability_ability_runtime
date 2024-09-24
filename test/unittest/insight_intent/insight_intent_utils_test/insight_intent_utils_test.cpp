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

#include "ability_manager_errors.h"
#include "bundle_mgr_helper.h"
#include "hilog_tag_wrapper.h"
#include "want_params_wrapper.h"
#include "insight_intent_utils.h"
#include "int_wrapper.h"
#include "insight_intent_profile.h"
#include "string_wrapper.h"
#include "want.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
namespace {
const std::string TEST_BUNDLE_NAME = "testBundleName";
const std::string TEST_ABILITY_NAME = "testAbilityName";
const std::string TEST_MODULE_NAME = "testModuleName";
const std::string TEST_INTENT_NAME = "testIntentName";
std::string TEST_SRC_ENTRY = "entry";
}
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
    AppExecFwk::ElementName element1("", TEST_BUNDLE_NAME, TEST_ABILITY_NAME, TEST_MODULE_NAME);
    auto result = utils.GetSrcEntry(element1, TEST_INTENT_NAME, ExecuteMode::SERVICE_EXTENSION_ABILITY,
        TEST_SRC_ENTRY);
    EXPECT_EQ(result, ERR_INSIGHT_INTENT_GET_PROFILE_FAILED);
    AppExecFwk::ElementName element2("", TEST_BUNDLE_NAME, TEST_ABILITY_NAME, "");
    result = utils.GetSrcEntry(element2, TEST_INTENT_NAME, ExecuteMode::SERVICE_EXTENSION_ABILITY, TEST_SRC_ENTRY);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    AppExecFwk::ElementName element3("", TEST_BUNDLE_NAME, "", TEST_MODULE_NAME);
    result = utils.GetSrcEntry(element3, TEST_INTENT_NAME, ExecuteMode::SERVICE_EXTENSION_ABILITY, TEST_SRC_ENTRY);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    AppExecFwk::ElementName element4("", "", TEST_BUNDLE_NAME, TEST_MODULE_NAME);
    result = utils.GetSrcEntry(element4, TEST_INTENT_NAME, ExecuteMode::SERVICE_EXTENSION_ABILITY, TEST_SRC_ENTRY);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "InsightIntentUtilsTest GetSrcEntry_0100 end.");
}
} // namespace AAFwk
} // namespace OHOS
