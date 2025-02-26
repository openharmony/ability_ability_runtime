/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "mock_permission_verification.h"

#include "hidden_start_utils.h"
#include "app_utils.h"
#include "hilog_tag_wrapper.h"
#include "process_options.h"
#include "ability_manager_errors.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class HiddenStartUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HiddenStartUtilsTest::SetUpTestCase() {}

void HiddenStartUtilsTest::TearDownTestCase() {}

void HiddenStartUtilsTest::SetUp() {}

void HiddenStartUtilsTest::TearDown() {}

/* *
 * @tc.name: HiddenStartUtils_IsHiddenStart_001
 * @tc.desc: IsHiddenStart
 * @tc.type: FUNC
 */
HWTEST_F(HiddenStartUtilsTest, HiddenStartUtils_IsHiddenStart_001, TestSize.Level1)
{
    AAFwk::Want want;
    StartOptions options;
    MyFlag::flag_ = 0;
    auto utils = std::make_shared<HiddenStartUtils>();
    bool result = utils->IsHiddenStart(want, options);
    EXPECT_EQ(result, false);

    MyFlag::flag_ = 1;
    options.processOptions = nullptr;
    result = utils->IsHiddenStart(want, options);
    EXPECT_EQ(result, false);

    options.processOptions = std::make_shared<ProcessOptions>();
    options.processOptions->startupVisibility = OHOS::AAFwk::StartupVisibility::STARTUP_SHOW;
    result = utils->IsHiddenStart(want, options);
    EXPECT_EQ(result, false);

    options.processOptions->startupVisibility = OHOS::AAFwk::StartupVisibility::STARTUP_HIDE;
    result = utils->IsHiddenStart(want, options);
    EXPECT_EQ(result, true);
}

/* *
 * @tc.name: HiddenStartUtils_CheckHiddenStartSupported_001
 * @tc.desc: CheckHiddenStartSupported
 * @tc.type: FUNC
 */
HWTEST_F(HiddenStartUtilsTest, HiddenStartUtils_CheckHiddenStartSupported_001, TestSize.Level1)
{
    AAFwk::Want want;
    StartOptions options;
    auto utils = std::make_shared<HiddenStartUtils>();
    int32_t result = utils->CheckHiddenStartSupported(want, options);
    EXPECT_EQ(result, ERR_NOT_SUPPORTED_PRODUCT_TYPE);

    AppUtils::isStartOptionsWithAnimation_ = true;
    options.processOptions = nullptr;
    result = utils->CheckHiddenStartSupported(want, options);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    options.processOptions = std::make_shared<ProcessOptions>();
    options.processOptions->processMode = ProcessMode::NO_ATTACHMENT;
    result = utils->CheckHiddenStartSupported(want, options);
    EXPECT_EQ(result, ERR_OK);
}
} // namespace AAFwk
} // namespace OHOS
