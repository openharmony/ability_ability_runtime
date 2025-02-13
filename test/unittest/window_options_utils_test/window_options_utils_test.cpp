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
#include "utils/window_options_utils.h"
#include "hilog_tag_wrapper.h"
using namespace testing;
using namespace testing::ext;
using OHOS::AppExecFwk::ExtensionAbilityType;

namespace OHOS {
namespace AAFwk {
class WindowOptionsUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void WindowOptionsUtilsTest::SetUpTestCase() {}

void WindowOptionsUtilsTest::TearDownTestCase() {}

void WindowOptionsUtilsTest::SetUp() {}

void WindowOptionsUtilsTest::TearDown() {}
/*
 * Feature: WindowOptionsUtils
 * Function: SetWindowPositionAndSize
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService SetWindowPositionAndSize
 */
HWTEST_F(WindowOptionsUtilsTest, SetWindowPositionAndSize_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "WindowOptionsUtilsTest SetWindowPositionAndSize_001 start");
    Want want;
    sptr<IRemoteObject> callerToken;
    StartOptions startOptions;
    auto Window_ = std::make_shared<WindowOptionsUtils>();
    Window_->SetWindowPositionAndSize(want, callerToken, startOptions);
    EXPECT_NE(nullptr, Window_);
    TAG_LOGI(AAFwkTag::TEST, "WindowOptionsUtilsTest SetWindowPositionAndSize_001 end");
}

/*
 * Feature: WindowOptionsUtils
 * Function: SetWindowPositionAndSize
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService SetWindowPositionAndSize
 */
HWTEST_F(WindowOptionsUtilsTest, SetWindowPositionAndSize_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "WindowOptionsUtilsTest SetWindowPositionAndSize_002 start");
    Want want;
    sptr<IRemoteObject> callerToken;
    StartOptions startOptions;
    const int32_t minLength = 300;
    const int32_t maxLength = 500;
    startOptions.SetMinWindowWidth(minLength);
    startOptions.minWindowWidthUsed_ = true;
    startOptions.SetMinWindowHeight(minLength);
    startOptions.minWindowHeightUsed_ = true;
    startOptions.SetMaxWindowWidth(maxLength);
    startOptions.maxWindowWidthUsed_ = true;
    startOptions.SetMaxWindowHeight(maxLength);
    startOptions.maxWindowHeightUsed_ = true;
    auto Window_ = std::make_shared<WindowOptionsUtils>();
    ASSERT_NE(nullptr, Window_);
    Window_->SetWindowPositionAndSize(want, callerToken, startOptions);
    EXPECT_EQ(startOptions.GetMinWindowWidth(), minLength);
    EXPECT_EQ(startOptions.GetMinWindowHeight(), minLength);
    EXPECT_EQ(startOptions.GetMaxWindowWidth(), maxLength);
    EXPECT_EQ(startOptions.GetMaxWindowHeight(), maxLength);
    TAG_LOGI(AAFwkTag::TEST, "WindowOptionsUtilsTest SetWindowPositionAndSize_002 end");
}

/*
 * Feature: WindowOptionsUtils
 * Function: WindowModeMap
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService WindowModeMap
 */
HWTEST_F(WindowOptionsUtilsTest, WindowModeMap_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "WindowOptionsUtilsTest WindowModeMap_001 start");
    WindowOptionsUtils  Window_;
    int32_t windowMode = MULTI_WINDOW_DISPLAY_FULLSCREEN;
    auto result = Window_.WindowModeMap(windowMode);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, AppExecFwk::SupportWindowMode::FULLSCREEN);
    TAG_LOGI(AAFwkTag::TEST, "WindowOptionsUtilsTest WindowModeMap_001 end");
}
/*
 * Feature: WindowModeMap
 * Function: SetWindowPositionAndSize
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService WindowModeMap
 */
HWTEST_F(WindowOptionsUtilsTest, WindowModeMap_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "WindowOptionsUtilsTest WindowModeMap_002 start");
    WindowOptionsUtils  Window_;
    int32_t windowMode = MULTI_WINDOW_DISPLAY_PRIMARY;
    auto result = Window_.WindowModeMap(windowMode);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, AppExecFwk::SupportWindowMode::SPLIT);
    TAG_LOGI(AAFwkTag::TEST, "WindowOptionsUtilsTest WindowModeMap_002 end");
}
/*
 * Feature: WindowOptionsUtils
 * Function: WindowModeMap
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService WindowModeMap
 */
HWTEST_F(WindowOptionsUtilsTest, WindowModeMap_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "WindowOptionsUtilsTest WindowModeMap_003 start");
    WindowOptionsUtils  Window_;
    int32_t windowMode = MULTI_WINDOW_DISPLAY_SECONDARY;
    auto result = Window_.WindowModeMap(windowMode);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, AppExecFwk::SupportWindowMode::SPLIT);
    TAG_LOGI(AAFwkTag::TEST, "WindowOptionsUtilsTest WindowModeMap_003 end");
}
/*
 * Feature: WindowOptionsUtils
 * Function: WindowModeMap
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService WindowModeMap
 */
HWTEST_F(WindowOptionsUtilsTest, WindowModeMap_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "WindowOptionsUtilsTest WindowModeMap_004 start");
    WindowOptionsUtils  Window_;
    int32_t windowMode = MULTI_WINDOW_DISPLAY_FLOATING;
    auto result = Window_.WindowModeMap(windowMode);
    EXPECT_TRUE(result.first);
    EXPECT_EQ(result.second, AppExecFwk::SupportWindowMode::FLOATING);
    TAG_LOGI(AAFwkTag::TEST, "WindowOptionsUtilsTest WindowModeMap_004 end");
}
} // namespace AAFwk
} // namespace OHOS
