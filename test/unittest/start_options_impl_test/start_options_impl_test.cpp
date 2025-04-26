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

#include "gtest/gtest.h"
#define private public
#include "start_options_impl.h"
#undef private
#include "hilog_tag_wrapper.h"
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
#include "pixelmap_native_impl.h"
#endif
#include "securec.h"
#include "start_window_option.h"

using namespace testing;

constexpr int MAX_SUPPOPRT_WINDOW_MODES_SIZE = 10;

// Test suite
class StartOptionsImplTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Create a StartOptionsImpl object before each test case
        startOptions = new AbilityRuntime_StartOptions();
    }

    void TearDown() override
    {
        // Delete the StartOptionsImpl object after each test case
        delete startOptions;
        startOptions = nullptr;
    }

    // Declare a StartOptionsImpl pointer
    AbilityRuntime_StartOptions* startOptions = nullptr;
};

// Test cases
// Test SetStartOptionsWindowMode function - Normal case
/**
 * @tc.name: SetStartOptionsWindowMode_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsWindowMode_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWindowMode_001 begin");
    // Arrange
    AbilityRuntime_WindowMode windowMode = ABILITY_RUNTIME_WINDOW_MODE_FULL_SCREEN;
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->SetStartOptionsWindowMode(windowMode);
    TAG_LOGI(AAFwkTag::TEST,
        "SetStartOptionsWindowMode_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWindowMode_001 end");
}

// Test SetStartOptionsWindowMode function - Boundary case
/**
 * @tc.name: SetStartOptionsWindowMode_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsWindowMode_002, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWindowMode_002 begin");
    // Arrange
    AbilityRuntime_WindowMode windowMode = ABILITY_RUNTIME_WINDOW_MODE_UNDEFINED;
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->SetStartOptionsWindowMode(windowMode);
    TAG_LOGI(AAFwkTag::TEST,
        "SetStartOptionsWindowMode_002 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWindowMode_002 end");
}

// Test SetStartOptionsWindowMode function - Exception case
/**
 * @tc.name: SetStartOptionsWindowMode_003
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsWindowMode_003, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWindowMode_003 begin");
    // Arrange
    // Assuming 100 is outside the enum definition range
    AbilityRuntime_WindowMode windowMode = static_cast<AbilityRuntime_WindowMode>(100);
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;

    // Act
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->SetStartOptionsWindowMode(windowMode);
    TAG_LOGI(AAFwkTag::TEST,
        "SetStartOptionsWindowMode_003 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWindowMode_003 end");
}

// Test cases
// Test GetStartOptionsWindowMode function - Normal case
/**
 * @tc.name: GetStartOptionsWindowMode_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsWindowMode_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowMode_001 begin");
    // Arrange
    AbilityRuntime_WindowMode expectedWindowMode = ABILITY_RUNTIME_WINDOW_MODE_FULL_SCREEN;
    startOptions->SetStartOptionsWindowMode(expectedWindowMode);
    AbilityRuntime_WindowMode windowMode;
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsWindowMode(windowMode);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsWindowMode_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedWindowMode, windowMode);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowMode_001 end");
}

// Test cases
// Test SetStartOptionsDisplayId function - Normal case
/**
 * @tc.name: SetStartOptionsDisplayId_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsDisplayId_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsDisplayId_001 begin");
    // Arrange
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t displayId = 10;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->SetStartOptionsDisplayId(displayId);
    TAG_LOGI(AAFwkTag::TEST,
        "SetStartOptionsDisplayId_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsDisplayId_001 end");
}

// Test cases
// Test GetStartOptionsDisplayId function - Normal case
/**
 * @tc.name: GetStartOptionsDisplayId_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsDisplayId_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsDisplayId_001 begin");
    // Arrange
    int32_t expectedDisplayId = 10;
    startOptions->SetStartOptionsDisplayId(expectedDisplayId);
    int32_t displayId;
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsDisplayId(displayId);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsDisplayId_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedDisplayId, displayId);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsDisplayId_001 end");
}

// Test cases
// Test SetStartOptionsWithAnimation function - Normal case
/**
 * @tc.name: SetStartOptionsWithAnimation_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsWithAnimation_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWithAnimation_001 begin");
    // Arrange
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->SetStartOptionsWithAnimation(true);
    TAG_LOGI(AAFwkTag::TEST,
        "SetStartOptionsWithAnimation_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWithAnimation_001 end");
}

// Test cases
// Test GetStartOptionsWithAnimation function - Normal case
/**
 * @tc.name: GetStartOptionsWithAnimation_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsWithAnimation_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWithAnimation_001 begin");
    // Arrange
    bool expectedWithAnimation = true;
    startOptions->SetStartOptionsWithAnimation(expectedWithAnimation);
    bool withAnimation;
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsWithAnimation(withAnimation);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsWithAnimation_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedWithAnimation, withAnimation);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWithAnimation_001 end");
}

// Test cases
// Test SetStartOptionsWindowLeft function - Normal case
/**
 * @tc.name: SetStartOptionsWindowLeft_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsWindowLeft_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWindowLeft_001 begin");
    // Arrange
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t windowLeft = 100;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->SetStartOptionsWindowLeft(windowLeft);
    TAG_LOGI(AAFwkTag::TEST,
        "SetStartOptionsWindowLeft_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWindowLeft_001 end");
}

// Test cases
// Test GetStartOptionsWindowLeft function - Normal case
/**
 * @tc.name: GetStartOptionsWindowLeft_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsWindowLeft_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowLeft_001 begin");
    // Arrange
    int32_t expectedWindowLeft = 500;
    startOptions->SetStartOptionsWindowLeft(expectedWindowLeft);
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t windowLeft = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsWindowLeft(windowLeft);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsWindowLeft_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedWindowLeft, windowLeft);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowLeft_001 end");
}

// Test cases
// Test GetStartOptionsWindowLeft function
/**
 * @tc.name: GetStartOptionsWindowLeft_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsWindowLeft_002, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowLeft_002 begin");
    // Arrange
    int32_t expectedWindowLeft = -100;
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t windowLeft = -100;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsWindowLeft(windowLeft);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsWindowLeft_002 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedWindowLeft, windowLeft);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowLeft_002 end");
}

// Test cases
// Test SetStartOptionsWindowTop function - Normal case
/**
 * @tc.name: SetStartOptionsWindowTop_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsWindowTop_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWindowTop_001 begin");
    // Arrange
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t windowTop = 100;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->SetStartOptionsWindowTop(windowTop);
    TAG_LOGI(AAFwkTag::TEST,
        "SetStartOptionsWindowTop_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWindowTop_001 end");
}

// Test cases
// Test GetStartOptionsWindowTop function - Normal case
/**
 * @tc.name: GetStartOptionsWindowTop_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsWindowTop_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowTop_001 begin");
    // Arrange
    int32_t expectedWindowTop = 500;
    startOptions->SetStartOptionsWindowTop(expectedWindowTop);
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t windowTop = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsWindowTop(windowTop);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsWindowTop_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedWindowTop, windowTop);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowTop_001 end");
}

// Test cases
// Test GetStartOptionsWindowTop function
/**
 * @tc.name: GetStartOptionsWindowTop_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsWindowTop_002, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowTop_002 begin");
    // Arrange
    int32_t expectedWindowTop = 500;
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t windowTop = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsWindowTop(windowTop);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsWindowTop_002 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedWindowTop, windowTop);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowTop_002 end");
}

// Test cases
// Test SetStartOptionsWindowHeight function - Normal case
/**
 * @tc.name: SetStartOptionsWindowHeight_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsWindowHeight_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWindowHeight_001 begin");
    // Arrange
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t windowHeight = 100;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->SetStartOptionsWindowHeight(windowHeight);
    TAG_LOGI(AAFwkTag::TEST,
        "SetStartOptionsWindowHeight_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWindowHeight_001 end");
}

// Test cases
// Test GetStartOptionsWindowHeight function - Normal case
/**
 * @tc.name: GetStartOptionsWindowHeight_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsWindowHeight_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowHeight_001 begin");
    // Arrange
    int32_t expectedWindowHeight = 500;
    startOptions->SetStartOptionsWindowHeight(expectedWindowHeight);
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t windowHeight = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsWindowHeight(windowHeight);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsWindowHeight_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedWindowHeight, windowHeight);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowHeight_001 end");
}

// Test cases
// Test GetStartOptionsWindowHeight function
/**
 * @tc.name: GetStartOptionsWindowHeight_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsWindowHeight_002, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowHeight_002 begin");
    // Arrange
    int32_t expectedWindowHeight = 500;
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t windowHeight = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsWindowHeight(windowHeight);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsWindowHeight_002 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedWindowHeight, windowHeight);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowHeight_002 end");
}

// Test cases
// Test SetStartOptionsWindowWidth function - Normal case
/**
 * @tc.name: SetStartOptionsWindowWidth_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsWindowWidth_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWindowWidth_001 begin");
    // Arrange
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t windowWidth = 100;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->SetStartOptionsWindowWidth(windowWidth);
    TAG_LOGI(AAFwkTag::TEST,
        "SetStartOptionsWindowWidth_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsWindowWidth_001 end");
}

// Test cases
// Test GetStartOptionsWindowWidth function - Normal case
/**
 * @tc.name: GetStartOptionsWindowWidth_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsWindowWidth_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowWidth_001 begin");
    // Arrange
    int32_t expectedWindowWidth = 500;
    startOptions->SetStartOptionsWindowWidth(expectedWindowWidth);
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t windowWidth = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsWindowWidth(windowWidth);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsWindowWidth_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedWindowWidth, windowWidth);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowWidth_001 end");
}

// Test cases
// Test GetStartOptionsWindowWidth function
/**
 * @tc.name: GetStartOptionsWindowWidth_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsWindowWidth_002, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowWidth_002 begin");
    // Arrange
    int32_t expectedWindowWidth = 500;
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t windowWidth = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsWindowWidth(windowWidth);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsWindowWidth_002 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedWindowWidth, windowWidth);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsWindowWidth_002 end");
}

// Test cases
// Test SetStartOptionsStartVisibility function - Normal case
/**
 * @tc.name: SetStartOptionsStartVisibility_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsStartVisibility_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsStartVisibility_001 begin");
    // Arrange
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    AbilityRuntime_StartVisibility startVisibility = AbilityRuntime_StartVisibility::ABILITY_RUNTIME_SHOW_UPON_START;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->SetStartOptionsStartVisibility(startVisibility);
    TAG_LOGI(AAFwkTag::TEST,
        "SetStartOptionsStartVisibility_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsStartVisibility_001 end");
}

// Test cases
// Test GetStartOptionsStartVisibility function - Normal case
/**
 * @tc.name: GetStartOptionsStartVisibility_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsStartVisibility_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsStartVisibility_001 begin");
    // Arrange
    AbilityRuntime_StartVisibility expectedStartVisibility =
        AbilityRuntime_StartVisibility::ABILITY_RUNTIME_SHOW_UPON_START;
    startOptions->SetStartOptionsStartVisibility(expectedStartVisibility);
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    AbilityRuntime_StartVisibility startVisibility = AbilityRuntime_StartVisibility::ABILITY_RUNTIME_HIDE_UPON_START;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsStartVisibility(startVisibility);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsStartVisibility_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedStartVisibility, startVisibility);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsStartVisibility_001 end");
}

// Test cases
// Test GetStartOptionsStartVisibility function - Get without set
/**
 * @tc.name: GetStartOptionsStartVisibility_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsStartVisibility_002, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsStartVisibility_002 begin");
    // Arrange
    startOptions = new AbilityRuntime_StartOptions();
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;

    // Act
    AbilityRuntime_StartVisibility startVisibility = AbilityRuntime_StartVisibility::ABILITY_RUNTIME_HIDE_UPON_START;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsStartVisibility(startVisibility);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsStartVisibility_002 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsStartVisibility_002 end");
}

// Test cases
// Test SetStartOptionsStartWindowIcon function - Normal case
/**
 * @tc.name: SetStartOptionsStartWindowIcon_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsStartWindowIcon_001, testing::ext::TestSize.Level1)
{
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    OH_PixelmapNative* startWindowIcon = nullptr;
    EXPECT_EQ(startOptions->SetStartOptionsStartWindowIcon(startWindowIcon),
        ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
#endif
}

// Test cases
// Test SetStartOptionsStartWindowIcon function - Normal case
/**
 * @tc.name: SetStartOptionsStartWindowIcon_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsStartWindowIcon_002, testing::ext::TestSize.Level1)
{
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    OH_PixelmapNative *startWindowIcon = new OH_PixelmapNative(nullptr);
    EXPECT_EQ(startOptions->SetStartOptionsStartWindowIcon(startWindowIcon),
        ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    delete startWindowIcon;
#endif
}

// Test cases
// Test SetStartOptionsStartWindowIcon function - Normal case
/**
 * @tc.name: SetStartOptionsStartWindowIcon_003
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsStartWindowIcon_003, testing::ext::TestSize.Level1)
{
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    OH_PixelmapNative *startWindowIcon = new OH_PixelmapNative(nullptr);
    startOptions->options.startWindowOption = nullptr;
    EXPECT_EQ(startOptions->SetStartOptionsStartWindowIcon(startWindowIcon),
        ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    delete startWindowIcon;
#endif
}

// Test cases
// Test SetStartOptionsStartWindowIcon function - Normal case
/**
 * @tc.name: SetStartOptionsStartWindowIcon_004
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsStartWindowIcon_004, testing::ext::TestSize.Level1)
{
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    OH_PixelmapNative *startWindowIcon = new OH_PixelmapNative(nullptr);
    startOptions->options.startWindowOption = std::make_shared<OHOS::AAFwk::StartWindowOption>();
    EXPECT_EQ(startOptions->SetStartOptionsStartWindowIcon(startWindowIcon),
        ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    delete startWindowIcon;
#endif
}

// Test cases
// Test GetStartOptionsStartWindowIcon function - Normal case
/**
 * @tc.name: GetStartOptionsStartWindowIcon_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsStartWindowIcon_001, testing::ext::TestSize.Level1)
{
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    // Arrange
    startOptions->options.startWindowOption = nullptr;
    OH_PixelmapNative* startWindowIcon = nullptr;

    // Act
    AbilityRuntime_ErrorCode result = startOptions->GetStartOptionsStartWindowIcon(&startWindowIcon);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
#endif
}

// Test cases
// Test SetStartOptionsStartWindowIcon function - Normal case
/**
 * @tc.name: GetStartOptionsStartWindowIcon_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsStartWindowIcon_002, testing::ext::TestSize.Level1)
{
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    // Arrange
    startOptions->options.startWindowOption = std::make_shared<OHOS::AAFwk::StartWindowOption>();
    startOptions->options.startWindowOption->hasStartWindow = true;
    startOptions->options.startWindowOption->startWindowIcon = nullptr;
    OH_PixelmapNative* startWindowIcon = new OH_PixelmapNative(nullptr);

    // Act
    AbilityRuntime_ErrorCode result = startOptions->GetStartOptionsStartWindowIcon(&startWindowIcon);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
    delete startWindowIcon;
#endif
}

// Test cases
// Test SetStartOptionsStartWindowIcon function - Normal case
/**
 * @tc.name: GetStartOptionsStartWindowIcon_003
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsStartWindowIcon_003, testing::ext::TestSize.Level1)
{
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    // Arrange
    startOptions->options.startWindowOption = std::make_shared<OHOS::AAFwk::StartWindowOption>();
    startOptions->options.startWindowOption->hasStartWindow = true;
    startOptions->options.startWindowOption->startWindowIcon = nullptr;
    OH_PixelmapNative* startWindowIcon = nullptr;

    // Act
    AbilityRuntime_ErrorCode result = startOptions->GetStartOptionsStartWindowIcon(&startWindowIcon);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_NE(nullptr, startWindowIcon);
#endif
}

// Test cases
// Test SetStartOptionsStartWindowIcon function - Normal case
/**
 * @tc.name: GetStartOptionsStartWindowIcon_004
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsStartWindowIcon_004, testing::ext::TestSize.Level1)
{
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    // Arrange
    startOptions->options.startWindowOption = std::make_shared<OHOS::AAFwk::StartWindowOption>();
    startOptions->options.startWindowOption->hasStartWindow = false;
    startOptions->options.startWindowOption->startWindowIcon = nullptr;
    OH_PixelmapNative* startWindowIcon = nullptr;

    // Act
    AbilityRuntime_ErrorCode result = startOptions->GetStartOptionsStartWindowIcon(&startWindowIcon);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(nullptr, startWindowIcon);
#endif
}

// Test cases
// Test SetStartOptionsStartWindowBackgroundColor function
/**
 * @tc.name: SetStartOptionsStartWindowBackgroundColor_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsStartWindowBackgroundColor_001, testing::ext::TestSize.Level1)
{
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID,
        startOptions->SetStartOptionsStartWindowBackgroundColor(nullptr));
}

// Test cases
// Test SetStartOptionsStartWindowBackgroundColor function
/**
 * @tc.name: SetStartOptionsStartWindowBackgroundColor_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsStartWindowBackgroundColor_002, testing::ext::TestSize.Level1)
{
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR,
        startOptions->SetStartOptionsStartWindowBackgroundColor("#FFFFFFFF"));
}

// Test cases
// Test SetStartOptionsStartWindowBackgroundColor function
/**
 * @tc.name: SetStartOptionsStartWindowBackgroundColor_003
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsStartWindowBackgroundColor_003, testing::ext::TestSize.Level1)
{
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR,
        startOptions->SetStartOptionsStartWindowBackgroundColor(""));
}

// Test cases
// Test SetStartOptionsStartWindowBackgroundColor function
/**
 * @tc.name: SetStartOptionsStartWindowBackgroundColor_004
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsStartWindowBackgroundColor_004, testing::ext::TestSize.Level1)
{
    startOptions->options.startWindowOption = nullptr;
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR,
        startOptions->SetStartOptionsStartWindowBackgroundColor("FFFFFF"));
}

// Test cases
// Test GetStartOptionsStartWindowBackgroundColor function
/**
 * @tc.name: GetStartOptionsStartWindowBackgroundColor_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsStartWindowBackgroundColor_001, testing::ext::TestSize.Level1)
{
    // Arrange
    startOptions->options.startWindowOption = nullptr;
    char* startWindowBackgroundColor = nullptr;
    size_t size = 0;

    // Act
    AbilityRuntime_ErrorCode result = startOptions->GetStartOptionsStartWindowBackgroundColor(
        &startWindowBackgroundColor, size);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

// Test cases
// Test GetStartOptionsStartWindowBackgroundColor function
/**
 * @tc.name: GetStartOptionsStartWindowBackgroundColor_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsStartWindowBackgroundColor_002, testing::ext::TestSize.Level1)
{
    // Arrange
    startOptions->options.startWindowOption = std::make_shared<OHOS::AAFwk::StartWindowOption>();
    startOptions->options.startWindowOption->hasStartWindow = true;
    startOptions->options.startWindowOption->startWindowBackgroundColor = "red";
    char* startWindowBackgroundColor = const_cast<char*>("blue");
    size_t size = 0;

    // Act
    AbilityRuntime_ErrorCode result = startOptions->GetStartOptionsStartWindowBackgroundColor(
        &startWindowBackgroundColor, size);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

// Test cases
// Test GetStartOptionsStartWindowBackgroundColor function
/**
 * @tc.name: GetStartOptionsStartWindowBackgroundColor_003
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsStartWindowBackgroundColor_003, testing::ext::TestSize.Level1)
{
    // Arrange
    startOptions->options.startWindowOption = std::make_shared<OHOS::AAFwk::StartWindowOption>();
    startOptions->options.startWindowOption->hasStartWindow = true;
    startOptions->options.startWindowOption->startWindowBackgroundColor = "red";
    char* startWindowBackgroundColor = nullptr;
    size_t size = 0;

    // Act
    AbilityRuntime_ErrorCode result = startOptions->GetStartOptionsStartWindowBackgroundColor(
        &startWindowBackgroundColor, size);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(0, strcmp(startWindowBackgroundColor, "red"));
    EXPECT_EQ(3, size);
}

// Test cases
// Test GetStartOptionsStartWindowBackgroundColor function
/**
 * @tc.name: GetStartOptionsStartWindowBackgroundColor_004
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsStartWindowBackgroundColor_004, testing::ext::TestSize.Level1)
{
    // Arrange
    startOptions->options.startWindowOption = std::make_shared<OHOS::AAFwk::StartWindowOption>();
    startOptions->options.startWindowOption->hasStartWindow = false;
    char* startWindowBackgroundColor = nullptr;
    size_t size = 0;

    // Act
    AbilityRuntime_ErrorCode result = startOptions->GetStartOptionsStartWindowBackgroundColor(
        &startWindowBackgroundColor, size);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(startWindowBackgroundColor, nullptr);
    EXPECT_EQ(size, 0);
}

// Test cases
// Test SetStartOptionsSupportedWindowModes function
/**
 * @tc.name: SetStartOptionsSupportedWindowModes_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsSupportedWindowModes_001, testing::ext::TestSize.Level1)
{
    AbilityRuntime_SupportedWindowMode* supportedWindowModes = nullptr;
    size_t size = 1;
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID,
        startOptions->SetStartOptionsSupportedWindowModes(supportedWindowModes, size));
}

// Test cases
// Test SetStartOptionsSupportedWindowModes function
/**
 * @tc.name: SetStartOptionsSupportedWindowModes_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsSupportedWindowModes_002, testing::ext::TestSize.Level1)
{
    AbilityRuntime_SupportedWindowMode supportedWindowModes[1] =
        { ABILITY_RUNTIME_SUPPORTED_WINDOW_MODE_FULL_SCREEN };
    size_t size = 0;
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID,
        startOptions->SetStartOptionsSupportedWindowModes(supportedWindowModes, size));
}

// Test cases
// Test SetStartOptionsSupportedWindowModes function
/**
 * @tc.name: SetStartOptionsSupportedWindowModes_003
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsSupportedWindowModes_003, testing::ext::TestSize.Level1)
{
    AbilityRuntime_SupportedWindowMode supportedWindowModes[MAX_SUPPOPRT_WINDOW_MODES_SIZE + 1];
    size_t size = MAX_SUPPOPRT_WINDOW_MODES_SIZE + 1;
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID,
        startOptions->SetStartOptionsSupportedWindowModes(supportedWindowModes, size));
}

// Test cases
// Test SetStartOptionsSupportedWindowModes function
/**
 * @tc.name: SetStartOptionsSupportedWindowModes_004
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsSupportedWindowModes_004, testing::ext::TestSize.Level1)
{
    AbilityRuntime_SupportedWindowMode supportedWindowModes[1] =
        { AbilityRuntime_SupportedWindowMode(999) }; // Invalid mode
    size_t size = 1;
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID,
        startOptions->SetStartOptionsSupportedWindowModes(supportedWindowModes, size));
}

// Test cases
// Test SetStartOptionsSupportedWindowModes function
/**
 * @tc.name: SetStartOptionsSupportedWindowModes_005
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsSupportedWindowModes_005, testing::ext::TestSize.Level1)
{
    AbilityRuntime_SupportedWindowMode supportedWindowModes[1] =
        { ABILITY_RUNTIME_SUPPORTED_WINDOW_MODE_FULL_SCREEN };
    size_t size = 1;
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR,
        startOptions->SetStartOptionsSupportedWindowModes(supportedWindowModes, size));
}

// Test cases
// Test GetStartOptionsSupportedWindowModes function
/**
 * @tc.name: GetStartOptionsSupportedWindowModes_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsSupportedWindowModes_001, testing::ext::TestSize.Level1)
{
    AbilityRuntime_SupportedWindowMode* supportedWindowModes = nullptr;
    size_t size = 0;
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR,
        startOptions->GetStartOptionsSupportedWindowModes(&supportedWindowModes, size));
}

// Test cases
// Test GetStartOptionsSupportedWindowModes function
/**
 * @tc.name: GetStartOptionsSupportedWindowModes_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsSupportedWindowModes_002, testing::ext::TestSize.Level1)
{
    AbilityRuntime_SupportedWindowMode* supportedWindowModes = new AbilityRuntime_SupportedWindowMode;
    size_t size = 0;
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID,
        startOptions->GetStartOptionsSupportedWindowModes(&supportedWindowModes, size));
    delete supportedWindowModes;
}

// Test cases
// Test GetStartOptionsSupportedWindowModes function
/**
 * @tc.name: GetStartOptionsSupportedWindowModes_003
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsSupportedWindowModes_003, testing::ext::TestSize.Level1)
{
    AbilityRuntime_SupportedWindowMode* supportedWindowModes = nullptr;
    size_t size = 0;
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR,
        startOptions->GetStartOptionsSupportedWindowModes(&supportedWindowModes, size));
    EXPECT_EQ(0, size);
    EXPECT_EQ(nullptr, supportedWindowModes);
}

// Test cases
// Test GetStartOptionsSupportedWindowModes function
/**
 * @tc.name: GetStartOptionsSupportedWindowModes_004
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsSupportedWindowModes_004, testing::ext::TestSize.Level1)
{
    startOptions->options.supportWindowModes_.push_back(
        static_cast<OHOS::AppExecFwk::SupportWindowMode>(ABILITY_RUNTIME_SUPPORTED_WINDOW_MODE_FULL_SCREEN));
    AbilityRuntime_SupportedWindowMode* supportedWindowModes = nullptr;
    size_t size = 0;
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR,
        startOptions->GetStartOptionsSupportedWindowModes(&supportedWindowModes, size));
    EXPECT_EQ(1, size);
    EXPECT_NE(nullptr, supportedWindowModes);
    EXPECT_EQ(ABILITY_RUNTIME_SUPPORTED_WINDOW_MODE_FULL_SCREEN, supportedWindowModes[0]);
    free(supportedWindowModes);
}

// Test cases
// Test SetStartOptionsMinWindowWidth function - Normal case
/**
 * @tc.name: SetStartOptionsMinWindowWidth_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsMinWindowWidth_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsMinWindowWidth_001 begin");
    // Arrange
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t minWindowWidth = 100;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->SetStartOptionsMinWindowWidth(minWindowWidth);
    TAG_LOGI(AAFwkTag::TEST,
        "SetStartOptionsMinWindowWidth_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsMinWindowWidth_001 end");
}

// Test cases
// Test GetStartOptionsMinWindowWidth function - Normal case
/**
 * @tc.name: GetStartOptionsMinWindowWidth_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsMinWindowWidth_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMinWindowWidth_001 begin");
    // Arrange
    int32_t expectedMinWindowWidth = 500;
    startOptions->SetStartOptionsMinWindowWidth(expectedMinWindowWidth);
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t minWindowWidth = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsMinWindowWidth(minWindowWidth);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsMinWindowWidth_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedMinWindowWidth, minWindowWidth);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMinWindowWidth_001 end");
}

// Test cases
// Test GetStartOptionsMinWindowWidth function
/**
 * @tc.name: GetStartOptionsMinWindowWidth_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsMinWindowWidth_002, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMinWindowWidth_002 begin");
    // Arrange
    int32_t expectedMinWindowWidth = 500;
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t minWindowWidth = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsMinWindowWidth(minWindowWidth);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsMinWindowWidth_002 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedMinWindowWidth, minWindowWidth);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMinWindowWidth_002 end");
}

// Test cases
// Test SetStartOptionsMaxWindowWidth function - Normal case
/**
 * @tc.name: SetStartOptionsMaxWindowWidth_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsMaxWindowWidth_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsMaxWindowWidth_001 begin");
    // Arrange
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t maxMaxWindowWidth = 100;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->SetStartOptionsMaxWindowWidth(maxMaxWindowWidth);
    TAG_LOGI(AAFwkTag::TEST,
        "SetStartOptionsMaxWindowWidth_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsMaxWindowWidth_001 end");
}

// Test cases
// Test GetStartOptionsMaxWindowWidth function - Normal case
/**
 * @tc.name: GetStartOptionsMaxWindowWidth_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsMaxWindowWidth_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMaxWindowWidth_001 begin");
    // Arrange
    int32_t expectedMaxWindowWidth = 500;
    startOptions->SetStartOptionsMaxWindowWidth(expectedMaxWindowWidth);
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t maxWindowWidth = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsMaxWindowWidth(maxWindowWidth);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsMaxWindowWidth_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedMaxWindowWidth, maxWindowWidth);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMaxWindowWidth_001 end");
}

// Test cases
// Test GetStartOptionsMaxWindowWidth function
/**
 * @tc.name: GetStartOptionsMaxWindowWidth_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsMaxWindowWidth_002, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMaxWindowWidth_002 begin");
    // Arrange
    int32_t expectedMaxWindowWidth = 500;
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t maxWindowWidth = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsMaxWindowWidth(maxWindowWidth);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsMaxWindowWidth_002 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedMaxWindowWidth, maxWindowWidth);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMaxWindowWidth_002 end");
}

// Test cases
// Test SetStartOptionsMinWindowHeight function - Normal case
/**
 * @tc.name: SetStartOptionsMinWindowHeight_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsMinWindowHeight_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsMinWindowHeight_001 begin");
    // Arrange
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t minWindowHeight = 100;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->SetStartOptionsMinWindowHeight(minWindowHeight);
    TAG_LOGI(AAFwkTag::TEST,
        "SetStartOptionsMinWindowHeight_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsMinWindowHeight_001 end");
}

// Test cases
// Test GetStartOptionsMinWindowHeight function - Normal case
/**
 * @tc.name: GetStartOptionsMinWindowHeight_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsMinWindowHeight_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMinWindowHeight_001 begin");
    // Arrange
    int32_t expectedMinWindowHeight = 500;
    startOptions->SetStartOptionsMinWindowHeight(expectedMinWindowHeight);
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t minWindowHeight = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsMinWindowHeight(minWindowHeight);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsMinWindowHeight_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedMinWindowHeight, minWindowHeight);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMinWindowHeight_001 end");
}

// Test cases
// Test GetStartOptionsMinWindowHeight function - Normal case
/**
 * @tc.name: GetStartOptionsMinWindowHeight_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsMinWindowHeight_002, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMinWindowHeight_002 begin");
    // Arrange
    int32_t expectedMinWindowHeight = 500;
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t minWindowHeight = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsMinWindowHeight(minWindowHeight);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsMinWindowHeight_002 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedMinWindowHeight, minWindowHeight);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMinWindowHeight_002 end");
}

// Test cases
// Test SetStartOptionsMaxWindowHeight function - Normal case
/**
 * @tc.name: SetStartOptionsMaxWindowHeight_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, SetStartOptionsMaxWindowHeight_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsMaxWindowHeight_001 begin");
    // Arrange
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t maxWindowHeight = 100;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->SetStartOptionsMaxWindowHeight(maxWindowHeight);
    TAG_LOGI(AAFwkTag::TEST,
        "SetStartOptionsMaxWindowHeight_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    TAG_LOGI(AAFwkTag::TEST, "SetStartOptionsMaxWindowHeight_001 end");
}

// Test cases
// Test GetStartOptionsMaxWindowHeight function - Normal case
/**
 * @tc.name: GetStartOptionsMaxWindowHeight_001
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsMaxWindowHeight_001, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMaxWindowHeight_001 begin");
    // Arrange
    int32_t expectedMaxWindowHeight = 500;
    startOptions->SetStartOptionsMaxWindowHeight(expectedMaxWindowHeight);
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t maxWindowHeight = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsMaxWindowHeight(maxWindowHeight);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsMaxWindowHeight_001 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedMaxWindowHeight, maxWindowHeight);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMaxWindowHeight_001 end");
}

// Test cases
// Test GetStartOptionsMaxWindowHeight function - Normal case
/**
 * @tc.name: GetStartOptionsMaxWindowHeight_002
 * @tc.desc: test class StartOptions number function
 * @tc.type: FUNC
 */
HWTEST_F(StartOptionsImplTest, GetStartOptionsMaxWindowHeight_002, testing::ext::TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMaxWindowHeight_002 begin");
    // Arrange
    int32_t expectedMaxWindowHeight = 500;
    AbilityRuntime_ErrorCode expectedErrorCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    // Act
    int32_t maxWindowHeight = 500;
    AbilityRuntime_ErrorCode resultErrorCode = startOptions->GetStartOptionsMaxWindowHeight(maxWindowHeight);
    TAG_LOGI(AAFwkTag::TEST,
        "GetStartOptionsMaxWindowHeight_002 resultErrorCode=%{public}d,expectedErrorCode=%{public}d",
        resultErrorCode, expectedErrorCode);

    // Assert
    EXPECT_EQ(expectedErrorCode, resultErrorCode);
    EXPECT_EQ(expectedMaxWindowHeight, maxWindowHeight);
    TAG_LOGI(AAFwkTag::TEST, "GetStartOptionsMaxWindowHeight_002 end");
}
