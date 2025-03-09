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

#include "start_options.h"

#include <cstring>
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
#include "pixelmap_native_impl.h"
#endif
#include "start_options_impl.h"

using namespace testing::ext;
namespace OHOS {
namespace AAFwk {
constexpr int MAX_SUPPOPRT_WINDOW_MODES_SIZE = 10;

class AbilityRuntimeStartOptionsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AbilityRuntimeStartOptionsTest::SetUpTestCase()
{}

void AbilityRuntimeStartOptionsTest::TearDownTestCase()
{}

void AbilityRuntimeStartOptionsTest::SetUp()
{}

void AbilityRuntimeStartOptionsTest::TearDown()
{}

/**
 * @tc.name: OH_AbilityRuntime_CreateStartOptions_001
 * @tc.desc: OH_AbilityRuntime_CreateStartOptions
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_CreateStartOptions_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions* startOptions = OH_AbilityRuntime_CreateStartOptions();

    // Act & Assert
    ASSERT_NE(startOptions, nullptr);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_DestroyStartOptions_001
 * @tc.desc: OH_AbilityRuntime_DestroyStartOptions
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_DestroyStartOptions_001, TestSize.Level1)
{
    AbilityRuntime_StartOptions* startOptions = nullptr;
    EXPECT_EQ(OH_AbilityRuntime_DestroyStartOptions(&startOptions), ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(startOptions, nullptr);
}

/**
 * @tc.name: OH_AbilityRuntime_DestroyStartOptions_002
 * @tc.desc: OH_AbilityRuntime_DestroyStartOptions
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_DestroyStartOptions_002, TestSize.Level1)
{
    AbilityRuntime_StartOptions* startOptions = OH_AbilityRuntime_CreateStartOptions();
    EXPECT_EQ(OH_AbilityRuntime_DestroyStartOptions(&startOptions), ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(startOptions, nullptr);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowMode_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowMode
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowMode_001, TestSize.Level1)
{
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWindowMode(nullptr,
        ABILITY_RUNTIME_WINDOW_MODE_FULL_SCREEN);
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowMode_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowMode
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowMode_002, TestSize.Level1)
{
    AbilityRuntime_StartOptions* startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWindowMode(startOptions,
        ABILITY_RUNTIME_WINDOW_MODE_FULL_SCREEN);
    // Assuming SetStartOptionsWindowMode returns ABILITY_RUNTIME_OK on success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowMode_003
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowMode
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowMode_003, TestSize.Level1)
{
    AbilityRuntime_StartOptions* startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWindowMode(startOptions,
        static_cast<AbilityRuntime_WindowMode>(-1));
    // Assuming ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID is returned for invalid window mode
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWindowMode_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWindowMode
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWindowMode_001, TestSize.Level0)
{
    AbilityRuntime_WindowMode windowMode;
    AbilityRuntime_ErrorCode errorCode = OH_AbilityRuntime_GetStartOptionsWindowMode(nullptr, windowMode);
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, errorCode);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWindowMode_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWindowMode
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWindowMode_002, TestSize.Level0)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWindowMode(startOptions,
        ABILITY_RUNTIME_WINDOW_MODE_FULL_SCREEN);
    // Assuming SetStartOptionsWindowMode returns ABILITY_RUNTIME_OK on success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    AbilityRuntime_WindowMode windowMode;
    AbilityRuntime_ErrorCode errorCode = OH_AbilityRuntime_GetStartOptionsWindowMode(startOptions, windowMode);
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, errorCode);
    EXPECT_EQ(ABILITY_RUNTIME_WINDOW_MODE_FULL_SCREEN, windowMode);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsDisplayId_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsDisplayId
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsDisplayId_001, TestSize.Level1)
{
    AbilityRuntime_StartOptions* startOptions = nullptr;
    int32_t displayId = 1;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsDisplayId(startOptions, displayId),
        ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsDisplayId_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsDisplayId
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsDisplayId_002, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t displayId = 1;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsDisplayId(startOptions, displayId),
        startOptions->SetStartOptionsDisplayId(displayId));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsDisplayId_003
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsDisplayId
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsDisplayId_003, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t displayId = -1;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsDisplayId(startOptions, displayId),
        startOptions->SetStartOptionsDisplayId(displayId));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsDisplayId_004
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsDisplayId
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsDisplayId_004, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t displayId = 0;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsDisplayId(startOptions, displayId),
        startOptions->SetStartOptionsDisplayId(displayId));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsDisplayId_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsDisplayId
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsDisplayId_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    int32_t displayId;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_GetStartOptionsDisplayId(startOptions, displayId);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsDisplayId_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsDisplayId
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsDisplayId_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsDisplayId(startOptions, 1);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t displayId;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsDisplayId(startOptions, displayId);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(1, displayId);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsDisplayId_003
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsDisplayId
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsDisplayId_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsDisplayId(startOptions, -1);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t displayId;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsDisplayId(startOptions, displayId);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(-1, displayId);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWithAnimation_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWithAnimation
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWithAnimation_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    bool withAnimation = true;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWithAnimation(startOptions, withAnimation);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWithAnimation_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWithAnimation
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWithAnimation_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();

    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWithAnimation(startOptions, true);

    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWithAnimation_003
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWithAnimation
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWithAnimation_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();

    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWithAnimation(startOptions, false);

    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWithAnimation_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWithAnimation
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWithAnimation_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    bool withAnimation;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_GetStartOptionsWithAnimation(startOptions, withAnimation);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}
 
/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWithAnimation_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWithAnimation
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWithAnimation_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWithAnimation(startOptions, true);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    bool withAnimation;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsWithAnimation(startOptions, withAnimation);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(true, withAnimation);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWithAnimation_003
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWithAnimation
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWithAnimation_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWithAnimation(startOptions, false);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    bool withAnimation;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsWithAnimation(startOptions, withAnimation);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(false, withAnimation);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowLeft_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowLeft
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowLeft_001, TestSize.Level1)
{
    AbilityRuntime_StartOptions* startOptions = nullptr;
    int32_t windowLeft = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowLeft(startOptions, windowLeft),
        ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowLeft_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowLeft
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowLeft_002, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t windowLeft = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowLeft(startOptions, windowLeft),
        startOptions->SetStartOptionsWindowLeft(windowLeft));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowLeft_003
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowLeft
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowLeft_003, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t windowLeft = -100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowLeft(startOptions, windowLeft),
        startOptions->SetStartOptionsWindowLeft(windowLeft));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowLeft_004
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowLeft
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowLeft_004, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t windowLeft = 0;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowLeft(startOptions, windowLeft),
        startOptions->SetStartOptionsWindowLeft(windowLeft));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWindowLeft_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWindowLeft
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWindowLeft_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    int32_t windowLeft;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_GetStartOptionsWindowLeft(startOptions, windowLeft);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWindowLeft_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWindowLeft
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWindowLeft_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWindowLeft(startOptions, 100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t windowLeft;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsWindowLeft(startOptions, windowLeft);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(100, windowLeft);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWindowLeft_003
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWindowLeft
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWindowLeft_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWindowLeft(startOptions, -100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t windowLeft;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsWindowLeft(startOptions, windowLeft);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(-100, windowLeft);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowTop_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowTop
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowTop_001, TestSize.Level1)
{
    AbilityRuntime_StartOptions* startOptions = nullptr;
    int32_t windowTop = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowTop(startOptions, windowTop),
        ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowTop_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowTop
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowTop_002, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t windowTop = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowTop(startOptions, windowTop),
        startOptions->SetStartOptionsWindowTop(windowTop));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowTop_003
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowTop
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowTop_003, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t windowTop = -100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowTop(startOptions, windowTop),
        startOptions->SetStartOptionsWindowTop(windowTop));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowTop_004
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowTop
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowTop_004, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t windowTop = 0;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowTop(startOptions, windowTop),
        startOptions->SetStartOptionsWindowTop(windowTop));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWindowTop_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWindowTop
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWindowTop_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    int32_t windowTop;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_GetStartOptionsWindowTop(startOptions, windowTop);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWindowTop_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWindowTop
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWindowTop_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWindowTop(startOptions, 100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t windowTop;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsWindowTop(startOptions, windowTop);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(100, windowTop);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWindowTop_003
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWindowTop
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWindowTop_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWindowTop(startOptions, -100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t windowTop;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsWindowTop(startOptions, windowTop);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(-100, windowTop);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowHeight_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowHeight_001, TestSize.Level1)
{
    AbilityRuntime_StartOptions* startOptions = nullptr;
    int32_t windowHeight = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowHeight(startOptions, windowHeight),
        ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowHeight_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowHeight_002, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t windowHeight = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowHeight(startOptions, windowHeight),
        startOptions->SetStartOptionsWindowHeight(windowHeight));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowHeight_003
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowHeight_003, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t windowHeight = -100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowHeight(startOptions, windowHeight),
        startOptions->SetStartOptionsWindowHeight(windowHeight));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowHeight_004
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowHeight_004, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t windowHeight = 0;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowHeight(startOptions, windowHeight),
        startOptions->SetStartOptionsWindowHeight(windowHeight));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWindowHeight_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWindowHeight_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    int32_t windowHeight;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_GetStartOptionsWindowHeight(startOptions, windowHeight);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWindowHeight_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWindowHeight_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWindowHeight(startOptions, 100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t windowHeight;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsWindowHeight(startOptions, windowHeight);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(100, windowHeight);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWindowHeight_003
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWindowHeight_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWindowHeight(startOptions, -100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t windowHeight;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsWindowHeight(startOptions, windowHeight);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(-100, windowHeight);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowWidth_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowWidth_001, TestSize.Level1)
{
    AbilityRuntime_StartOptions* startOptions = nullptr;
    int32_t windowWidth = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowWidth(startOptions, windowWidth),
        ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowWidth_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowWidth_002, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t windowWidth = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowWidth(startOptions, windowWidth),
        startOptions->SetStartOptionsWindowWidth(windowWidth));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowWidth_003
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowWidth_003, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t windowWidth = -100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowWidth(startOptions, windowWidth),
        startOptions->SetStartOptionsWindowWidth(windowWidth));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsWindowWidth_004
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsWindowWidth_004, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t windowWidth = 0;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowWidth(startOptions, windowWidth),
        startOptions->SetStartOptionsWindowWidth(windowWidth));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWindowWidth_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWindowWidth_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    int32_t windowWidth;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_GetStartOptionsWindowWidth(startOptions, windowWidth);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWindowWidth_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWindowWidth_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWindowWidth(startOptions, 100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t windowWidth;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsWindowWidth(startOptions, windowWidth);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(100, windowWidth);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsWindowWidth_003
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsWindowWidth_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsWindowWidth(startOptions, -100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t windowWidth;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsWindowWidth(startOptions, windowWidth);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(-100, windowWidth);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsStartVisibility_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsStartVisibility
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsStartVisibility_001, TestSize.Level1)
{
    AbilityRuntime_StartOptions* startOptions = nullptr;
    AbilityRuntime_StartVisibility startVisibility = AbilityRuntime_StartVisibility::ABILITY_RUNTIME_HIDE_UPON_START;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsWindowWidth(startOptions, startVisibility),
        ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsStartVisibility_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsStartVisibility
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsStartVisibility_002, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_StartVisibility startVisibility = AbilityRuntime_StartVisibility::ABILITY_RUNTIME_HIDE_UPON_START;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsStartVisibility(startOptions, startVisibility),
        startOptions->SetStartOptionsStartVisibility(startVisibility));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsStartVisibility_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsStartVisibility
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsStartVisibility_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    AbilityRuntime_StartVisibility startVisibility;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_GetStartOptionsStartVisibility(startOptions, startVisibility);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsStartVisibility_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsStartVisibility
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsStartVisibility_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsStartVisibility(startOptions,
        AbilityRuntime_StartVisibility::ABILITY_RUNTIME_SHOW_UPON_START);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    AbilityRuntime_StartVisibility startVisibility;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsStartVisibility(startOptions, startVisibility);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(AbilityRuntime_StartVisibility::ABILITY_RUNTIME_SHOW_UPON_START, startVisibility);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);

    result = OH_AbilityRuntime_GetStartOptionsStartVisibility(startOptions, startVisibility);
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsStartVisibility_003
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsStartVisibility
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsStartVisibility_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_StartVisibility startVisibility;

    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_GetStartOptionsStartVisibility(startOptions, startVisibility);
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMinWindowWidth_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMinWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMinWindowWidth_001, TestSize.Level1)
{
    AbilityRuntime_StartOptions* startOptions = nullptr;
    int32_t minMinWindowWidth = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMinWindowWidth(startOptions, minMinWindowWidth),
        ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMinWindowWidth_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMinWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMinWindowWidth_002, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t minMinWindowWidth = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMinWindowWidth(startOptions, minMinWindowWidth),
        startOptions->SetStartOptionsMinWindowWidth(minMinWindowWidth));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMinWindowWidth_003
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMinWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMinWindowWidth_003, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t minMinWindowWidth = -100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMinWindowWidth(startOptions, minMinWindowWidth),
        startOptions->SetStartOptionsMinWindowWidth(minMinWindowWidth));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMinWindowWidth_004
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMinWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMinWindowWidth_004, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t minMinWindowWidth = 0;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMinWindowWidth(startOptions, minMinWindowWidth),
        startOptions->SetStartOptionsMinWindowWidth(minMinWindowWidth));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsMinWindowWidth_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsMinWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsMinWindowWidth_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    int32_t minMinWindowWidth;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_GetStartOptionsMinWindowWidth(startOptions, minMinWindowWidth);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsMinWindowWidth_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsMinWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsMinWindowWidth_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsMinWindowWidth(startOptions, 100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t minMinWindowWidth;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsMinWindowWidth(startOptions, minMinWindowWidth);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(100, minMinWindowWidth);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsMinWindowWidth_003
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsMinWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsMinWindowWidth_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsMinWindowWidth(startOptions, -100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t minMinWindowWidth;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsMinWindowWidth(startOptions, minMinWindowWidth);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(-100, minMinWindowWidth);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMaxWindowWidth_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMaxWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMaxWindowWidth_001, TestSize.Level1)
{
    AbilityRuntime_StartOptions* startOptions = nullptr;
    int32_t maxWindowWidth = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMaxWindowWidth(startOptions, maxWindowWidth),
        ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMaxWindowWidth_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMaxWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMaxWindowWidth_002, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t maxWindowWidth = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMaxWindowWidth(startOptions, maxWindowWidth),
        startOptions->SetStartOptionsMaxWindowWidth(maxWindowWidth));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMaxWindowWidth_003
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMaxWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMaxWindowWidth_003, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t maxWindowWidth = -100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMaxWindowWidth(startOptions, maxWindowWidth),
        startOptions->SetStartOptionsMaxWindowWidth(maxWindowWidth));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMaxWindowWidth_004
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMaxWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMaxWindowWidth_004, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t maxWindowWidth = 0;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMaxWindowWidth(startOptions, maxWindowWidth),
        startOptions->SetStartOptionsMaxWindowWidth(maxWindowWidth));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsMaxWindowWidth_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsMaxWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsMaxWindowWidth_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    int32_t maxWindowWidth;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_GetStartOptionsMaxWindowWidth(startOptions, maxWindowWidth);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsMaxWindowWidth_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsMaxWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsMaxWindowWidth_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsMaxWindowWidth(startOptions, 100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t maxWindowWidth;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsMaxWindowWidth(startOptions, maxWindowWidth);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(100, maxWindowWidth);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsMaxWindowWidth_003
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsMaxWindowWidth
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsMaxWindowWidth_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsMaxWindowWidth(startOptions, -100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t maxWindowWidth;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsMaxWindowWidth(startOptions, maxWindowWidth);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(-100, maxWindowWidth);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMaxWindowHeight_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMaxWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMaxWindowHeight_001, TestSize.Level1)
{
    AbilityRuntime_StartOptions* startOptions = nullptr;
    int32_t maxWindowHeight = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMaxWindowHeight(startOptions, maxWindowHeight),
        ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMaxWindowHeight_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMaxWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMaxWindowHeight_002, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t maxWindowHeight = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMaxWindowHeight(startOptions, maxWindowHeight),
        startOptions->SetStartOptionsMaxWindowHeight(maxWindowHeight));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMaxWindowHeight_003
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMaxWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMaxWindowHeight_003, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t maxWindowHeight = -100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMaxWindowHeight(startOptions, maxWindowHeight),
        startOptions->SetStartOptionsMaxWindowHeight(maxWindowHeight));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMaxWindowHeight_004
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMaxWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMaxWindowHeight_004, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t maxWindowHeight = 0;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMaxWindowHeight(startOptions, maxWindowHeight),
        startOptions->SetStartOptionsMaxWindowHeight(maxWindowHeight));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsMaxWindowHeight_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsMaxWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsMaxWindowHeight_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    int32_t maxWindowHeight;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_GetStartOptionsMaxWindowHeight(startOptions, maxWindowHeight);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsMaxWindowHeight_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsMaxWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsMaxWindowHeight_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsMaxWindowHeight(startOptions, 100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t maxWindowHeight;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsMaxWindowHeight(startOptions, maxWindowHeight);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(100, maxWindowHeight);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsMaxWindowHeight_003
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsMaxWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsMaxWindowHeight_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsMaxWindowHeight(startOptions, -100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t maxWindowHeight;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsMaxWindowHeight(startOptions, maxWindowHeight);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(-100, maxWindowHeight);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMinWindowHeight_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMinWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMinWindowHeight_001, TestSize.Level1)
{
    AbilityRuntime_StartOptions* startOptions = nullptr;
    int32_t minWindowHeight = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMinWindowHeight(startOptions, minWindowHeight),
        ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMinWindowHeight_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMinWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMinWindowHeight_002, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t minWindowHeight = 100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMinWindowHeight(startOptions, minWindowHeight),
        startOptions->SetStartOptionsMinWindowHeight(minWindowHeight));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMinWindowHeight_003
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMinWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMinWindowHeight_003, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t minWindowHeight = -100;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMinWindowHeight(startOptions, minWindowHeight),
        startOptions->SetStartOptionsMinWindowHeight(minWindowHeight));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsMinWindowHeight_004
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsMinWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsMinWindowHeight_004, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    int32_t minWindowHeight = 0;
    EXPECT_EQ(OH_AbilityRuntime_SetStartOptionsMinWindowHeight(startOptions, minWindowHeight),
        startOptions->SetStartOptionsMinWindowHeight(minWindowHeight));
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsMinWindowHeight_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsMinWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsMinWindowHeight_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    int32_t minWindowHeight;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_GetStartOptionsMinWindowHeight(startOptions, minWindowHeight);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsMinWindowHeight_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsMinWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsMinWindowHeight_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsMinWindowHeight(startOptions, 100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t minWindowHeight;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsMinWindowHeight(startOptions, minWindowHeight);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(100, minWindowHeight);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsMinWindowHeight_003
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsMinWindowHeight
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsMinWindowHeight_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsMinWindowHeight(startOptions, -100);
    // Assuming OH_AbilityRuntime_SetStartOptionsWindowMode returns success
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    int32_t minWindowHeight;

    // Act
    result = OH_AbilityRuntime_GetStartOptionsMinWindowHeight(startOptions, minWindowHeight);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    EXPECT_EQ(-100, minWindowHeight);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsStartWindowIcon_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsStartWindowIcon
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsStartWindowIcon_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    OH_PixelmapNative *startWindowIcon = nullptr;
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    startWindowIcon = new OH_PixelmapNative(nullptr);
#endif

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsStartWindowIcon(startOptions, startWindowIcon);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    delete startWindowIcon;
#endif
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsStartWindowIcon_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsStartWindowIcon
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsStartWindowIcon_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    EXPECT_NE(startOptions, nullptr);
    OH_PixelmapNative *startWindowIcon = nullptr;
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    startWindowIcon = new OH_PixelmapNative(nullptr);
#endif
    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsStartWindowIcon(startOptions, startWindowIcon);

    // Assert
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    EXPECT_EQ(startOptions->SetStartOptionsStartWindowIcon(startWindowIcon), result);
#else
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
#endif

    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    delete startWindowIcon;
#endif
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsStartWindowIcon_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsStartWindowIcon
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsStartWindowIcon_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    OH_PixelmapNative *startWindowIcon = nullptr;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_GetStartOptionsStartWindowIcon(startOptions, &startWindowIcon);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsStartWindowIcon_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsStartWindowIcon
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsStartWindowIcon_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    EXPECT_NE(startOptions, nullptr);

    OH_PixelmapNative *startWindowIcon = nullptr;
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    startWindowIcon = new OH_PixelmapNative(nullptr);
#endif
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsStartWindowIcon(startOptions, startWindowIcon);
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    // Act
    OH_PixelmapNative *newStartWindowIcon = nullptr;
    result = OH_AbilityRuntime_GetStartOptionsStartWindowIcon(startOptions, &newStartWindowIcon);

    // Assert
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    newStartWindowIcon = nullptr;
    EXPECT_EQ(startOptions->GetStartOptionsStartWindowIcon(&newStartWindowIcon), result);
#else
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
#endif

#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    delete startWindowIcon;
#endif
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsStartWindowIcon_003
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsStartWindowIcon
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsStartWindowIcon_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    EXPECT_NE(startOptions, nullptr);

    OH_PixelmapNative *startWindowIcon = nullptr;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_GetStartOptionsStartWindowIcon(startOptions, &startWindowIcon);

    // Assert
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    startWindowIcon = nullptr;
    EXPECT_EQ(startOptions->GetStartOptionsStartWindowIcon(&startWindowIcon), result);
#else
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
#endif

OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest,
    OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    const char *startWindowBackgroundColor = "FFFFFF";

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor(
        startOptions, startWindowBackgroundColor);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest,
    OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    EXPECT_NE(startOptions, nullptr);
    const char *startWindowBackgroundColor = "FFFFFF";

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor(
        startOptions, startWindowBackgroundColor);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor_003
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest,
    OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    EXPECT_NE(startOptions, nullptr);
    const char *startWindowBackgroundColor = nullptr;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor(
        startOptions, startWindowBackgroundColor);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsStartWindowBackgroundColor_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsStartWindowBackgroundColor
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest,
    OH_AbilityRuntime_GetStartOptionsStartWindowBackgroundColor_001, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = nullptr;
    char *startWindowBackgroundColor;
    size_t size;
    EXPECT_EQ(OH_AbilityRuntime_GetStartOptionsStartWindowBackgroundColor(
        startOptions, &startWindowBackgroundColor, size), ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsStartWindowBackgroundColor_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsStartWindowBackgroundColor
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest,
    OH_AbilityRuntime_GetStartOptionsStartWindowBackgroundColor_002, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    EXPECT_NE(startOptions, nullptr);

    char originalStartWindowBackgroundColor[] = "FFFFFF";
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor(
        startOptions, originalStartWindowBackgroundColor);
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    char *startWindowBackgroundColor = nullptr;
    size_t size = 0;
    EXPECT_EQ(OH_AbilityRuntime_GetStartOptionsStartWindowBackgroundColor(startOptions,
        &startWindowBackgroundColor, size), ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(strcmp(startWindowBackgroundColor, originalStartWindowBackgroundColor), 0);
    EXPECT_EQ(size, strlen(originalStartWindowBackgroundColor));
    free(startWindowBackgroundColor);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsStartWindowBackgroundColor_003
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsStartWindowBackgroundColor
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest,
    OH_AbilityRuntime_GetStartOptionsStartWindowBackgroundColor_003, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    EXPECT_NE(startOptions, nullptr);

    char originalStartWindowBackgroundColor[] = "";
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor(
        startOptions, originalStartWindowBackgroundColor);
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    char *startWindowBackgroundColor = nullptr;
    size_t size = 0;
    EXPECT_EQ(OH_AbilityRuntime_GetStartOptionsStartWindowBackgroundColor(
        startOptions, &startWindowBackgroundColor, size), ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(size, 0);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsSupportedWindowModes_001
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsSupportedWindowModes
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsSupportedWindowModes_001, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = nullptr;
    AbilityRuntime_SupportedWindowMode *supportedWindowModes = nullptr;
    size_t size = 0;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsSupportedWindowModes(
        startOptions, supportedWindowModes, size);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsSupportedWindowModes_002
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsSupportedWindowModes
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsSupportedWindowModes_002, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    EXPECT_NE(startOptions, nullptr);

    AbilityRuntime_SupportedWindowMode supportedWindowModes[1] = { ABILITY_RUNTIME_SUPPORTED_WINDOW_MODE_FULL_SCREEN };
    size_t size = 1;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsSupportedWindowModes(
        startOptions, supportedWindowModes, size);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsSupportedWindowModes_003
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsSupportedWindowModes
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsSupportedWindowModes_003, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    EXPECT_NE(startOptions, nullptr);

    AbilityRuntime_SupportedWindowMode *supportedWindowModes = nullptr;
    size_t size = 0; // Invalid size

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsSupportedWindowModes(
        startOptions, supportedWindowModes, size);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_SetStartOptionsSupportedWindowModes_004
 * @tc.desc: OH_AbilityRuntime_SetStartOptionsSupportedWindowModes
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_SetStartOptionsSupportedWindowModes_004, TestSize.Level1)
{
    // Arrange
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    EXPECT_NE(startOptions, nullptr);

    AbilityRuntime_SupportedWindowMode supportedWindowModes[1] = { ABILITY_RUNTIME_SUPPORTED_WINDOW_MODE_FULL_SCREEN };
    size_t size = MAX_SUPPOPRT_WINDOW_MODES_SIZE + 1; // Invalid size

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsSupportedWindowModes(
        startOptions, supportedWindowModes, size);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsSupportedWindowModes_001
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsSupportedWindowModes
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsSupportedWindowModes_001, TestSize.Level1)
{
    AbilityRuntime_SupportedWindowMode *supportedWindowModes = nullptr;
    size_t size = 0;
    EXPECT_EQ(OH_AbilityRuntime_GetStartOptionsSupportedWindowModes(nullptr, &supportedWindowModes, size),
        ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsSupportedWindowModes_002
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsSupportedWindowModes
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsSupportedWindowModes_002, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    EXPECT_NE(startOptions, nullptr);

    AbilityRuntime_SupportedWindowMode supportedWindowModes[1] = { ABILITY_RUNTIME_SUPPORTED_WINDOW_MODE_FULL_SCREEN };
    size_t size = 1;

    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_SetStartOptionsSupportedWindowModes(
        startOptions, supportedWindowModes, size);
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);

    // Act
    AbilityRuntime_SupportedWindowMode *newSupportWindowModes = nullptr;
    size_t newSize = 0;
    EXPECT_EQ(OH_AbilityRuntime_GetStartOptionsSupportedWindowModes(startOptions, &newSupportWindowModes, newSize),
        ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_NE(newSupportWindowModes, nullptr);
    EXPECT_EQ(newSize, 1);
    free(newSupportWindowModes);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}

/**
 * @tc.name: OH_AbilityRuntime_GetStartOptionsSupportedWindowModes_003
 * @tc.desc: OH_AbilityRuntime_GetStartOptionsSupportedWindowModes
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRuntimeStartOptionsTest, OH_AbilityRuntime_GetStartOptionsSupportedWindowModes_003, TestSize.Level1)
{
    AbilityRuntime_StartOptions *startOptions = OH_AbilityRuntime_CreateStartOptions();
    EXPECT_NE(startOptions, nullptr);

    // Act
    AbilityRuntime_SupportedWindowMode *newSupportWindowModes = nullptr;
    size_t newSize = 0;
    EXPECT_EQ(OH_AbilityRuntime_GetStartOptionsSupportedWindowModes(startOptions, &newSupportWindowModes, newSize),
        ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(newSupportWindowModes, nullptr);
    EXPECT_EQ(newSize, 0);
    OH_AbilityRuntime_DestroyStartOptions(&startOptions);
}
}  // namespace AppExecFwk
}  // namespace OHOS
