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

#ifndef ABILITY_RUNTIME_START_OPTIONS_IMPL_H
#define ABILITY_RUNTIME_START_OPTIONS_IMPL_H

#include "ability_manager/include/start_options.h"
#include "ability_runtime_common.h"
#include "context_constant.h"

#ifdef __cplusplus
extern "C" {
#endif

struct OH_PixelmapNative;
typedef struct OH_PixelmapNative OH_PixelmapNative;

struct AbilityRuntime_StartOptions {
public:
    AbilityRuntime_StartOptions();
    OHOS::AAFwk::StartOptions GetInnerStartOptions();

    AbilityRuntime_ErrorCode SetStartOptionsWindowMode(AbilityRuntime_WindowMode windowMode);
    AbilityRuntime_ErrorCode GetStartOptionsWindowMode(AbilityRuntime_WindowMode &windowMode);
    AbilityRuntime_ErrorCode SetStartOptionsDisplayId(int32_t displayId);
    AbilityRuntime_ErrorCode GetStartOptionsDisplayId(int32_t &displayId);
    AbilityRuntime_ErrorCode SetStartOptionsWithAnimation(bool withAnimation);
    AbilityRuntime_ErrorCode GetStartOptionsWithAnimation(bool &withAnimation);
    AbilityRuntime_ErrorCode SetStartOptionsWindowLeft(int32_t windowLeft);
    AbilityRuntime_ErrorCode GetStartOptionsWindowLeft(int32_t &windowLeft);
    AbilityRuntime_ErrorCode SetStartOptionsWindowTop(int32_t windowTop);
    AbilityRuntime_ErrorCode GetStartOptionsWindowTop(int32_t &windowTop);
    AbilityRuntime_ErrorCode SetStartOptionsWindowHeight(int32_t windowHeight);
    AbilityRuntime_ErrorCode GetStartOptionsWindowHeight(int32_t &windowHeight);
    AbilityRuntime_ErrorCode SetStartOptionsWindowWidth(int32_t windowWidth);
    AbilityRuntime_ErrorCode GetStartOptionsWindowWidth(int32_t &windowWidth);
    AbilityRuntime_ErrorCode SetStartOptionsStartVisibility(AbilityRuntime_StartVisibility startVisibility);
    AbilityRuntime_ErrorCode GetStartOptionsStartVisibility(AbilityRuntime_StartVisibility &startVisibility);
    AbilityRuntime_ErrorCode SetStartOptionsStartWindowIcon(OH_PixelmapNative *startWindowIcon);
    AbilityRuntime_ErrorCode GetStartOptionsStartWindowIcon(OH_PixelmapNative **startWindowIcon);
    AbilityRuntime_ErrorCode SetStartOptionsStartWindowBackgroundColor(const char *startWindowBackgroundColor);
    AbilityRuntime_ErrorCode GetStartOptionsStartWindowBackgroundColor(char **startWindowBackgroundColor,
        size_t &size);
    AbilityRuntime_ErrorCode SetStartOptionsSupportedWindowModes(
        AbilityRuntime_SupportedWindowMode *supportedWindowModes, size_t size);
    AbilityRuntime_ErrorCode GetStartOptionsSupportedWindowModes(
        AbilityRuntime_SupportedWindowMode **supportedWindowModes, size_t &size);
    AbilityRuntime_ErrorCode SetStartOptionsMinWindowWidth(int32_t minWindowWidth);
    AbilityRuntime_ErrorCode GetStartOptionsMinWindowWidth(int32_t &minWindowWidth);
    AbilityRuntime_ErrorCode SetStartOptionsMaxWindowWidth(int32_t maxWindowWidth);
    AbilityRuntime_ErrorCode GetStartOptionsMaxWindowWidth(int32_t &maxWindowWidth);
    AbilityRuntime_ErrorCode SetStartOptionsMinWindowHeight(int32_t minWindowHeight);
    AbilityRuntime_ErrorCode GetStartOptionsMinWindowHeight(int32_t &minWindowHeight);
    AbilityRuntime_ErrorCode SetStartOptionsMaxWindowHeight(int32_t maxWindowHeight);
    AbilityRuntime_ErrorCode GetStartOptionsMaxWindowHeight(int32_t &maxWindowHeight);

private:
    OHOS::AAFwk::StartOptions options;
};

#ifdef __cplusplus
} // extern "C"
#endif

#endif // ABILITY_RUNTIME_START_OPTIONS_IMPL_H