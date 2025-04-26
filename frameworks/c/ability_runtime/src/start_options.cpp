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

#include "start_options.h"

#include "start_options_impl.h"
#include "hilog_tag_wrapper.h"
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

AbilityRuntime_StartOptions* OH_AbilityRuntime_CreateStartOptions(void)
{
    std::unique_ptr<AbilityRuntime_StartOptions> options = std::make_unique<AbilityRuntime_StartOptions>();
    return options.release();
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_DestroyStartOptions(AbilityRuntime_StartOptions **startOptions)
{
    if (startOptions == nullptr || *startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    delete *startOptions;
    *startOptions = nullptr;
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsWindowMode(AbilityRuntime_StartOptions *startOptions,
    AbilityRuntime_WindowMode windowMode)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsWindowMode(windowMode);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsWindowMode(AbilityRuntime_StartOptions *startOptions,
    AbilityRuntime_WindowMode &windowMode)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsWindowMode(windowMode);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsDisplayId(AbilityRuntime_StartOptions *startOptions,
    int32_t displayId)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsDisplayId(displayId);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsDisplayId(AbilityRuntime_StartOptions *startOptions,
    int32_t &displayId)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsDisplayId(displayId);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsWithAnimation(AbilityRuntime_StartOptions *startOptions,
    bool withAnimation)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsWithAnimation(withAnimation);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsWithAnimation(AbilityRuntime_StartOptions *startOptions,
    bool &withAnimation)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsWithAnimation(withAnimation);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsWindowLeft(AbilityRuntime_StartOptions *startOptions,
    int32_t windowLeft)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsWindowLeft(windowLeft);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsWindowLeft(AbilityRuntime_StartOptions *startOptions,
    int32_t &windowLeft)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsWindowLeft(windowLeft);
}
    
AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsWindowTop(AbilityRuntime_StartOptions *startOptions,
    int32_t windowTop)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsWindowTop(windowTop);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsWindowTop(AbilityRuntime_StartOptions *startOptions,
    int32_t &windowTop)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsWindowTop(windowTop);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsWindowHeight(AbilityRuntime_StartOptions *startOptions,
    int32_t windowHeight)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsWindowHeight(windowHeight);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsWindowHeight(AbilityRuntime_StartOptions *startOptions,
    int32_t &windowHeight)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsWindowHeight(windowHeight);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsWindowWidth(AbilityRuntime_StartOptions *startOptions,
    int32_t windowWidth)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsWindowWidth(windowWidth);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsWindowWidth(AbilityRuntime_StartOptions *startOptions,
    int32_t &windowWidth)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsWindowWidth(windowWidth);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsStartVisibility(AbilityRuntime_StartOptions *startOptions,
    AbilityRuntime_StartVisibility startVisibility)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsStartVisibility(startVisibility);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsStartVisibility(AbilityRuntime_StartOptions *startOptions,
    AbilityRuntime_StartVisibility &startVisibility)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsStartVisibility(startVisibility);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsStartWindowIcon(AbilityRuntime_StartOptions *startOptions,
    OH_PixelmapNative *startWindowIcon)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsStartWindowIcon(startWindowIcon);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsStartWindowIcon(AbilityRuntime_StartOptions *startOptions,
    OH_PixelmapNative **startWindowIcon)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsStartWindowIcon(startWindowIcon);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsStartWindowBackgroundColor(
    AbilityRuntime_StartOptions *startOptions, const char *startWindowBackgroundColor)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsStartWindowBackgroundColor(startWindowBackgroundColor);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsStartWindowBackgroundColor(
    AbilityRuntime_StartOptions *startOptions, char **startWindowBackgroundColor, size_t &size)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsStartWindowBackgroundColor(startWindowBackgroundColor, size);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsSupportedWindowModes(
    AbilityRuntime_StartOptions *startOptions, AbilityRuntime_SupportedWindowMode *supportedWindowModes,
    size_t size)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsSupportedWindowModes(supportedWindowModes, size);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsSupportedWindowModes(
    AbilityRuntime_StartOptions *startOptions, AbilityRuntime_SupportedWindowMode **supportedWindowModes,
    size_t &size)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsSupportedWindowModes(supportedWindowModes, size);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsMinWindowWidth(
    AbilityRuntime_StartOptions *startOptions, int32_t minWindowWidth)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsMinWindowWidth(minWindowWidth);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsMinWindowWidth(
    AbilityRuntime_StartOptions *startOptions, int32_t &minWindowWidth)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsMinWindowWidth(minWindowWidth);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsMaxWindowWidth(
    AbilityRuntime_StartOptions *startOptions, int32_t maxWindowWidth)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsMaxWindowWidth(maxWindowWidth);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsMaxWindowWidth(
    AbilityRuntime_StartOptions *startOptions, int32_t &maxWindowWidth)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsMaxWindowWidth(maxWindowWidth);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsMinWindowHeight(
    AbilityRuntime_StartOptions *startOptions, int32_t minWindowHeight)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsMinWindowHeight(minWindowHeight);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsMinWindowHeight(
    AbilityRuntime_StartOptions *startOptions, int32_t &minWindowHeight)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsMinWindowHeight(minWindowHeight);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_SetStartOptionsMaxWindowHeight(
    AbilityRuntime_StartOptions *startOptions, int32_t maxWindowHeight)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->SetStartOptionsMaxWindowHeight(maxWindowHeight);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_GetStartOptionsMaxWindowHeight(
    AbilityRuntime_StartOptions *startOptions, int32_t &maxWindowHeight)
{
    if (startOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return startOptions->GetStartOptionsMaxWindowHeight(maxWindowHeight);
}

#ifdef __cplusplus
} // extern "C"
#endif
