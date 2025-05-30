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

#include "start_options_impl.h"

#include "hilog_tag_wrapper.h"
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
#include "pixelmap_native_impl.h"
#endif
#include "process_options.h"
#include "securec.h"
#include "start_window_option.h"

constexpr int MAX_SUPPOPRT_WINDOW_MODES_SIZE = 10;

AbilityRuntime_StartOptions::AbilityRuntime_StartOptions()
{}

OHOS::AAFwk::StartOptions AbilityRuntime_StartOptions::GetInnerStartOptions()
{
    return options;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsWindowMode(AbilityRuntime_WindowMode windowMode)
{
    if (windowMode < ABILITY_RUNTIME_WINDOW_MODE_UNDEFINED ||
        windowMode > ABILITY_RUNTIME_WINDOW_MODE_FULL_SCREEN) {
        TAG_LOGE(AAFwkTag::APPKIT, "windowMode=%{public}d is invalid", static_cast<int32_t>(windowMode));
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    options.SetWindowMode(static_cast<int32_t>(windowMode));
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsWindowMode(AbilityRuntime_WindowMode &windowMode)
{
    windowMode = static_cast<AbilityRuntime_WindowMode>(options.GetWindowMode());
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsDisplayId(int32_t displayId)
{
    options.SetDisplayID(displayId);
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsDisplayId(int32_t &displayId)
{
    displayId = options.GetDisplayID();
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsWithAnimation(bool withAnimation)
{
    options.SetWithAnimation(withAnimation);
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsWithAnimation(bool &withAnimation)
{
    withAnimation = options.GetWithAnimation();
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsWindowLeft(int32_t windowLeft)
{
    options.windowLeftUsed_ = true;
    options.SetWindowLeft(windowLeft);
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsWindowLeft(int32_t &windowLeft)
{
    if (options.windowLeftUsed_) {
        windowLeft = options.GetWindowLeft();
    }
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsWindowTop(int32_t windowTop)
{
    options.windowTopUsed_ = true;
    options.SetWindowTop(windowTop);
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsWindowTop(int32_t &windowTop)
{
    if (options.windowTopUsed_) {
        windowTop = options.GetWindowTop();
    }
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsWindowHeight(int32_t windowHeight)
{
    options.windowHeightUsed_ = true;
    options.SetWindowHeight(windowHeight);
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsWindowHeight(int32_t &windowHeight)
{
    if (options.windowHeightUsed_) {
        windowHeight = options.GetWindowHeight();
    }
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsWindowWidth(int32_t windowWidth)
{
    options.windowWidthUsed_ = true;
    options.SetWindowWidth(windowWidth);
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsWindowWidth(int32_t &windowWidth)
{
    if (options.windowWidthUsed_) {
        windowWidth = options.GetWindowWidth();
    }
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsStartVisibility(
    AbilityRuntime_StartVisibility startVisibility)
{
    if (startVisibility < ABILITY_RUNTIME_HIDE_UPON_START ||
        startVisibility > ABILITY_RUNTIME_SHOW_UPON_START) {
        TAG_LOGE(AAFwkTag::APPKIT, "startVisibility=%{public}d is invalid", static_cast<int32_t>(startVisibility));
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (options.processOptions == nullptr) {
        options.processOptions = std::make_shared<OHOS::AAFwk::ProcessOptions>();
    }
    options.processOptions->startupVisibility =
        static_cast<OHOS::AAFwk::StartupVisibility>(startVisibility);
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsStartVisibility(
    AbilityRuntime_StartVisibility &startVisibility)
{
    if (options.processOptions == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null processOptions");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    startVisibility = static_cast<AbilityRuntime_StartVisibility>(options.processOptions->startupVisibility);
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsStartWindowIcon(
    OH_PixelmapNative *startWindowIcon)
{
    if (startWindowIcon == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startWindowIcon");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (options.startWindowOption == nullptr) {
        options.startWindowOption = std::make_shared<OHOS::AAFwk::StartWindowOption>();
    }
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    options.startWindowOption->startWindowIcon = startWindowIcon->GetInnerPixelmap();
    options.startWindowOption->hasStartWindow =
        (options.startWindowOption->startWindowIcon != nullptr);
#endif
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsStartWindowIcon(
    OH_PixelmapNative **startWindowIcon)
{
    if (options.startWindowOption == nullptr || startWindowIcon == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startWindowOption or startWindowIcon");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (*startWindowIcon != nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "startWindowIcon is not null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    if (options.startWindowOption->hasStartWindow) {
        std::unique_ptr<OH_PixelmapNative> icon = std::make_unique<OH_PixelmapNative>(
            options.startWindowOption->startWindowIcon);
        *startWindowIcon = icon.release();
    }
#endif
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsStartWindowBackgroundColor(
    const char* startWindowBackgroundColor)
{
    if (startWindowBackgroundColor == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startWindowBackgroundColor");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (options.startWindowOption == nullptr) {
        options.startWindowOption = std::make_shared<OHOS::AAFwk::StartWindowOption>();
    }
    options.startWindowOption->startWindowBackgroundColor = startWindowBackgroundColor;
    options.startWindowOption->hasStartWindow =
        !options.startWindowOption->startWindowBackgroundColor.empty();
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsStartWindowBackgroundColor(
    char **startWindowBackgroundColor, size_t &size)
{
    if (options.startWindowOption == nullptr || startWindowBackgroundColor == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startWindowOption or startWindowBackgroundColor");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (*startWindowBackgroundColor != nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "startWindowBackgroundColor is not null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (options.startWindowOption->hasStartWindow) {
        size_t length = options.startWindowOption->startWindowBackgroundColor.size() + 1;
        *startWindowBackgroundColor = static_cast<char*>(malloc(sizeof(char) * length));
        if (*startWindowBackgroundColor == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "startWindowBackgroundColor uninitialized");
            return ABILITY_RUNTIME_ERROR_CODE_INTERNAL;
        }
        if (strcpy_s(*startWindowBackgroundColor, length,
            options.startWindowOption->startWindowBackgroundColor.c_str()) != 0) {
            TAG_LOGE(AAFwkTag::APPKIT, "strcpy_s failed");
            free(*startWindowBackgroundColor);
            return ABILITY_RUNTIME_ERROR_CODE_INTERNAL;
        }
        size = options.startWindowOption->startWindowBackgroundColor.size();
    }
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsSupportedWindowModes(
    AbilityRuntime_SupportedWindowMode* supportedWindowModes, size_t size)
{
    if (supportedWindowModes == nullptr || size == 0 || size > MAX_SUPPOPRT_WINDOW_MODES_SIZE) {
        TAG_LOGE(AAFwkTag::APPKIT, "null supportedWindowModes or size is invalid");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    for (size_t i = 0; i < size; ++i) {
        if (supportedWindowModes[i] < ABILITY_RUNTIME_SUPPORTED_WINDOW_MODE_FULL_SCREEN ||
            supportedWindowModes[i] > ABILITY_RUNTIME_SUPPORTED_WINDOW_MODE_FLOATING) {
            TAG_LOGE(AAFwkTag::APPKIT, "invalild supportWindowMode:%{public}d", supportedWindowModes[i]);
            return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
        }
        options.supportWindowModes_.push_back(
            static_cast<OHOS::AppExecFwk::SupportWindowMode>(supportedWindowModes[i]));
    }
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsSupportedWindowModes(
    AbilityRuntime_SupportedWindowMode **supportedWindowModes, size_t &size)
{
    if (supportedWindowModes == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null supportedWindowModes");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (*supportedWindowModes != nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "supportedWindowModes is not null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (!options.supportWindowModes_.empty()) {
        size = options.supportWindowModes_.size();
        *supportedWindowModes = static_cast<AbilityRuntime_SupportedWindowMode*>(
            malloc(sizeof(AbilityRuntime_SupportedWindowMode) * options.supportWindowModes_.size()));
        if (*supportedWindowModes == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "supportedWindowModes uninitialized");
            return ABILITY_RUNTIME_ERROR_CODE_INTERNAL;
        }
        for (size_t i = 0; i < size; ++i) {
            (*supportedWindowModes)[i] =
                static_cast<AbilityRuntime_SupportedWindowMode>(options.supportWindowModes_[i]);
        }
    }
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsMinWindowWidth(int32_t minWindowWidth)
{
    options.minWindowWidthUsed_ = true;
    options.SetMinWindowWidth(minWindowWidth);
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsMinWindowWidth(int32_t &minWindowWidth)
{
    if (options.minWindowWidthUsed_) {
        minWindowWidth = options.GetMinWindowWidth();
    }
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsMaxWindowWidth(int32_t maxWindowWidth)
{
    options.maxWindowWidthUsed_ = true;
    options.SetMaxWindowWidth(maxWindowWidth);
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsMaxWindowWidth(int32_t &maxWindowWidth)
{
    if (options.maxWindowWidthUsed_) {
        maxWindowWidth = options.GetMaxWindowWidth();
    }
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsMinWindowHeight(int32_t minWindowHeight)
{
    options.minWindowHeightUsed_ = true;
    options.SetMinWindowHeight(minWindowHeight);
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsMinWindowHeight(int32_t &minWindowHeight)
{
    if (options.minWindowHeightUsed_) {
        minWindowHeight = options.GetMinWindowHeight();
    }
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::SetStartOptionsMaxWindowHeight(int32_t maxWindowHeight)
{
    options.maxWindowHeightUsed_ = true;
    options.SetMaxWindowHeight(maxWindowHeight);
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode AbilityRuntime_StartOptions::GetStartOptionsMaxWindowHeight(int32_t &maxWindowHeight)
{
    if (options.maxWindowHeightUsed_) {
        maxWindowHeight = options.GetMaxWindowHeight();
    }
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}