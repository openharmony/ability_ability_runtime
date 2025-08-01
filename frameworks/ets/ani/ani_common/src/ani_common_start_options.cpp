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

#include "ability_info.h"
#include "ani_common_start_options.h"
#include "hilog_tag_wrapper.h"
#include "ani_enum_convert.h"
#include "int_wrapper.h"
#include "process_options.h"
#include "start_window_option.h"
#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {

bool UnwrapStartOptionsWithProcessOption(ani_env* env, ani_object param, AAFwk::StartOptions &startOptions)
{
    TAG_LOGD(AAFwkTag::ANI, "UnwrapStartOptionsWithProcessOption called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    if (!UnwrapStartOptions(env, param, startOptions)) {
        TAG_LOGE(AAFwkTag::ANI, "Unwrap UnwrapStartOptions failed");
        return false;
    }
    if (!UnwrapProcessOptions(env, param, startOptions.processOptions)) {
        TAG_LOGE(AAFwkTag::ANI, "Unwrap processOptions failed");
        return false;
    }
    if (!UnwrapStartWindowOption(env, param, startOptions.startWindowOption)) {
        TAG_LOGE(AAFwkTag::ANI, "Unwrap startWindowOption failed");
        return false;
    }
    return true;
}

void UnwrapStartOptionsWindowOptions(ani_env *env, ani_object param, AAFwk::StartOptions &startOptions)
{
    ani_double windowLeft = 0.0;
    if (GetFieldDoubleByName(env, param, "windowLeft", windowLeft)) {
        TAG_LOGD(AAFwkTag::ANI, "windowLeft:%{public}f", windowLeft);
        startOptions.SetWindowLeft(windowLeft);
        startOptions.windowLeftUsed_ = true;
    }

    ani_double windowTop = 0.0;
    if (GetFieldDoubleByName(env, param, "windowTop", windowTop)) {
        TAG_LOGD(AAFwkTag::ANI, "windowTop:%{public}f", windowTop);
        startOptions.SetWindowTop(windowTop);
        startOptions.windowTopUsed_ = true;
    }

    ani_double windowWidth = 0.0;
    if (GetFieldDoubleByName(env, param, "windowWidth", windowWidth)) {
        TAG_LOGD(AAFwkTag::ANI, "windowWidth:%{public}f", windowWidth);
        startOptions.SetWindowWidth(windowWidth);
        startOptions.windowWidthUsed_ = true;
    }

    ani_double windowHeight = 0.0;
    if (GetFieldDoubleByName(env, param, "windowHeight", windowHeight)) {
        TAG_LOGD(AAFwkTag::ANI, "windowHeight:%{public}f", windowHeight);
        startOptions.SetWindowHeight(windowHeight);
        startOptions.windowHeightUsed_ = true;
    }

    ani_double minWindowWidth = 0.0;
    if (GetFieldDoubleByName(env, param, "minWindowWidth", minWindowWidth)) {
        TAG_LOGD(AAFwkTag::ANI, "minWindowWidth:%{public}f", minWindowWidth);
        startOptions.SetMinWindowWidth(minWindowWidth);
        startOptions.minWindowWidthUsed_ = true;
    }

    ani_double minWindowHeight = 0.0;
    if (GetFieldDoubleByName(env, param, "minWindowHeight", minWindowHeight)) {
        TAG_LOGD(AAFwkTag::ANI, "minWindowHeight:%{public}f", minWindowHeight);
        startOptions.SetMinWindowHeight(minWindowHeight);
        startOptions.minWindowHeightUsed_ = true;
    }

    ani_double maxWindowWidth = 0.0;
    if (GetFieldDoubleByName(env, param, "maxWindowWidth", maxWindowWidth)) {
        TAG_LOGD(AAFwkTag::ANI, "maxWindowWidth:%{public}f", maxWindowWidth);
        startOptions.SetMaxWindowWidth(maxWindowWidth);
        startOptions.maxWindowWidthUsed_ = true;
    }

    ani_double maxWindowHeight = 0.0;
    if (GetFieldDoubleByName(env, param, "maxWindowHeight", maxWindowHeight)) {
        TAG_LOGD(AAFwkTag::ANI, "maxWindowHeight:%{public}f", maxWindowHeight);
        startOptions.SetMaxWindowHeight(maxWindowHeight);
        startOptions.maxWindowHeightUsed_ = true;
    }
}

bool SetSupportWindowModes(ani_env *env, ani_object param, AAFwk::StartOptions &startOptions)
{
    ani_ref supportWindowModesRef = nullptr;
    ani_boolean hasValue = true;
    if (GetPropertyRef(env, param, "supportWindowModes", supportWindowModesRef, hasValue) && !hasValue) {
        ani_array_ref supportWindowModesArr = reinterpret_cast<ani_array_ref>(supportWindowModesRef);
        ani_size supportWindowModesLen = 0;
        if (env->Array_GetLength(supportWindowModesArr, &supportWindowModesLen) != ANI_OK) {
            TAG_LOGE(AAFwkTag::ANI, "Array_GetLength failed");
            return false;
        }
        for (size_t i = 0; i < supportWindowModesLen; ++i) {
            ani_ref supportWindowModeRef = nullptr;
            int32_t supportWindowMode = 0;
            if (env->Array_Get_Ref(supportWindowModesArr, i, &supportWindowModeRef) != ANI_OK) {
                TAG_LOGE(AAFwkTag::ANI, "Array_Get_Ref failed");
                return false;
            }
            AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(
                env, reinterpret_cast<ani_object>(supportWindowModeRef), supportWindowMode);
            TAG_LOGD(AAFwkTag::ANI, "supportWindowMode:%{public}d", supportWindowMode);
            startOptions.supportWindowModes_.emplace_back(
                static_cast<AppExecFwk::SupportWindowMode>(supportWindowMode));
        }
    }
    return true;
}


bool UnwrapStartOptions(ani_env *env, ani_object param, AAFwk::StartOptions &startOptions)
{
    TAG_LOGD(AAFwkTag::ANI, "UnwrapStartOptions called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }

    ani_double windowMode = 0.0;
    if (GetFieldDoubleByName(env, param, "windowMode", windowMode)) {
        TAG_LOGD(AAFwkTag::ANI, "windowMode:%{public}f", windowMode);
        startOptions.SetWindowMode(windowMode);
    }

    ani_double displayId = 0.0;
    if (GetFieldDoubleByName(env, param, "displayId", displayId)) {
        startOptions.SetDisplayID(static_cast<int>(displayId));
    }

    bool withAnimation = true;
    if (GetFieldBoolByName(env, param, "withAnimation", withAnimation)) {
        TAG_LOGD(AAFwkTag::ANI, "withAnimation:%{public}hhu", withAnimation);
        startOptions.SetWithAnimation(withAnimation);
    }

    UnwrapStartOptionsWindowOptions(env, param, startOptions);

    bool windowFocused = true;
    if (GetFieldBoolByName(env, param, "windowFocused", windowFocused)) {
        TAG_LOGD(AAFwkTag::ANI, "windowFocused:%{public}hhu", windowFocused);
        startOptions.SetWindowFocused(windowFocused);
    }

    if (!SetSupportWindowModes(env, param, startOptions)) {
        TAG_LOGE(AAFwkTag::ANI, "SetSupportWindowModes failed");
        return false;
    }

    return true;
}

bool UnwrapProcessOptions(ani_env* env, ani_object param, std::shared_ptr<AAFwk::ProcessOptions> &processOptions)
{
    auto option = std::make_shared<AAFwk::ProcessOptions>();

    ani_boolean isProcessModeUndefined = true;
    ani_ref processModeRef = nullptr;
    if (!GetPropertyRef(env, param, "processMode", processModeRef, isProcessModeUndefined)) {
        TAG_LOGE(AAFwkTag::ANI, "Unwrap processMode failed");
        return false;
    }

    ani_boolean isStartupVisibilityUndefined = true;
    ani_ref startupVisibilityRef = nullptr;
    if (!GetPropertyRef(env, param, "startupVisibility", startupVisibilityRef, isStartupVisibilityUndefined)) {
        TAG_LOGE(AAFwkTag::ANI, "Unwrap startupVisibility failed");
        return false;
    }

    if (isProcessModeUndefined && isStartupVisibilityUndefined) {
        return true;
    }

    int32_t processMode = 0;
    if (isProcessModeUndefined) {
        TAG_LOGE(AAFwkTag::ANI, "Unwrap processMode failed");
        return false;
    }
    AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(
        env, reinterpret_cast<ani_enum_item>(processModeRef), processMode);
    TAG_LOGD(AAFwkTag::ANI, "processMode: %{public}d", processMode);
    option->processMode = AAFwk::ProcessOptions::ConvertInt32ToProcessMode(processMode);
    if (option->processMode == AAFwk::ProcessMode::UNSPECIFIED) {
        TAG_LOGE(AAFwkTag::ANI, "Convert processMode failed");
        return false;
    }

    int32_t startupVisibility = 0;
    if (isStartupVisibilityUndefined) {
        TAG_LOGE(AAFwkTag::ANI, "Unwrap startupVisibility failed");
        return false;
    }
    AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(
        env, reinterpret_cast<ani_enum_item>(startupVisibilityRef), startupVisibility);
    TAG_LOGD(AAFwkTag::ANI, "startupVisibility: %{public}d", startupVisibility);
    option->startupVisibility = AAFwk::ProcessOptions::ConvertInt32ToStartupVisibility(startupVisibility);
    if (option->startupVisibility == AAFwk::StartupVisibility::UNSPECIFIED) {
        TAG_LOGE(AAFwkTag::ANI, "Convert startupVisibility failed");
        return false;
    }

    processOptions = option;
    return true;
}

#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
bool UnwrapPixelMapFromAni(ani_env *env, ani_object param, std::shared_ptr<Media::PixelMap> &value)
{
    auto pixelMap = OHOS::Media::ImageAniUtils::GetPixelMapFromEnvSp(env, param);
    if (!pixelMap) {
        TAG_LOGE(AAFwkTag::ANI, "Unwrap pixelMap failed");
        return false;
    }

    value = pixelMap;
    return true;
}

bool UnwrapPixelMapByPropertyName(
    ani_env *env, ani_object param, const char *propertyName, std::shared_ptr<Media::PixelMap> &value)
{
    ani_ref envValue = nullptr;
    if (!GetFieldRefByName(env, param, propertyName, envValue)) {
        TAG_LOGE(AAFwkTag::ANI, "Get PixelMap failed");
        return false;
    }
    if (envValue == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "UnwrapPixelMapByPropertyName failed");
        return false;
    }
    return UnwrapPixelMapFromAni(env, reinterpret_cast<ani_object>(envValue), value);
}
#endif

bool UnwrapStartWindowOption(ani_env *env, ani_object param,
    std::shared_ptr<AAFwk::StartWindowOption> &startWindowOption)
{
    auto option = std::make_shared<AAFwk::StartWindowOption>();
    std::string startWindowBackgroundColor;
    if (IsExistsField(env, param, "startWindowBackgroundColor")) {
        if (!GetFieldStringByName(env, param, "startWindowBackgroundColor", startWindowBackgroundColor)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Unwrap startWindowBackgroundColor failed");
            return false;
        }
        option->startWindowBackgroundColor = startWindowBackgroundColor;
    }
    if (!startWindowBackgroundColor.empty()) {
        option->hasStartWindow = true;
    }
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
    std::shared_ptr<Media::PixelMap> startWindowIcon = nullptr;
    if (IsExistsField(env, param, "startWindowIcon")) {
        if (!UnwrapPixelMapByPropertyName(env, param, "startWindowIcon", startWindowIcon)) {
            TAG_LOGE(AAFwkTag::ANI, "Unwrap startWindowIcon failed");
            return false;
        }
        option->startWindowIcon = startWindowIcon;
    }

    if (startWindowIcon != nullptr) {
        option->hasStartWindow = true;
    }
#endif
    startWindowOption = option;
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS