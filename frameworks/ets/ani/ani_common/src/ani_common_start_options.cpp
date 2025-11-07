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
namespace {
const std::string APP_LINKING_ONLY = "appLinkingOnly";
}

bool UnwrapStartOptionsWithProcessOption(ani_env* env, ani_object param, AAFwk::StartOptions &startOptions)
{
    TAG_LOGD(AAFwkTag::BRIDGE, "UnwrapStartOptionsWithProcessOption called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::BRIDGE, "null env");
        return false;
    }
    if (!UnwrapStartOptions(env, param, startOptions)) {
        TAG_LOGE(AAFwkTag::BRIDGE, "Unwrap UnwrapStartOptions failed");
        return false;
    }
    if (!UnwrapProcessOptions(env, param, startOptions.processOptions)) {
        TAG_LOGE(AAFwkTag::BRIDGE, "Unwrap processOptions failed");
        return false;
    }
    if (!UnwrapStartWindowOption(env, param, startOptions.startWindowOption)) {
        TAG_LOGE(AAFwkTag::BRIDGE, "Unwrap startWindowOption failed");
        return false;
    }
    return true;
}

void UnwrapStartOptionsWindowOptions(ani_env *env, ani_object param, AAFwk::StartOptions &startOptions)
{
    ani_int windowLeft = 0;
    if (GetFieldIntByName(env, param, "windowLeft", windowLeft)) {
        TAG_LOGD(AAFwkTag::BRIDGE, "windowLeft:%{public}d", windowLeft);
        startOptions.SetWindowLeft(windowLeft);
        startOptions.windowLeftUsed_ = true;
    }

    ani_int windowTop = 0;
    if (GetFieldIntByName(env, param, "windowTop", windowTop)) {
        TAG_LOGD(AAFwkTag::BRIDGE, "windowTop:%{public}d", windowTop);
        startOptions.SetWindowTop(windowTop);
        startOptions.windowTopUsed_ = true;
    }

    ani_int windowWidth = 0;
    if (GetFieldIntByName(env, param, "windowWidth", windowWidth)) {
        TAG_LOGD(AAFwkTag::BRIDGE, "windowWidth:%{public}d", windowWidth);
        startOptions.SetWindowWidth(windowWidth);
        startOptions.windowWidthUsed_ = true;
    }

    ani_int windowHeight = 0;
    if (GetFieldIntByName(env, param, "windowHeight", windowHeight)) {
        TAG_LOGD(AAFwkTag::BRIDGE, "windowHeight:%{public}d", windowHeight);
        startOptions.SetWindowHeight(windowHeight);
        startOptions.windowHeightUsed_ = true;
    }

    ani_int minWindowWidth = 0;
    if (GetFieldIntByName(env, param, "minWindowWidth", minWindowWidth)) {
        TAG_LOGD(AAFwkTag::BRIDGE, "minWindowWidth:%{public}d", minWindowWidth);
        startOptions.SetMinWindowWidth(minWindowWidth);
        startOptions.minWindowWidthUsed_ = true;
    }

    ani_int minWindowHeight = 0;
    if (GetFieldIntByName(env, param, "minWindowHeight", minWindowHeight)) {
        TAG_LOGD(AAFwkTag::BRIDGE, "minWindowHeight:%{public}d", minWindowHeight);
        startOptions.SetMinWindowHeight(minWindowHeight);
        startOptions.minWindowHeightUsed_ = true;
    }

    ani_int maxWindowWidth = 0;
    if (GetFieldIntByName(env, param, "maxWindowWidth", maxWindowWidth)) {
        TAG_LOGD(AAFwkTag::BRIDGE, "maxWindowWidth:%{public}d", maxWindowWidth);
        startOptions.SetMaxWindowWidth(maxWindowWidth);
        startOptions.maxWindowWidthUsed_ = true;
    }

    ani_int maxWindowHeight = 0;
    if (GetFieldIntByName(env, param, "maxWindowHeight", maxWindowHeight)) {
        TAG_LOGD(AAFwkTag::BRIDGE, "maxWindowHeight:%{public}d", maxWindowHeight);
        startOptions.SetMaxWindowHeight(maxWindowHeight);
        startOptions.maxWindowHeightUsed_ = true;
    }
}

bool SetSupportWindowModes(ani_env *env, ani_object param, AAFwk::StartOptions &startOptions)
{
    ani_ref supportWindowModesRef = nullptr;
    ani_boolean hasValue = true;
    if (GetPropertyRef(env, param, "supportWindowModes", supportWindowModesRef, hasValue) && !hasValue) {
        ani_array supportWindowModesArr = reinterpret_cast<ani_array>(supportWindowModesRef);
        ani_size supportWindowModesLen = 0;
        if (env->Array_GetLength(supportWindowModesArr, &supportWindowModesLen) != ANI_OK) {
            TAG_LOGE(AAFwkTag::BRIDGE, "Array_GetLength failed");
            return false;
        }
        for (size_t i = 0; i < supportWindowModesLen; ++i) {
            ani_ref supportWindowModeRef = nullptr;
            int32_t supportWindowMode = 0;
            if (env->Array_Get(supportWindowModesArr, i, &supportWindowModeRef) != ANI_OK) {
                TAG_LOGE(AAFwkTag::BRIDGE, "Array_Get_Ref failed");
                return false;
            }
            AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(
                env, reinterpret_cast<ani_object>(supportWindowModeRef), supportWindowMode);
            TAG_LOGD(AAFwkTag::BRIDGE, "supportWindowMode:%{public}d", supportWindowMode);
            startOptions.supportWindowModes_.emplace_back(
                static_cast<AppExecFwk::SupportWindowMode>(supportWindowMode));
        }
    }
    return true;
}


bool UnwrapStartOptions(ani_env *env, ani_object param, AAFwk::StartOptions &startOptions)
{
    TAG_LOGD(AAFwkTag::BRIDGE, "UnwrapStartOptions called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::BRIDGE, "null env");
        return false;
    }

    ani_int windowMode = 0;
    if (GetFieldIntByName(env, param, "windowMode", windowMode)) {
        TAG_LOGD(AAFwkTag::BRIDGE, "windowMode:%{public}d", windowMode);
        startOptions.SetWindowMode(windowMode);
    }

    ani_long displayId = 0;
    if (GetFieldLongByName(env, param, "displayId", displayId)) {
        startOptions.SetDisplayID(static_cast<int>(displayId));
    }

    bool withAnimation = true;
    if (GetFieldBoolByName(env, param, "withAnimation", withAnimation)) {
        TAG_LOGD(AAFwkTag::BRIDGE, "withAnimation:%{public}hhu", withAnimation);
        startOptions.SetWithAnimation(withAnimation);
    }

    UnwrapStartOptionsWindowOptions(env, param, startOptions);

    bool windowFocused = true;
    if (GetFieldBoolByName(env, param, "windowFocused", windowFocused)) {
        TAG_LOGD(AAFwkTag::BRIDGE, "windowFocused:%{public}hhu", windowFocused);
        startOptions.SetWindowFocused(windowFocused);
    }

    bool hideStartWindow = true;
    if (GetFieldBoolByName(env, param, "hideStartWindow", hideStartWindow)) {
        TAG_LOGD(AAFwkTag::BRIDGE, "hideStartWindow:%{public}d", hideStartWindow);
        startOptions.SetHideStartWindow(hideStartWindow);
    }

    if (!SetSupportWindowModes(env, param, startOptions)) {
        TAG_LOGE(AAFwkTag::BRIDGE, "SetSupportWindowModes failed");
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
        TAG_LOGE(AAFwkTag::BRIDGE, "Unwrap processMode failed");
        return false;
    }

    ani_boolean isStartupVisibilityUndefined = true;
    ani_ref startupVisibilityRef = nullptr;
    if (!GetPropertyRef(env, param, "startupVisibility", startupVisibilityRef, isStartupVisibilityUndefined)) {
        TAG_LOGE(AAFwkTag::BRIDGE, "Unwrap startupVisibility failed");
        return false;
    }

    if (isProcessModeUndefined && isStartupVisibilityUndefined) {
        return true;
    }

    int32_t processMode = 0;
    if (isProcessModeUndefined) {
        TAG_LOGE(AAFwkTag::BRIDGE, "Unwrap processMode failed");
        return false;
    }
    AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(
        env, reinterpret_cast<ani_enum_item>(processModeRef), processMode);
    TAG_LOGD(AAFwkTag::BRIDGE, "processMode: %{public}d", processMode);
    option->processMode = AAFwk::ProcessOptions::ConvertInt32ToProcessMode(processMode);
    if (option->processMode == AAFwk::ProcessMode::UNSPECIFIED) {
        TAG_LOGE(AAFwkTag::BRIDGE, "Convert processMode failed");
        return false;
    }

    int32_t startupVisibility = 0;
    if (isStartupVisibilityUndefined) {
        TAG_LOGE(AAFwkTag::BRIDGE, "Unwrap startupVisibility failed");
        return false;
    }
    AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(
        env, reinterpret_cast<ani_enum_item>(startupVisibilityRef), startupVisibility);
    TAG_LOGD(AAFwkTag::BRIDGE, "startupVisibility: %{public}d", startupVisibility);
    option->startupVisibility = AAFwk::ProcessOptions::ConvertInt32ToStartupVisibility(startupVisibility);
    if (option->startupVisibility == AAFwk::StartupVisibility::UNSPECIFIED) {
        TAG_LOGE(AAFwkTag::BRIDGE, "Convert startupVisibility failed");
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
        TAG_LOGE(AAFwkTag::BRIDGE, "Unwrap pixelMap failed");
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
        TAG_LOGE(AAFwkTag::BRIDGE, "Get PixelMap failed");
        return false;
    }
    if (envValue == nullptr) {
        TAG_LOGE(AAFwkTag::BRIDGE, "UnwrapPixelMapByPropertyName failed");
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
            TAG_LOGE(AAFwkTag::BRIDGE, "Unwrap startWindowBackgroundColor failed");
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
            TAG_LOGE(AAFwkTag::BRIDGE, "Unwrap startWindowIcon failed");
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

bool UnwrapAtomicServiceOptions(ani_env *env, ani_object optionsObj, AAFwk::Want &want,
    AAFwk::StartOptions &startOptions)
{
    if (!UnwrapStartOptionsWithProcessOption(env, optionsObj, startOptions)) {
        TAG_LOGE(AAFwkTag::BRIDGE, "UnwrapStartOptions filed");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_ref paramRef = nullptr;
    if ((status = env->Object_GetPropertyByName_Ref(optionsObj, "parameters", &paramRef))  == ANI_OK) {
        AAFwk::WantParams wantParam;
        if (UnwrapWantParams(env, paramRef, wantParam)) {
            want.SetParams(wantParam);
        } else {
            TAG_LOGE(AAFwkTag::BRIDGE, "UnwrapWantParams failed");
        }
    }
    int32_t flags = 0;
    if (GetIntPropertyObject(env, optionsObj, "flags", flags)) {
        want.SetFlags(flags);
    }
    return true;
}

void UnWrapOpenLinkOptions(
    ani_env *env, ani_object optionsObj, AAFwk::OpenLinkOptions &openLinkOptions, AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::BRIDGE, "UnWrapOpenLinkOptions");
    ani_status status = ANI_ERROR;
    ani_ref paramRef = nullptr;
    if ((status = env->Object_GetPropertyByName_Ref(optionsObj, "parameters", &paramRef)) == ANI_OK) {
        AAFwk::WantParams wantParam;
        if (AppExecFwk::UnwrapWantParams(env, paramRef, wantParam)) {
            want.SetParams(wantParam);
        } else {
            TAG_LOGE(AAFwkTag::BRIDGE, "UnwrapWantParams failed");
        }
    }
    if ((status = env->Object_GetPropertyByName_Ref(optionsObj, APP_LINKING_ONLY.c_str(), &paramRef)) == ANI_OK) {
        bool appLinkingOnly = false;
        AppExecFwk::GetBooleanPropertyObject(env, optionsObj, "appLinkingOnly", appLinkingOnly);
        openLinkOptions.SetAppLinkingOnly(appLinkingOnly);
        want.SetParam(APP_LINKING_ONLY, appLinkingOnly);
    }
    if (!want.HasParameter(APP_LINKING_ONLY)) {
        want.SetParam(APP_LINKING_ONLY, false);
    }
}
} // namespace AppExecFwk
} // namespace OHOS