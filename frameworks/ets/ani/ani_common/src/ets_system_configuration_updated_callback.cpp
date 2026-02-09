/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "ets_system_configuration_updated_callback.h"

#include "ani_common_util.h"
#include "ani_enum_convert.h"
#include "ani_enum_convert.h"
#include "configuration.h"
#include "configuration_convertor.h"
#include "hilog_tag_wrapper.h"
#include "res_common.h"

namespace {
constexpr const char *COLOR_MODE_ENUM_NAME = "@ohos.app.ability.ConfigurationConstant.ConfigurationConstant.ColorMode";

bool IsValidValue(const char *end, const std::string &str)
{
    if (!end) {
        return false;
    }

    if (end == str.c_str() || errno == ERANGE || *end != '\0') {
        return false;
    }
    return true;
}

bool ConvertToDouble(const std::string &str, double &outValue)
{
    if (str.empty()) {
        TAG_LOGW(AAFwkTag::JSNAPI, "ConvertToDouble failed str is null");
        return false;
    }
    char *end = nullptr;
    errno = 0;
    double value = std::strtod(str.c_str(), &end);
    if (!IsValidValue(end, str)) {
        TAG_LOGW(AAFwkTag::APPKIT, "ConvertToDouble failed for: %{public}s", str.c_str());
        return false;
    }
    outValue = value;
    return true;
}

}  // namespace
namespace OHOS {
namespace AbilityRuntime {
EtsSystemConfigurationUpdatedCallback::EtsSystemConfigurationUpdatedCallback(ani_vm *etsVm) : etsVm_(etsVm)
{}

void EtsSystemConfigurationUpdatedCallback::Register(ani_object aniCallback)
{
    if (aniCallback == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env or aniCallback");
        return;
    }
    ani_ref aniCallbackRef = nullptr;
    ani_status status = ANI_ERROR;
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed");
        return;
    }

    for (auto callback : callbacksRef_) {
        if (IsEquel(env, aniCallback, callback)) {
            TAG_LOGW(AAFwkTag::APPKIT, "callback exist");
            return;
        }
    }
    if ((status = env->GlobalReference_Create(aniCallback, &aniCallbackRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Create status : %{public}d", status);
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    {
        std::lock_guard lock(mutex_);
        callbacksRef_.emplace(aniCallbackRef);
    }
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

bool EtsSystemConfigurationUpdatedCallback::IsEquel(ani_env *env, ani_object aniCallback, ani_ref refCallback)
{
    ani_boolean isEqual = false;
    env->Reference_StrictEquals(aniCallback, refCallback, &isEqual);
    return isEqual;
}

bool EtsSystemConfigurationUpdatedCallback::UnRegister(ani_object aniCallback)
{
    ani_status status = ANI_ERROR;
    std::lock_guard lock(mutex_);
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed");
        return false;
    }
    if (aniCallback == nullptr) {
        TAG_LOGI(AAFwkTag::APPKIT, "null aniCallback");
        for (auto &callback : callbacksRef_) {
            if (!callback) {
                TAG_LOGE(AAFwkTag::APPKIT, "Invalid aniCallback");
                continue;
            }
            if ((status = env->GlobalReference_Delete(callback)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Delete status: %{public}d", status);
            }
        }
        callbacksRef_.clear();
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return true;
    }
    for (auto &callback : callbacksRef_) {
        if (!callback) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid aniCallback");
            continue;
        }
        if (IsEquel(env, aniCallback, callback)) {
            if ((status = env->GlobalReference_Delete(callback)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Delete status: %{public}d", status);
                AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
                return false;
            }
            AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
            return callbacksRef_.erase(callback) == 1;
        }
    }
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
    return false;
}

EtsSystemConfigurationUpdatedCallback::~EtsSystemConfigurationUpdatedCallback()
{
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed");
        return;
    }
    ani_status status = ANI_ERROR;
    {
        std::lock_guard lock(mutex_);
        for (auto &callback : callbacksRef_) {
            if (!callback) {
                TAG_LOGE(AAFwkTag::APPKIT, "Invalid aniCallback");
                return;
            }
            if ((status = env->GlobalReference_Delete(callback)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Delete status: %{public}d", status);
            }
        }
    }

    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

template <class NATIVE_T, class ANI_T>
static bool ConvertToAniValue(ani_env *env, const NATIVE_T &nativeVa, ANI_T &aniVa)
{
    if constexpr (std::is_same_v<NATIVE_T, double>) {
        aniVa = AppExecFwk::CreateDouble(env, nativeVa);
        return true;
    } else if constexpr (std::is_same_v<NATIVE_T, std::string>) {
        aniVa = AppExecFwk::GetAniString(env, nativeVa);
        return true;
    } else if constexpr (std::is_same_v<NATIVE_T, Global::Resource::ColorMode>) {
        if (!OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToEts(env, COLOR_MODE_ENUM_NAME, nativeVa, aniVa)) {
            TAG_LOGE(AAFwkTag::APPKIT, "EnumConvert_NativeToEts fail value:%{public}d", nativeVa);
            return false;
        }
        return true;
    } else if (std::is_same_v<NATIVE_T, bool>) {
        aniVa = AppExecFwk::CreateBoolean(env, nativeVa);
        return true;
    }
    TAG_LOGE(AAFwkTag::APPKIT, "ConvertToAniValue fail, type error");
    return false;
}

template <class NATIVE_T, class ANI_T>
void EtsSystemConfigurationUpdatedCallback::CallAniMethod(
    ani_env *env, ani_ref callback, ani_ref method, const NATIVE_T &value)
{
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "method or param nullptr");
        return;
    }

    ANI_T aniValue{};
    if (!ConvertToAniValue<NATIVE_T, ANI_T>(env, value, aniValue) || aniValue == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "convert ani_value failed");
        return;
    }

    ani_status status = ANI_ERROR;
    std::array<ani_ref, 1> args = {aniValue};
    ani_ref fnReturnVal{};
    if ((status = env->FunctionalObject_Call(static_cast<ani_fn_object>(method), args.size(),
        args.data(), &fnReturnVal)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FunctionalObject_Call status: %{public}d", status);
        return;
    }
    // }
}

bool EtsSystemConfigurationUpdatedCallback::CheckAndGetAniMethod(
    ani_env *env, ani_ref callback, const char *methodName, ani_ref &method)
{
    if (env == nullptr || methodName == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env or methodName");
        method = nullptr;
        return false;
    }

    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetPropertyByName_Ref(static_cast<ani_object>(callback), methodName, &method)) !=
        ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT,
            "Object_GetPropertyByName_Ref status: %{public}d methodName:%{public}s",
            status,
            methodName);
        return false;
    }

    ani_boolean isUndef = true;
    env->Reference_IsUndefined(method, &isUndef);
    if (isUndef) {
        TAG_LOGW(AAFwkTag::APPKIT, "method not exist methodName:%{public}s", methodName);
        return false;
    }

    return true;
}

void EtsSystemConfigurationUpdatedCallback::NotifySystemConfigurationUpdated(
    const OHOS::AppExecFwk::Configuration &configuration)
{
    TAG_LOGI(AAFwkTag::APPKIT, "NotifySystemConfig:%{public}s", configuration.GetName().c_str());

    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }

    std::lock_guard lock(mutex_);
    for (auto &callback : callbacksRef_) {
        if (callback == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid aniCallback");
            continue;
        }
        ani_ref method = {};
        auto colorMode = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE);
        if (!colorMode.empty() && CheckAndGetAniMethod(env, callback,
            SystemConfigurationUpdatedFunctionName::SYSTEM_COLOR_MODE_UPDATED_FUNCTION_NAME, method)) {
            NotifyColorModeUpdated(env, callback, method, colorMode);
        }

        auto fontSizeScale = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_SIZE_SCALE);
        if (!fontSizeScale.empty() &&
            CheckAndGetAniMethod(env,
                callback,
                SystemConfigurationUpdatedFunctionName::SYSTEM_FONT_SIZE_SCALE_UPDATED_FUNCTION_NAME,
                method)) {
            NotifyFontSizeScaleUpdated(env, callback, method, fontSizeScale);
        }

        auto fontWeightScale = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_WEIGHT_SCALE);
        if (!fontWeightScale.empty() &&
            CheckAndGetAniMethod(env,
                callback,
                SystemConfigurationUpdatedFunctionName::SYSTEM_FONT_WEIGHT_SCALE_UPDATED_FUNCTION_NAME,
                method)) {
            NotifyFontWeightScaleUpdated(env, callback, method, fontWeightScale);
        }

        auto language = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
        if (!language.empty() &&
            CheckAndGetAniMethod(
                env, callback, SystemConfigurationUpdatedFunctionName::SYSTEM_LANGUAGE_UPDATED_FUNCTION_NAME, method)) {
            NotifyLanguageUpdated(env, callback, method, language);
        }

        auto mcc = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_MCC);
        if (!mcc.empty() &&
            CheckAndGetAniMethod(
                env, callback, SystemConfigurationUpdatedFunctionName::SYSTEM_MCC_UPDATED_FUNCTION_NAME, method)) {
            NotifyMCCUpdated(env, callback, method, mcc);
        }

        auto mnc = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_MNC);
        if (!mnc.empty() &&
            CheckAndGetAniMethod(
                env, callback, SystemConfigurationUpdatedFunctionName::SYSTEM_MNC_UPDATED_FUNCTION_NAME, method)) {
            NotifyMNCUpdated(env, callback, method, mnc);
        }

        auto locale = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_LOCALE);
        if (!locale.empty() &&
            CheckAndGetAniMethod(
                env, callback, SystemConfigurationUpdatedFunctionName::SYSTEM_LOCALE_UPDATED_FUNCTION_NAME, method)) {
            NotifyLocaleUpdated(env, callback, method, locale);
        }

        auto hasPointerDevice = configuration.GetItem(AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE);
        if (!hasPointerDevice.empty() &&
            CheckAndGetAniMethod(env,
                callback,
                SystemConfigurationUpdatedFunctionName::SYSTEM_HAS_POINTER_DEVICE_UPDATED_FUNCTION_NAME,
                method)) {
            NotifyHasPointerDeviceUpdated(env, callback, method, hasPointerDevice);
        }

        auto fontId = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_ID);
        if (!fontId.empty() &&
            CheckAndGetAniMethod(
                env, callback, SystemConfigurationUpdatedFunctionName::SYSTEM_FONTID_UPDATED_FUNCTION_NAME, method)) {
            NotifyFontIdUpdated(env, callback, method, fontId);
        }
    }
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

void EtsSystemConfigurationUpdatedCallback::NotifyColorModeUpdated(
    ani_env *env, ani_ref callback, ani_ref method, const std::string &colorMode)
{
    TAG_LOGI(AAFwkTag::APPKIT, "NotifyColorModeUpdated");
    Global::Resource::ColorMode colorModeValue = AppExecFwk::ConvertColorMode(colorMode);
    CallAniMethod<Global::Resource::ColorMode, ani_enum_item>(env, callback, method, colorModeValue);
}

void EtsSystemConfigurationUpdatedCallback::NotifyFontSizeScaleUpdated(
    ani_env *env, ani_ref callback, ani_ref method, const std::string &fontSizeScale)
{
    TAG_LOGI(AAFwkTag::APPKIT, "NotifyFontSizeScaleUpdated");
    double fontSizeScaleDouble = 1.0;
    ConvertToDouble(fontSizeScale, fontSizeScaleDouble);
    CallAniMethod<double, ani_ref>(env, callback, method, fontSizeScaleDouble);
}
void EtsSystemConfigurationUpdatedCallback::NotifyFontWeightScaleUpdated(
    ani_env *env, ani_ref callback, ani_ref method, const std::string &fontWeightScale)
{
    TAG_LOGI(AAFwkTag::APPKIT, "NotifyFontWeightScaleUpdated");
    double fontWeightScaleDouble = 1.0;
    ConvertToDouble(fontWeightScale, fontWeightScaleDouble);
    CallAniMethod<double, ani_ref>(env, callback, method, fontWeightScaleDouble);
}
void EtsSystemConfigurationUpdatedCallback::NotifyLanguageUpdated(
    ani_env *env, ani_ref callback, ani_ref method, const std::string &language)
{
    TAG_LOGI(AAFwkTag::APPKIT, "NotifyLanguageUpdated");
    CallAniMethod<std::string, ani_string>(env, callback, method, language);
}

void EtsSystemConfigurationUpdatedCallback::NotifyFontIdUpdated(
    ani_env *env, ani_ref callback, ani_ref method, const std::string &fontId)
{
    TAG_LOGI(AAFwkTag::APPKIT, "NotifyFontIdUpdated");
    CallAniMethod<std::string, ani_string>(env, callback, method, fontId);
}
void EtsSystemConfigurationUpdatedCallback::NotifyMCCUpdated(
    ani_env *env, ani_ref callback, ani_ref method, const std::string &mcc)
{
    TAG_LOGI(AAFwkTag::APPKIT, "NotifyMCCUpdated");
    CallAniMethod<std::string, ani_string>(env, callback, method, mcc);
}
void EtsSystemConfigurationUpdatedCallback::NotifyMNCUpdated(
    ani_env *env, ani_ref callback, ani_ref method, const std::string &mnc)
{
    TAG_LOGI(AAFwkTag::APPKIT, "NotifyMNCUpdated");
    CallAniMethod<std::string, ani_string>(env, callback, method, mnc);
}
void EtsSystemConfigurationUpdatedCallback::NotifyLocaleUpdated(
    ani_env *env, ani_ref callback, ani_ref method, const std::string &locale)
{
    TAG_LOGI(AAFwkTag::APPKIT, "NotifyLocaleUpdated");
    CallAniMethod<std::string, ani_string>(env, callback, method, locale);
}
void EtsSystemConfigurationUpdatedCallback::NotifyHasPointerDeviceUpdated(
    ani_env *env, ani_ref callback, ani_ref method, const std::string &hasPointerDevice)
{
    TAG_LOGI(AAFwkTag::APPKIT, "NotifyHasPointerDeviceUpdated");
    CallAniMethod<bool, ani_ref>(env, callback, method, hasPointerDevice == "true" ? true : false);
}

bool EtsSystemConfigurationUpdatedCallback::IsEmpty() const
{
    std::lock_guard lock(mutex_);
    return callbacksRef_.empty();
}

}  // namespace AbilityRuntime
}  // namespace OHOS
