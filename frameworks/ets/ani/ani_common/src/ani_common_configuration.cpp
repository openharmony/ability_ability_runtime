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

#include "ani_common_configuration.h"

#include "ani_enum_convert.h"
#include "configuration_convertor.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr double FONT_SIZE_MIN_SCALE = 0.0;
constexpr double FONT_SIZE_MAX_SCALE = 3.2;
constexpr double FONT_WEIGHT_MIN_SCALE = 0.0;
constexpr double FONT_WEIGHT_MAX_SCALE = 1.25;
constexpr const char* COLOR_MODE_ENUM_NAME =
    "L@ohos/app/ability/ConfigurationConstant/ConfigurationConstant/ColorMode;";
constexpr const char* DIRECTION_ENUM_NAME =
    "L@ohos/app/ability/ConfigurationConstant/ConfigurationConstant/Direction;";
constexpr const char* DENSITY_ENUM_NAME =
    "L@ohos/app/ability/ConfigurationConstant/ConfigurationConstant/ScreenDensity;";
constexpr const char* CONFIGURATION_IMPL_CLASS_NAME = "L@ohos/app/ability/Configuration/ConfigurationImpl;";
}

void SetBasicConfiguration(
    ani_env *env, ani_class cls, ani_object object, const AppExecFwk::Configuration &configuration)
{
    std::string str = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
    env->Object_SetPropertyByName_Ref(object, "language", GetAniString(env, str));

    ani_enum_item colorModeItem {};
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToSts(env,
        COLOR_MODE_ENUM_NAME,
        ConvertColorMode(configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE)), colorModeItem);
    env->Object_SetPropertyByName_Ref(object, "colorMode", colorModeItem);

    int32_t displayId = ConvertDisplayId(configuration.GetItem(ConfigurationInner::APPLICATION_DISPLAYID));
    env->Object_SetPropertyByName_Ref(object, "displayId", createDouble(env, static_cast<ani_double>(displayId)));

    std::string direction = configuration.GetItem(displayId, ConfigurationInner::APPLICATION_DIRECTION);
    ani_enum_item directionItem {};
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToSts(env,
        DIRECTION_ENUM_NAME, ConvertDirection(direction),
        directionItem);
    env->Object_SetPropertyByName_Ref(object, "direction", directionItem);

    std::string density = configuration.GetItem(displayId, ConfigurationInner::APPLICATION_DENSITYDPI);
    ani_enum_item densityItem {};
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToSts(env,
        DENSITY_ENUM_NAME, ConvertDensity(density), densityItem);
    env->Object_SetPropertyByName_Ref(object, "screenDensity", densityItem);
}

void SetAdditionalConfiguration(
    ani_env *env, ani_class cls, ani_object object, const AppExecFwk::Configuration &configuration)
{
    std::string hasPointerDevice = configuration.GetItem(AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE);
    env->Object_SetPropertyByName_Ref(
        object, "hasPointerDevice", createBoolean(env, hasPointerDevice == "true" ? true : false));

    std::string str = configuration.GetItem(AAFwk::GlobalConfigurationKey::APPLICATION_FONT);
    env->Object_SetPropertyByName_Ref(object, "fontId", GetAniString(env, str));

    std::string fontSizeScale = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_SIZE_SCALE);
    env->Object_SetPropertyByName_Ref(
        object, "fontSizeScale", createDouble(env, fontSizeScale != "" ? std::stod(fontSizeScale) : 1.0));

    std::string fontWeightScale = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_WEIGHT_SCALE);
    env->Object_SetPropertyByName_Ref(
        object, "fontWeightScale", createDouble(env, fontWeightScale != "" ? std::stod(fontWeightScale) : 1.0));

    str = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_MCC);
    env->Object_SetPropertyByName_Ref(object, "mcc", GetAniString(env, str));

    str = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_MNC);
    env->Object_SetPropertyByName_Ref(object, "mnc", GetAniString(env, str));
}

ani_object WrapConfiguration(ani_env *env, const AppExecFwk::Configuration &configuration)
{
    ani_class cls {};
    ani_status status = ANI_ERROR;
    ani_method method {};
    ani_object object = nullptr;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(CONFIGURATION_IMPL_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return nullptr;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null Configuration");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return nullptr;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null object");
        return nullptr;
    }
    SetBasicConfiguration(env, cls, object, configuration);
    SetAdditionalConfiguration(env, cls, object, configuration);
    return object;
}

bool UnwrapConfiguration(ani_env *env, ani_object param, Configuration &config)
{
    std::string language { "" };
    if (GetStringOrUndefined(env, param, "language", language)) {
        TAG_LOGD(AAFwkTag::JSNAPI, "The parsed language part %{public}s", language.c_str());
        if (!config.AddItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, language)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "language Parsing failed");
            return false;
        }
    }

    ani_double fontSizeScale = 0.0;
    if (GetDoubleOrUndefined(env, param, "fontSizeScale", fontSizeScale)) {
        if (fontSizeScale < FONT_SIZE_MIN_SCALE || fontSizeScale > FONT_SIZE_MAX_SCALE) {
            TAG_LOGE(AAFwkTag::JSNAPI, "invalid fontSizeScale");
            return false;
        }
        if (!config.AddItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_SIZE_SCALE, std::to_string(fontSizeScale))) {
            return false;
        }
    }

    ani_double fontWeightScale = 0.0;
    if (GetDoubleOrUndefined(env, param, "fontWeightScale", fontWeightScale)) {
        if (fontWeightScale < FONT_WEIGHT_MIN_SCALE || fontWeightScale > FONT_WEIGHT_MAX_SCALE) {
            TAG_LOGE(AAFwkTag::JSNAPI, "invalid fontWeightScale");
            return false;
        }
        if (!config.AddItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_WEIGHT_SCALE, std::to_string(fontWeightScale))) {
            return false;
        }
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
