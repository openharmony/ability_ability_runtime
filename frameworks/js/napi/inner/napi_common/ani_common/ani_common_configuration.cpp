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

#include "configuration_convertor.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr double FONT_SIZE_MIN_SCALE = 0.0;
constexpr double FONT_SIZE_MAX_SCALE = 3.2;
constexpr double FONT_WEIGHT_MIN_SCALE = 0.0;
constexpr double FONT_WEIGHT_MAX_SCALE = 1.25;
}

ani_object WrapConfiguration(ani_env *env, const AppExecFwk::Configuration &configuration)
{
    TAG_LOGE(AAFwkTag::JSNAPI, "WrapConfiguration");
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = nullptr;

    if ((status = env->FindClass("LUIAbilityContext/Configuration;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null Configuration");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null object");
        return nullptr;
    }

    std::string str;

    str = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
    SetFieldString(env, cls, object, "language", str);

    SetFieldInt(env, cls, object, "colorMode", ConvertColorMode(configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE)));

    int32_t displayId = ConvertDisplayId(configuration.GetItem(ConfigurationInner::APPLICATION_DISPLAYID));
    SetFieldInt(env, cls, object, "displayId", displayId);

    std::string direction = configuration.GetItem(displayId, ConfigurationInner::APPLICATION_DIRECTION);
    SetFieldInt(env, cls, object, "direction", ConvertDirection(direction));

    std::string density = configuration.GetItem(displayId, ConfigurationInner::APPLICATION_DENSITYDPI);
    SetFieldInt(env, cls, object, "screenDensity", ConvertDensity(density));
    
    std::string hasPointerDevice = configuration.GetItem(AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE);
    SetFieldBoolean(env, cls, object, "hasPointerDevice", hasPointerDevice == "true" ? true : false);

    str = configuration.GetItem(AAFwk::GlobalConfigurationKey::APPLICATION_FONT);
    SetFieldString(env, cls, object, "fontId", str);

    std::string fontSizeScale = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_SIZE_SCALE);
    SetFieldDouble(env, cls, object, "fontSizeScale", fontSizeScale != "" ? std::stod(fontSizeScale) : 1.0);

    std::string fontWeightScale = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_WEIGHT_SCALE);
    SetFieldDouble(env, cls, object, "fontWeightScale", fontWeightScale != "" ? std::stod(fontWeightScale) : 1.0);

    str = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_MCC);
    SetFieldString(env, cls, object, "mcc", str);

    str = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_MNC);
    SetFieldString(env, cls, object, "mnc", str);

    return object;
}

bool UnwrapConfiguration(ani_env *env, ani_object param, Configuration &config)
{
    std::string language {""};
    if (GetStringOrUndefined(env, param, "language", language)) {
        TAG_LOGD(AAFwkTag::JSNAPI, "The parsed language part %{public}s", language.c_str());
        if (!config.AddItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, language)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "language Parsing failed");
            return false;
        }
    }

    double fontSizeScale = GetDoubleOrUndefined(env, param, "fontSizeScale");
    TAG_LOGD(AAFwkTag::JSNAPI, "The parsed fontSizeScale part %{public}lf", fontSizeScale);
    if (fontSizeScale < FONT_SIZE_MIN_SCALE || fontSizeScale > FONT_SIZE_MAX_SCALE) {
        TAG_LOGE(AAFwkTag::JSNAPI, "invalid fontSizeScale");
        return false;
    }
    if (!config.AddItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_SIZE_SCALE, std::to_string(fontSizeScale))) {
        return false;
    }

    double fontWeightScale = GetDoubleOrUndefined(env, param, "fontWeightScale");
    TAG_LOGD(AAFwkTag::JSNAPI, "The parsed fontWeightScale part %{public}lf", fontWeightScale);
    if (fontWeightScale < FONT_WEIGHT_MIN_SCALE || fontWeightScale > FONT_WEIGHT_MAX_SCALE) {
        TAG_LOGE(AAFwkTag::JSNAPI, "invalid fontWeightScale");
        return false;
    }
    if (!config.AddItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_WEIGHT_SCALE, std::to_string(fontWeightScale))) {
        return false;
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
