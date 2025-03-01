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

#include "sts_configuration.h"

#include <map>
#include "hilog_tag_wrapper.h"
#include "cj_environment_callback.h"
#include "global_configuration_key.h"

namespace OHOS {
namespace ConfigurationSts {

int32_t ConvertColorMode(std::string colormode)
{
    auto resolution = -1;
    static const std::vector<std::pair<std::string, int32_t>> resolutions = {
        { "dark", 0 },
        { "light", 1 },
    };
    for (const auto& [tempColorMode, value] : resolutions) {
        if (tempColorMode == colormode) {
            resolution = value;
            break;
        }
    }
    return resolution;
}

void SetLanguage(ani_env *aniEnv, ani_class cf, ani_object cfObject, const std::string &language)
{
    ani_status status = ANI_ERROR;
    ani_string aniStr;
    status = aniEnv->String_NewUTF8(language.c_str(), language.length(), &aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "String_NewUTF8 failed status: %{public}d", status);
        return;
    }
    TAG_LOGI(AAFwkTag::APPKIT, "String_NewUTF8 success");

    // find the setter method
    ani_method nameSetter;
    status = aniEnv->Class_FindMethod(cf, "<set>language", nullptr, &nameSetter);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod failed status: %{public}d", status);
        return;
    }
    TAG_LOGI(AAFwkTag::APPKIT, "Class_FindMethod success");

    // call set language(n:string)
    status = aniEnv->Object_CallMethod_Void(cfObject, nameSetter, aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_CallMethod_Void failed status : %{public}d", status);
        return;
    }
    TAG_LOGI(AAFwkTag::APPKIT, "Object_CallMethod_Void success");
}

void SetColorMode(ani_env *aniEnv, ani_class cf, ani_object cfObject, const std::string colorMode)
{
    ani_status status = ANI_ERROR;
    
    // find the setter method
    ani_method nameSetter;
    status = aniEnv->Class_FindMethod(cf, "<set>colorMode", nullptr, &nameSetter);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod failed status: %{public}d", status);
        return;
    }
    TAG_LOGI(AAFwkTag::APPKIT, "Class_FindMethod success");

    // call set colorMode(n:int32_t)
    status = aniEnv->Object_CallMethod_Void(cfObject, nameSetter, ConvertColorMode(colorMode));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_CallMethod_Void failed status : %{public}d", status);
        return;
    }
    TAG_LOGI(AAFwkTag::APPKIT, "Object_CallMethod_Void success");
}

void SetFontSizeScale(ani_env *aniEnv, ani_class cf, ani_object cfObject, std::string fontSizeScale)
{
    ani_status status = ANI_ERROR;

    // find the setter method
    ani_method nameSetter;
    status = aniEnv->Class_FindMethod(cf, "<set>fontSizeScale", nullptr, &nameSetter);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod failed status: %{public}d", status);
        return;
    }
    TAG_LOGI(AAFwkTag::APPKIT, "Class_FindMethod success");

    // call set fontSizeScale(n:double)
    ani_double dval = (fontSizeScale != "" ? std::stod(fontSizeScale) : 1.0);
    status = aniEnv->Object_CallMethod_Void(cfObject, nameSetter, dval);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_CallMethod_Void failed status : %{public}d", status);
        return;
    }
    TAG_LOGI(AAFwkTag::APPKIT, "Object_CallMethod_Void success");
}

ani_object CreateStsConfiguration(ani_env *aniEnv, const std::shared_ptr<AppExecFwk::Configuration> configuration)
{
    TAG_LOGI(AAFwkTag::APPKIT, "CreateStsConfiguration");
    ani_class cf = nullptr;
    ani_status status = ANI_ERROR;
    status = aniEnv->FindClass("LEntryAbility/ConfigurationInner;", &cf);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "find ConfigurationInner failed status : %{public}d", status);
        return {};
    }
    TAG_LOGI(AAFwkTag::APPKIT, "find ConfigurationInner success");

    ani_method method = nullptr;
    status = aniEnv->Class_FindMethod(cf, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod ctor failed status : %{public}d", status);
        return {};
    }
    TAG_LOGI(AAFwkTag::APPKIT, "Class_FindMethod ctor success");

    ani_object cfObject = nullptr;
    status = aniEnv->Object_New(cf, method, &cfObject);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_New failed status : %{public}d", status);
        return {};
    }
    TAG_LOGI(AAFwkTag::APPKIT, "Object_New success");

    std::string language = configuration->GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
    SetLanguage(aniEnv, cf, cfObject, language);
    
    std::string colorMode = configuration->GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE);
    SetColorMode(aniEnv, cf, cfObject, colorMode);

    std::string fontSizeScale = configuration->GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_SIZE_SCALE);
    // std::string fontSizeScale = configuration->GetItem("");
    SetFontSizeScale(aniEnv, cf, cfObject, fontSizeScale);

    return cfObject;
}


void StsConfigurationInit(ani_env *aniEnv)
{
    TAG_LOGI(AAFwkTag::APPKIT, "StsConfigurationInit call");
    ani_status status = ANI_ERROR;
    if (aniEnv->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "ResetError failed");
    }

    ani_class cf = nullptr;
    status = aniEnv->FindClass("LEntryAbility/ConfigurationInner;", &cf);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "find ConfigurationInner failed status : %{public}d", status);
        return;
    }
    TAG_LOGI(AAFwkTag::APPKIT, "find ConfigurationInner success");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGI(AAFwkTag::APPKIT, "ANI_Constructor");
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    };
    StsConfigurationInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGI(AAFwkTag::APPKIT, "ANI_Constructor finish");
    return ANI_OK;
}
}
} // namespace ConfigurationSts
} // namespace OHOS