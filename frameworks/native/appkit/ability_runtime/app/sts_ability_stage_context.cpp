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
#include "ability_runtime/context/context.h"
#include "sts_ability_stage_context.h"
#include "hilog_tag_wrapper.h"
#include "sts_runtime.h"
#include "configuration_convertor.h"
#include "ohos_application.h"
#include "sts_context_util.h"

namespace OHOS {
namespace AbilityRuntime {

ani_ref STSAbilityStageContext::stsAbilityStageContextObj_ = nullptr;

void STSAbilityStageContext::ResetEnv(ani_env* env)
{
    env->DescribeError();  // 打印异常信息
    env->ResetError();  // 清除异常，避免影响后续 ANI 调用
}

ani_object STSAbilityStageContext::CreateStsAbilityStageContext(ani_env* env, std::shared_ptr<Context> context,
    std::weak_ptr<AppExecFwk::OHOSApplication> application)
{
    TAG_LOGI(AAFwkTag::ABILITY, "zg STS %{public}s called", __func__);
    if (!env) {
        TAG_LOGE(AAFwkTag::ABILITY, "env nullptr");
    }

    TAG_LOGE(AAFwkTag::ABILITY, "zg CreateStsAbilityStageContext env:%{public}p", env);
    ani_status status = ANI_OK;
    ani_class abilityStageCtxCls;
    status = env->FindClass(STS_ABILITY_STAGE_CONTEXT_CLASS_NAME, &abilityStageCtxCls);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg call FindClass L@ohos/hilog/OHAbilityStageContextMaterialized/AbilityStageContext failed");
        TAG_LOGI(AAFwkTag::ABILITY, "zg call FindClass LAbilityStageContext failed, status:%{public}d", status);
    }

    ani_method method = nullptr;
    status = env->Class_FindMethod(abilityStageCtxCls, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg call Class_FindMethod ctor failed");
    }
    ani_object obj = nullptr;
    status = env->Object_New(abilityStageCtxCls, method, &obj);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg call Object_New abilityStageCtxCls failed");
    }
    stsAbilityStageContextObj_ = reinterpret_cast<ani_ref>(obj);

    //bind context
    auto workContext = new (std::nothrow) std::weak_ptr<AbilityRuntime::Context>(context);
    ani_field contextField;
    status = env->Class_FindField(abilityStageCtxCls, "stageContext", &contextField);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg call Class_FindField stageContext failed");
    }
    auto pCtx = workContext->lock();
    if(pCtx != nullptr) {
        status = env->Object_SetField_Long(obj, contextField, reinterpret_cast<ani_long>(pCtx.get()));
        if (status != ANI_OK) {
            TAG_LOGI(AAFwkTag::ABILITY, "zg call Object_SetField_Long contextField failed");
            delete workContext;
            return nullptr;

        }
    }

    // bind parent context
    auto app = application.lock();
    if (app == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "application is null");
        return nullptr;
    }
    ContextUtil::StsCreatContext(env, abilityStageCtxCls, obj, app->GetApplicationCtxObjRef(), context);

    //set Config class
    ani_object configObj = Createfiguration(env, context);
    if(configObj != nullptr) {
        TAG_LOGI(AAFwkTag::ABILITY, "[ywz] configObj bind");
        ani_ref configObjRef = nullptr;
        if (env->GlobalReference_Create(configObj, &configObjRef) != ANI_OK) {
            TAG_LOGE(AAFwkTag::ABILITY, "[ywz] GlobalReference_Create configObjRef failed");
        }
        ani_field configField;
        status = env->Class_FindField(abilityStageCtxCls, "config", &configField);
        if (status != ANI_OK) {
            TAG_LOGI(AAFwkTag::ABILITY, "zg Class_FindField config failed");
        }
        if (env->Object_SetField_Ref(obj, configField, configObjRef) != ANI_OK) {
            TAG_LOGI(AAFwkTag::ABILITY, "zg Object_SetField_Ref configField failed");
        }
    }

    //set HapModuleInfo class
    ani_object moduleInfoObj = CreateHapModuleInfo(env, context);
    if (moduleInfoObj != nullptr) {
        ani_field moduleInfoField;
        status = env->Class_FindField(abilityStageCtxCls, "currentHapModuleInfo", &moduleInfoField);
        if (status != ANI_OK) {
            TAG_LOGI(AAFwkTag::ABILITY, "zg Class_FindField currentHapModuleInfo failed");
        }
        status = env->Object_SetField_Ref(obj, moduleInfoField, reinterpret_cast<ani_ref>(moduleInfoObj));
        if (status != ANI_OK) {
            TAG_LOGI(AAFwkTag::ABILITY, "zg Object_SetField_Ref moduleInfoField failed");
        }
    }
    TAG_LOGI(AAFwkTag::ABILITY, "zg STS %{public}s finished", __func__);
    return obj;
 }

ani_object STSAbilityStageContext::Createfiguration(ani_env *env, const std::shared_ptr<Context> &context)
{
    TAG_LOGI(AAFwkTag::ABILITY, "zg STS %{public}s start", __func__);
    if (context == nullptr || env == nullptr) {
        return nullptr;
    }
    return Createfiguration(env, context->GetConfiguration());
}

ani_object STSAbilityStageContext::CreateHapModuleInfo(ani_env* env, const std::shared_ptr<Context> &context)
{
    TAG_LOGI(AAFwkTag::ABILITY, "zg STS %{public}s start", __func__);
    if (env == nullptr || context == nullptr) {
        return nullptr;
    }
    ani_status status = ANI_OK;
    ani_class cls;
    auto hapModuleInfo = context->GetHapModuleInfo();
    status = env->FindClass(STS_HAPMODULEINFO_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg call FindClass HapModuleInfo failed");
        return nullptr;
    }
    ani_method initMethod = nullptr;
    status = env->Class_FindMethod(cls, "<ctor>", ":V", &initMethod);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg call Class_FindMethod ctor failed");
        return nullptr;
    }
    ani_object obj = nullptr;
    status = env->Object_New(cls, initMethod, &obj);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg Object_New obj failed");
        return nullptr;
    }
    TAG_LOGI(AAFwkTag::ABILITY, "zg STS %{public}s finished", __func__);
    return obj;
}

ani_object STSAbilityStageContext::Createfiguration(ani_env* env, const std::shared_ptr<AppExecFwk::Configuration> &configuration)
{
    TAG_LOGI(AAFwkTag::ABILITY, "zg STS %{public}s start", __func__);
    if (env == nullptr || configuration == nullptr) {
        return nullptr;
    }
    ani_status status = ANI_OK;
    ani_class configCls;
    status = env->FindClass(STS_CONFIGURATION_CLASS_NAME, &configCls);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg call FindClass Configuration failed");
        return nullptr;
    }
    ani_method initMethod = nullptr;
    status = env->Class_FindMethod(configCls, "<ctor>", ":V", &initMethod);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg call Class_FindMethod ctor failed");
        return nullptr;
    }
    ani_object configObj = nullptr;
    status = env->Object_New(configCls, initMethod, &configObj);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg Object_New configObj failed");
        return nullptr;
    }

    //set config fields
    ani_field filed;
    status = env->Class_FindField(configCls, "language", &filed);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg Class_FindField configObj failed");
    }

    //language
    // auto strLanguage = configuration->GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
    // ani_string aniStringVal {};
    // status = env->String_NewUTF8(strLanguage.c_str(), strLanguage.size(), &aniStringVal);
    // if (status != ANI_OK) {
    //     TAG_LOGI(AAFwkTag::ABILITY, "zg String_NewUTF8 strLanguage failed");
    // }
    // if (env->Object_SetField_Ref(configObj, filed, aniStringVal) != ANI_OK) {
    //     TAG_LOGI(AAFwkTag::ABILITY, "zg Object_SetField_Ref language failed");
    // }

    // //displayId
    // int32_t displayId = AppExecFwk::ConvertDisplayId(configuration->GetItem(AppExecFwk::ConfigurationInner::APPLICATION_DISPLAYID));
    // status = env->Class_FindField(configCls, "displayId", &filed);
    // if (status != ANI_OK) {
    //      TAG_LOGI(AAFwkTag::ABILITY, "zg Class_FindField displayId failed");
    // }
    // TAG_LOGI(AAFwkTag::ABILITY, "zg Object_SetField_Int displayId:%{public}d", displayId);
    // status = env->Object_SetField_Int(configObj, filed, displayId);
    // if (status != ANI_OK) {
    //     TAG_LOGI(AAFwkTag::ABILITY, "zg Object_SetField_Int displayId failed");
    // }

    //hasPointerDevice
    #if 0
    std::string hasPointerDevice = configuration->GetItem(AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE);
    TAG_LOGI(AAFwkTag::ABILITY, "zg debug ----- hasPointerDevice:%{public}s", hasPointerDevice.c_str());
    status = env->Class_FindField(configCls, "hasPointerDevice", &filed);
    if (status != ANI_OK) {
         TAG_LOGI(AAFwkTag::ABILITY, "zg Class_FindField hasPointerDevice failed");
    }
    ani_boolean bval = (hasPointerDevice == "true" ? true : false);
    if (env->Object_SetField_Boolean(configObj, filed, bval) != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg Class_FindField hasPointerDevice failed");
    } else {
        TAG_LOGI(AAFwkTag::ABILITY, "zg debug ----- set hasPointerDevice OK");
    }
    #endif

    //fontId
    // std::string strFontId = configuration->GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_ID);
    // TAG_LOGI(AAFwkTag::ABILITY, "zg debug ----- strFontId:%{public}s", strFontId.c_str());
    // status = env->Class_FindField(configCls, "fontId", &filed);
    // if (status != ANI_OK) {
    //      TAG_LOGI(AAFwkTag::ABILITY, "zg Class_FindField fontId failed");
    // }
    // status = env->String_NewUTF8(strFontId.c_str(), strFontId.size(), &aniStringVal);
    // if (status != ANI_OK) {
    //     TAG_LOGI(AAFwkTag::ABILITY, "zg String_NewUTF8 fontId failed");
    // }
    // if (env->Object_SetField_Ref(configObj, filed, aniStringVal) != ANI_OK) {
    //     TAG_LOGI(AAFwkTag::ABILITY, "zg Object_SetField_Ref fontId failed");
    // }

    //fontSizeScale
    std::string fontSizeScale = configuration->GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_SIZE_SCALE);
    TAG_LOGI(AAFwkTag::ABILITY, "zg debug ----- fontSizeScale:%{public}s", fontSizeScale.c_str());
    status = env->Class_FindField(configCls, "fontSizeScale", &filed);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg Class_FindField fontSizeScale failed");
    }

    #if 0
    ani_double dval = (fontSizeScale != "" ? std::stod(fontSizeScale) : 1.0);
    TAG_LOGI(AAFwkTag::ABILITY, "zg debug ----- fontSizeScale:%{public}f", dval);
    if (env->Object_SetField_Double(configObj, filed, dval) != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg Object_SetField_Double fontSizeScale failed");
    } else {
        TAG_LOGI(AAFwkTag::ABILITY, "zg debug ----- set fontSizeScale OK");
    }
    #endif

    //fontWeightScale
    std::string fontWeightScale = configuration->GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_WEIGHT_SCALE);
    TAG_LOGI(AAFwkTag::ABILITY, "zg debug ----- fontWeightScale:%{public}s", fontWeightScale.c_str());
    status = env->Class_FindField(configCls, "fontWeightScale", &filed);
    if (status != ANI_OK) {
         TAG_LOGI(AAFwkTag::ABILITY, "zg Class_FindField fontWeightScale failed");
    }

    #if 0
    dval = (fontWeightScale != "" ? std::stod(fontWeightScale) : 1.0);
    TAG_LOGI(AAFwkTag::ABILITY, "zg debug ----- dval:%{public}f", dval);
    if (env->Object_SetField_Double(configObj, filed, dval) != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg Object_SetField_Double fontSizeScale failed");
    } else {
        TAG_LOGI(AAFwkTag::ABILITY, "zg debug ----- set fontSizeScale OK");
    }
    #endif

    //mcc
    // std::string strMcc = configuration->GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_MCC);
    // TAG_LOGI(AAFwkTag::ABILITY, "zg debug ----- strMcc:%{public}s", strMcc.c_str());
    // status = env->Class_FindField(configCls, "mcc", &filed);
    // if (status != ANI_OK) {
    //      TAG_LOGI(AAFwkTag::ABILITY, "zg Class_FindField mcc failed");
    // }
    // status = env->String_NewUTF8(strMcc.c_str(), strMcc.size(), &aniStringVal);
    // if (status != ANI_OK) {
    //     TAG_LOGI(AAFwkTag::ABILITY, "zg String_NewUTF8 mcc failed");
    // }
    // if (env->Object_SetField_Ref(configObj, filed, aniStringVal) != ANI_OK) {
    //     TAG_LOGI(AAFwkTag::ABILITY, "zg Object_SetField_Ref mcc failed");
    // }

    //mnc
    // std::string strMnc = configuration->GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_MNC);
    // TAG_LOGI(AAFwkTag::ABILITY, "zg debug ----- strMnc:%{public}s", strMnc.c_str());
    // status = env->Class_FindField(configCls, "mnc", &filed);
    // if (status != ANI_OK) {
    //      TAG_LOGI(AAFwkTag::ABILITY, "zg Class_FindField mnc failed");
    // }
    // status = env->String_NewUTF8(strMnc.c_str(), strMnc.size(), &aniStringVal);
    // if (status != ANI_OK) {
    //     TAG_LOGI(AAFwkTag::ABILITY, "zg String_NewUTF8 mnc failed");
    // }
    // if (env->Object_SetField_Ref(configObj, filed, aniStringVal) != ANI_OK) {
    //     TAG_LOGI(AAFwkTag::ABILITY, "zg Object_SetField_Ref mcc failed");
    // }

    TAG_LOGI(AAFwkTag::ABILITY, "zg STS %{public}s finished", __func__);
    return configObj;
}

void STSAbilityStageContext::ConfigurationUpdated(ani_env* env, const std::shared_ptr<AppExecFwk::Configuration> &config)
{
    TAG_LOGI(AAFwkTag::ABILITY_SIM, "zg ConfigurationUpdated called");
    if (!config) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "null config");
        return;
    }
    ani_object configObj = Createfiguration(env, config);
    //TODO Get loadmodule returned nativeReference.

    ani_class abilityStageCtxCls = nullptr;
    ani_status status = env->FindClass(STS_ABILITY_STAGE_CLASS_NAME, &abilityStageCtxCls);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg FindClass LAbilityStageContext failed, status:%{public}d", status);
    }

    ani_method method = nullptr;
    status = env->Class_FindMethod(abilityStageCtxCls, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg call Class_FindMethod ctor failed");
    }
    ani_object abilityStageCtxObj = nullptr;
    status = env->Object_New(abilityStageCtxCls, method, &abilityStageCtxObj);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg call Object_New abilityStageCtxCls failed");
    }

    method = nullptr;
    status = env->Class_FindMethod(abilityStageCtxCls, "onUpdateConfiguration", "LConfiguration;:V", &method);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "zg Class_FindMethod FAILED");
        return;
    }

    status = env->Object_CallMethod_Void(abilityStageCtxObj, method, configObj);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "zg CALL Object_CallMethod_Void FAILED:");
        return;
    } else {
        TAG_LOGI(AAFwkTag::ABILITY, "zg CALL Object_CallMethod SUCCEED");
    }
    TAG_LOGI(AAFwkTag::ABILITY_SIM, "zg ConfigurationUpdated finished");
}
}  // namespace AbilityRuntime
}  // namespace OHOS
