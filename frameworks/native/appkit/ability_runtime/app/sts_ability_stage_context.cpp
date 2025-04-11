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
#include "ability_runtime/context/context.h"
#include "sts_ability_stage_context.h"
#include "hilog_tag_wrapper.h"
#include "sts_runtime.h"
#include "configuration_convertor.h"
#include "ohos_application.h"
#include "ani_common_configuration.h"
#include "sts_context_utils.h"
namespace OHOS {
namespace AbilityRuntime {

ani_ref STSAbilityStageContext::stsAbilityStageContextObj_ = nullptr;

void STSAbilityStageContext::ResetEnv(ani_env* env)
{
    if (env) {
        env->DescribeError();
        env->ResetError();
    }
}

ani_object STSAbilityStageContext::CreateStsAbilityStageContext(ani_env* env, std::shared_ptr<Context> context,
    std::weak_ptr<AppExecFwk::OHOSApplication> application)
{
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "env nullptr or context nullptr");
        return nullptr;
    }

    ani_status status = ANI_OK;
    ani_class abilityStageCtxCls;
    status = env->FindClass(STS_ABILITY_STAGE_CONTEXT_CLASS_NAME, &abilityStageCtxCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "call FindClass LAbilityStageContext failed, status:%{public}d", status);
        return nullptr;
    }

    ani_method method = nullptr;
    status = env->Class_FindMethod(abilityStageCtxCls, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "call Class_FindMethod ctor failed");
        return nullptr;
    }
    ani_object obj = nullptr;
    status = env->Object_New(abilityStageCtxCls, method, &obj);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "call Object_New abilityStageCtxCls failed");
        return nullptr;
    }
    stsAbilityStageContextObj_ = reinterpret_cast<ani_ref>(obj);

    //bind context
    auto workContext = new (std::nothrow) std::weak_ptr<AbilityRuntime::Context>(context);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "workContext nullptr");
        delete workContext;
        return nullptr;
    }
    ani_field contextField;
    status = env->Class_FindField(abilityStageCtxCls, "stageContext", &contextField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "call Class_FindField stageContext failed");
    }
    auto pCtx = workContext->lock();
    if(pCtx != nullptr) {
        status = env->Object_SetField_Long(obj, contextField, reinterpret_cast<ani_long>(pCtx.get()));
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::ABILITY, "call Object_SetField_Long contextField failed");
            delete workContext;
            return nullptr;

        }
    }

    // bind parent context
    auto app = application.lock();
    if (app == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "application is null");
        delete workContext;
        return nullptr;
    }
    ContextUtil::StsCreatContext(env, abilityStageCtxCls, obj, app->GetApplicationCtxObjRef(), context);

    //set Config class
    auto configuration = context->GetConfiguration();
    if (configuration != nullptr) {
        ani_object configObj = OHOS::AppExecFwk::WrapConfiguration(env, *configuration);
        if(configObj != nullptr) {
            TAG_LOGE(AAFwkTag::ABILITY, "configObj bind");
            ani_ref configObjRef = nullptr;
            if (env->GlobalReference_Create(configObj, &configObjRef) != ANI_OK) {
                TAG_LOGE(AAFwkTag::ABILITY, "GlobalReference_Create configObjRef failed");
            }
            ani_field configField;
            status = env->Class_FindField(abilityStageCtxCls, "config", &configField);
            if (status != ANI_OK) {
                TAG_LOGE(AAFwkTag::ABILITY, "Class_FindField config failed");
            }
            if (env->Object_SetField_Ref(obj, configField, configObjRef) != ANI_OK) {
                TAG_LOGE(AAFwkTag::ABILITY, "Object_SetField_Ref configField failed");
            }
        }
    }
    //set HapModuleInfo class
    ani_object moduleInfoObj = CreateHapModuleInfo(env, context);
    if (moduleInfoObj != nullptr) {
        ani_field moduleInfoField;
        status = env->Class_FindField(abilityStageCtxCls, "currentHapModuleInfo", &moduleInfoField);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::ABILITY, "Class_FindField currentHapModuleInfo failed");
        }
        status = env->Object_SetField_Ref(obj, moduleInfoField, reinterpret_cast<ani_ref>(moduleInfoObj));
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::ABILITY, "Object_SetField_Ref moduleInfoField failed");
        }
    }
    delete workContext;
    return obj;
}

ani_object STSAbilityStageContext::CreateHapModuleInfo(ani_env* env, const std::shared_ptr<Context> &context)
{
    if (env == nullptr || context == nullptr) {
        return nullptr;
    }
    ani_status status = ANI_OK;
    ani_class cls;
    auto hapModuleInfo = context->GetHapModuleInfo();
    status = env->FindClass(STS_HAPMODULEINFO_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "call FindClass HapModuleInfo failed");
        return nullptr;
    }
    ani_method initMethod = nullptr;
    status = env->Class_FindMethod(cls, "<ctor>", ":V", &initMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "call Class_FindMethod ctor failed");
        return nullptr;
    }
    ani_object obj = nullptr;
    status = env->Object_New(cls, initMethod, &obj);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "Object_New obj failed");
        return nullptr;
    }
    return obj;
}

void STSAbilityStageContext::ConfigurationUpdated(ani_env* env, const std::shared_ptr<AppExecFwk::Configuration> &config)
{
    if (!config) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "null config");
        return;
    }
    ani_object configObj = OHOS::AppExecFwk::WrapConfiguration(env, *config);

    ani_class abilityStageCtxCls = nullptr;
    ani_status status = env->FindClass(STS_ABILITY_STAGE_CLASS_NAME, &abilityStageCtxCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "FindClass LAbilityStageContext failed, status:%{public}d", status);
    }

    ani_method method = nullptr;
    status = env->Class_FindMethod(abilityStageCtxCls, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "call Class_FindMethod ctor failed");
    }
    ani_object abilityStageCtxObj = nullptr;
    status = env->Object_New(abilityStageCtxCls, method, &abilityStageCtxObj);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "call Object_New abilityStageCtxCls failed");
    }

    method = nullptr;
    status = env->Class_FindMethod(abilityStageCtxCls, "onUpdateConfiguration", "LConfiguration;:V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "Class_FindMethod FAILED");
        return;
    }

    status = env->Object_CallMethod_Void(abilityStageCtxObj, method, configObj);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "CALL Object_CallMethod_Void FAILED:");
        return;
    }
}
}  // namespace AbilityRuntime
}  // namespace OHOS
