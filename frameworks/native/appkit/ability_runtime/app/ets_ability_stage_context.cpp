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
#include "ets_ability_stage_context.h"
#include "hilog_tag_wrapper.h"
#include "ets_runtime.h"
#include "configuration_convertor.h"
#include "ohos_application.h"
#include "ani_common_configuration.h"
#include "ets_context_utils.h"

namespace OHOS {
namespace AbilityRuntime {

ani_ref ETSAbilityStageContext::etsAbilityStageContextObj_ = nullptr;

ani_object ETSAbilityStageContext::CreateEtsAbilityStageContext(ani_env* env, std::shared_ptr<Context> context)
{
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "env nullptr or context nullptr");
        return nullptr;
    }

    ani_status status = ANI_OK;
    ani_class abilityStageCtxCls;
    status = env->FindClass(ETS_ABILITY_STAGE_CONTEXT_CLASS_NAME, &abilityStageCtxCls);
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
    etsAbilityStageContextObj_ = reinterpret_cast<ani_ref>(obj);

    //bind context
    auto workContext = new (std::nothrow) std::weak_ptr<AbilityRuntime::Context>(context);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "workContext nullptr");
        return nullptr;
    }
    ani_field contextField;
    status = env->Class_FindField(abilityStageCtxCls, "nativeContext", &contextField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "call Class_FindField nativeContext failed");
    }
    ani_long nativeContextLong = (ani_long)workContext;
    status = env->Object_SetField_Long(obj, contextField, nativeContextLong);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "call Object_SetField_Long contextField failed");
        delete workContext;
        return nullptr;
    }

    ContextUtil::CreateEtsBaseContext(env, abilityStageCtxCls, obj, context);
    //set Config class
    SetConfiguration(env, abilityStageCtxCls, obj, context);
    return obj;
}

void ETSAbilityStageContext::SetConfiguration(ani_env* env, ani_class stageCls, ani_object stageCtxObj,
    std::shared_ptr<Context> &context)
{
    if (context == nullptr || env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "env or context null ptr");
        return;
    }
    auto configuration = context->GetConfiguration();
    if (configuration == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "configuration null ptr");
        return;
    }
    ani_object configObj = OHOS::AppExecFwk::WrapConfiguration(env, *configuration);
    if (configObj == nullptr) {
        TAG_LOGD(AAFwkTag::ABILITY, "configObj null ptr");
        return;
    }
    ani_status status = ANI_OK;
    status = env->Object_SetFieldByName_Ref(stageCtxObj, "config", configObj);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetPropertyByName_Ref failed, status: %{public}d", status);
    }
}

void ETSAbilityStageContext::ConfigurationUpdated(
    ani_env *env, const std::shared_ptr<AppExecFwk::Configuration> &config)
{
    if (!config) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "null config");
        return;
    }
    ani_object configObj = OHOS::AppExecFwk::WrapConfiguration(env, *config);

    ani_class abilityStageCtxCls = nullptr;
    ani_status status = env->FindClass(ETS_ABILITY_STAGE_CLASS_NAME, &abilityStageCtxCls);
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
