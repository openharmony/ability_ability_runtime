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

#include "ets_form_extension_context.h"

#include <algorithm>
#include <iterator>

#include "ani_common_configuration.h"
#include "form_extension_context.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* FORM_EXTENSION_CONTEXT_CLASS_NAME = "Lapplication/FormExtensionContext/FormExtensionContext;";
}

ani_object ETSFormExtensionContext::SetFormExtensionContext(
    ani_env *env, const std::shared_ptr<FormExtensionContext> &context)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "SetFormExtensionContext call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "env null");
        return nullptr;
    }
    ani_long nativeContextLong = (ani_long)context.get();
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_object contextObj = nullptr;
    ani_method method = nullptr;
    ani_field field = nullptr;

    if ((status = env->FindClass(FORM_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetField_Long(contextObj, field, nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "status : %{public}d", status);
        return nullptr;
    }
    TAG_LOGI(AAFwkTag::FORM_EXT, "SetFormExtensionContext end");
    return contextObj;
}

ani_ref ETSFormExtensionContext::CreateEtsExtensionContext(ani_env *env,
    const std::shared_ptr<FormExtensionContext> &context, std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> &abilityInfo)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "CreateEtsExtensionContext call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "env null");
        return nullptr;
    }

    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;

    status = env->FindClass(FORM_EXTENSION_CONTEXT_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "status : %{public}d", status);
        return nullptr;
    }

    ani_object contextObj = ETSFormExtensionContext::SetFormExtensionContext(env, context);

    TAG_LOGI(AAFwkTag::FORM_EXT, "CreateEtsExtensionContext end");
    return contextObj;
}

ani_ref CreateEtsFormExtensionContext(ani_env *env, std::shared_ptr<FormExtensionContext> &context)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "CreateEtsFormExtensionContext call");
    auto abilityInfo = context->GetAbilityInfo();
    ani_ref object = ETSFormExtensionContext::CreateEtsExtensionContext(env, context, abilityInfo);
    TAG_LOGI(AAFwkTag::FORM_EXT, "CreateEtsFormExtensionContext end");
    return object;
}
} // namespace AbilityRuntime
} // namespace OHOS