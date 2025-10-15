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

#include "ets_insight_intent_context.h"

#include "ability_window_configuration.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "ani_common_want.h"
#include "ets_error_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *CONTEXT_CLASS_NAME = "L@ohos/app/ability/InsightIntentContext/InsightIntentContext;";
}
void EtsInsightIntentContext::Finalizer(ani_env *env, void *data, void *hint)
{
    TAG_LOGI(AAFwkTag::INTENT, "EtsInsightIntentContext::Finalizer called");
    std::unique_ptr<EtsInsightIntentContext>(static_cast<EtsInsightIntentContext*>(data));
}

ani_object EtsInsightIntentContext::StartAbiitySync(ani_env *env, ani_object aniObj, ani_object wantObj)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto context = GetContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "get context failed.");
        return EtsErrorUtil::CreateInvalidParamError(env, "context null");
    }

    AAFwk::Want want;
    if (!OHOS::AppExecFwk::UnwrapWant(env, wantObj, want)) {
        TAG_LOGE(AAFwkTag::INTENT, "parse wantParam failed");
        return EtsErrorUtil::CreateInvalidParamError(env, "Parse param want failed, want must be Want.");
    }

    return context->StartAbilityInner(env, want);
}

EtsInsightIntentContext *EtsInsightIntentContext::GetContext(ani_env *env, ani_object aniObj)
{
    ani_long nativeContextLong;
    ani_class cls {};
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return nullptr;
    }

    if ((status = env->FindClass(CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return nullptr;
    }

    if ((status = env->Class_FindField(cls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_GetField_Long(aniObj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return nullptr;
    }
    return reinterpret_cast<EtsInsightIntentContext *>(nativeContextLong);
}

ani_object EtsInsightIntentContext::StartAbilityInner(ani_env *env, AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentContext::StartAbilityInner called");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);

    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null context");
        return EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_CODE_INNER);
    }

    // verify if bundleName is empty or invalid
    auto bundleNameFromWant = want.GetElement().GetBundleName();
    if (bundleNameFromWant.empty() || bundleNameFromWant != context->GetBundleName()) {
        TAG_LOGE(AAFwkTag::INTENT, "bundleName empty or invalid");
        return EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_CODE_OPERATION_NOT_SUPPORTED);
    }
    // modify windowmode setting
    auto windowMode = context->GetCurrentWindowMode();
    if (windowMode == AAFwk::AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_PRIMARY ||
        windowMode == AAFwk::AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_SECONDARY) {
        want.SetParam(AAFwk::Want::PARAM_RESV_WINDOW_MODE, windowMode);
    }

    auto innerErrCode = context->StartAbilityByInsightIntent(want);
    if (innerErrCode == ERR_OK) {
        return EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    } else {
        return EtsErrorUtil::CreateErrorByNativeErr(env, innerErrCode);
    }
}

std::unique_ptr<AppExecFwk::ETSNativeReference> CreateEtsInsightIntentContext(ani_env *env,
    const EtsInsightIntentContext *context)
{
    TAG_LOGD(AAFwkTag::INTENT, "CreateEtsInsightIntentContext called");
    ani_long nativeContextLong = (ani_long)context;
    ani_class cls {};
    ani_status status = ANI_ERROR;
    ani_object contextObj = nullptr;
    ani_method method {};
    ani_field field = nullptr;
    ani_ref contextObjtRef = nullptr;
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null context");
        return std::unique_ptr<AppExecFwk::ETSNativeReference>();
    }
    if ((status = env->FindClass(CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return std::unique_ptr<AppExecFwk::ETSNativeReference>();
    }
    std::array functions = {
        ani_native_function { "nativeStartAbilitySync", nullptr,
            reinterpret_cast<void*>(EtsInsightIntentContext::StartAbiitySync) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        if (status != ANI_ALREADY_BINDED) {
            TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
            return std::unique_ptr<AppExecFwk::ETSNativeReference>();
        }
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return std::unique_ptr<AppExecFwk::ETSNativeReference>();
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return std::unique_ptr<AppExecFwk::ETSNativeReference>();
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return std::unique_ptr<AppExecFwk::ETSNativeReference>();
    }
    if ((status = env->Object_SetField_Long(contextObj, field, nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return std::unique_ptr<AppExecFwk::ETSNativeReference>();
    }
    if ((status = env->GlobalReference_Create(contextObj, &contextObjtRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return std::unique_ptr<AppExecFwk::ETSNativeReference>();
    }
    auto nativeReference = std::make_unique<AppExecFwk::ETSNativeReference>();
    nativeReference->aniCls = cls;
    nativeReference->aniObj = contextObj;
    nativeReference->aniRef = contextObjtRef;
    return nativeReference;
}
} // namespace AbilityRuntime
} // namespace OHOS
