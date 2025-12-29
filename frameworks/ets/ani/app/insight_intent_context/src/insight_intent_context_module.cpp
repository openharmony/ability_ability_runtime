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

#include <cstdio>
#include <sys/syscall.h>
#include <unistd.h>

#include "insight_intent_context_module.h"
#include "ani_base_context.h"
#include "ani_common_util.h"
#include "context_transfer.h"
#include "ets_error_utils.h"
#include "ets_insight_intent_context.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "js_insight_intent_context.h"
#include "js_runtime_utils.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *INSIGHT_INTENT_CONTEXT_CLASS_NAME =
    "@ohos.app.ability.InsightIntentContext.InsightIntentContext";
} // namespace

ani_object EtsInsightIntentContextModule::NativeTransferStatic(
    ani_env *aniEnv, ani_object, ani_object input, ani_object type)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::INTENT, "transfer static InsightIntentContext");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null aniEnv");
        return nullptr;
    }

    void *unwrapResult = nullptr;
    bool success = arkts_esvalue_unwrap(aniEnv, input, &unwrapResult);
    if (!success) {
        TAG_LOGE(AAFwkTag::INTENT, "failed to unwrap");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }
    if (unwrapResult == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null unwrapResult");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto jsIntentContext = reinterpret_cast<JsInsightIntentContext *>(unwrapResult);
    if (jsIntentContext == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null JsInsightIntentContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }
    auto insightIntentContext = jsIntentContext->GetContext();
    if (insightIntentContext == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null InsightIntentContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }
    // if not exist, create a new one
    std::string contextType;
    if (!AppExecFwk::GetStdString(aniEnv, reinterpret_cast<ani_string>(type), contextType)) {
        TAG_LOGE(AAFwkTag::INTENT, "GetStdString failed");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::INTENT, "contextType %{public}s", contextType.c_str());
    EtsInsightIntentContext *etsContext = new (std::nothrow) EtsInsightIntentContext(insightIntentContext);
    auto newContext = CreateEtsInsightIntentContext(aniEnv, etsContext);
    if (newContext == nullptr || newContext->aniObj == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "create insightIntentContext failed");
        delete etsContext;
        return nullptr;
    }
    return newContext->aniObj;
}

napi_value AttachInsightIntentContext(napi_env env, void *value, void *)
{
    if (value == nullptr) {
        TAG_LOGW(AAFwkTag::INTENT, "null value");
        return nullptr;
    }
    auto ptr = reinterpret_cast<std::weak_ptr<InsightIntentContext> *>(value)->lock();
    if (ptr == nullptr) {
        TAG_LOGW(AAFwkTag::INTENT, "null ptr");
        return nullptr;
    }
    napi_value object = CreateJsInsightIntentContext(env, ptr);
    auto systemModule = JsRuntime::LoadSystemModuleByEngine(env, "app.ability.InsightIntentContext", &object, 1);
    if (systemModule == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null systemModule");
        return nullptr;
    }
    auto contextObj = systemModule->GetNapiValue();
    napi_coerce_to_native_binding_object(
        env, contextObj, DetachCallbackFunc, AttachInsightIntentContext, value, nullptr);
    auto workContext = new (std::nothrow) std::weak_ptr<InsightIntentContext>(ptr);
    auto res = napi_wrap(env, contextObj, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::INTENT, "Finalizer for weak_ptr insight intent context is called");
            delete static_cast<std::weak_ptr<InsightIntentContext> *>(data);
        },
        nullptr, nullptr);
    if (res != napi_ok && workContext != nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "napi_wrap failed:%{public}d", res);
        delete workContext;
        return nullptr;
    }
    return contextObj;
}

std::unique_ptr<NativeReference> EtsInsightIntentContextModule::CreateNativeReference(
    napi_env napiEnv, std::shared_ptr<InsightIntentContext> insightIntentContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (napiEnv == nullptr || insightIntentContext == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null param");
        return nullptr;
    }

    auto value = CreateJsInsightIntentContext(napiEnv, insightIntentContext);
    auto systemModule = JsRuntime::LoadSystemModuleByEngine(napiEnv, "app.ability.InsightIntentContext", &value, 1);
    if (systemModule == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null systemModule");
        return nullptr;
    }

    napi_value object = systemModule->GetNapiValue();
    if (!CheckTypeForNapiValue(napiEnv, object, napi_object)) {
        TAG_LOGE(AAFwkTag::INTENT, "check type failed");
        return nullptr;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<InsightIntentContext>(insightIntentContext);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null workContext");
        return nullptr;
    }
    auto status = napi_coerce_to_native_binding_object(
        napiEnv, object, DetachCallbackFunc, AttachInsightIntentContext, workContext, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::INTENT, "coerce InsightIntentContext failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    status = napi_wrap(napiEnv, object, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::INTENT, "finalizer for weak_ptr InsightIntentContext");
            delete static_cast<std::weak_ptr<InsightIntentContext> *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::INTENT, "wrap failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    return systemModule;
}

napi_value EtsInsightIntentContextModule::GetOrCreateDynamicObject(
    napi_env napiEnv, std::shared_ptr<InsightIntentContext> insightIntentContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (napiEnv == nullptr || insightIntentContext == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null param");
        return nullptr;
    }

    // if main-thread bindingObj didn't exist, create and bind
    auto nativeRef = CreateNativeReference(napiEnv, insightIntentContext);
    if (nativeRef == nullptr) {
        return nullptr;
    }

    auto object = nativeRef->Get();
    return object;
}

EtsInsightIntentContext *GetEtsInsightIntentContext(ani_env *env, ani_object aniObj)
{
    ani_long nativeContextLong;
    ani_class cls {};
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return nullptr;
    }

    if ((status = env->FindClass(INSIGHT_INTENT_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
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

ani_object EtsInsightIntentContextModule::NativeTransferDynamic(ani_env *aniEnv, ani_class aniCls, ani_object input)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::INTENT, "transfer dynamic InsightIntentContext");
    if (!IsInstanceOf(aniEnv, input)) {
        TAG_LOGE(AAFwkTag::INTENT, "not InsightIntentContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto etsContext = GetEtsInsightIntentContext(aniEnv, input);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null etsInsightIntentContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    ani_object object = CreateDynamicObject(aniEnv, aniCls, etsContext->GetNativeContext());
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "invalid object");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    return object;
}

ani_object EtsInsightIntentContextModule::CreateDynamicObject(
    ani_env *aniEnv, ani_class aniCls, std::shared_ptr<InsightIntentContext> insightIntentContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::string contextType;
    if (!AppExecFwk::GetStaticFieldString(aniEnv, aniCls, "contextType", contextType)) {
        TAG_LOGE(AAFwkTag::INTENT, "get context type failed");
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::INTENT, "contextType %{public}s", contextType.c_str());

    // get napiEnv from aniEnv
    napi_env napiEnv = {};
    if (!arkts_napi_scope_open(aniEnv, &napiEnv)) {
        TAG_LOGE(AAFwkTag::INTENT, "arkts_napi_scope_open failed");
        return nullptr;
    }

    // create normal ability context
    auto contextObj = EtsInsightIntentContextModule::GetOrCreateDynamicObject(napiEnv, insightIntentContext);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "create InsightIntentContext failed");
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    hybridgref ref = nullptr;
    bool success = hybridgref_create_from_napi(napiEnv, contextObj, &ref);
    if (!success) {
        TAG_LOGE(AAFwkTag::INTENT, "hybridgref_create_from_napi failed");
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    ani_object result = nullptr;
    success = hybridgref_get_esvalue(aniEnv, ref, &result);
    if (!success) {
        TAG_LOGE(AAFwkTag::INTENT, "hybridgref_get_esvalue failed");
        hybridgref_delete_from_napi(napiEnv, ref);
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    hybridgref_delete_from_napi(napiEnv, ref);

    if (!arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr)) {
        TAG_LOGE(AAFwkTag::INTENT, "arkts_napi_scope_close_n failed");
        return nullptr;
    }

    return result;
}

bool EtsInsightIntentContextModule::IsInstanceOf(ani_env *aniEnv, ani_object aniObj)
{
    ani_class cls {};
    ani_status status = ANI_ERROR;
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null aniEnv");
        return false;
    }
    if ((status = aniEnv->FindClass(INSIGHT_INTENT_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "FindClass status: %{public}d", status);
        return false;
    }
    ani_boolean isInstanceOf = false;
    if ((status = aniEnv->Object_InstanceOf(aniObj, cls, &isInstanceOf)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "Object_InstanceOf status: %{public}d", status);
        return false;
    }
    return isInstanceOf;
}

void EtsInsightIntentContextModuleInit(ani_env *aniEnv)
{
    TAG_LOGD(AAFwkTag::INTENT, "Init InsightIntentContext kit");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null ani env");
        return;
    }

    ani_class insightIntentContextCls = nullptr;
    auto status = aniEnv->FindClass(INSIGHT_INTENT_CONTEXT_CLASS_NAME, &insightIntentContextCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "FindClass InsightIntentContext failed status: %{public}d", status);
        return;
    }

    std::array nativeFuncs = {
        ani_native_function { "nativeTransferStatic", "C{std.interop.ESValue}C{std.core.String}:C{std.core.Object}",
            reinterpret_cast<void *>(EtsInsightIntentContextModule::NativeTransferStatic) },
        ani_native_function { "nativeTransferDynamic", "C{std.core.Object}:C{std.interop.ESValue}",
            reinterpret_cast<void *>(EtsInsightIntentContextModule::NativeTransferDynamic) },
    };
    status = aniEnv->Class_BindStaticNativeMethods(insightIntentContextCls, nativeFuncs.data(), nativeFuncs.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "Class_BindStaticNativeMethods failed status: %{public}d", status);
        return;
    }

    TAG_LOGD(AAFwkTag::INTENT, "Init InsightIntentContext kit end");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::INTENT, "ANI_Constructor");
    if (vm == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null vm");
        return ANI_ERROR;
    }

    ani_env *aniEnv = nullptr;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &aniEnv);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    }

    EtsInsightIntentContextModuleInit(aniEnv);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::INTENT, "ANI_Constructor finish");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS
