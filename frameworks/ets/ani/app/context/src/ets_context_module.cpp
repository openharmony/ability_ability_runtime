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

#include "ets_context_module.h"

#include <cstdio>
#include <sys/syscall.h>
#include <unistd.h>
#include "ani_base_context.h"
#include "ani_common_util.h"
#include "application_context_manager.h"
#include "context_transfer.h"
#include "ets_application_context_utils.h"
#include "event_hub.h"
#include "hilog_tag_wrapper.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "js_ability_stage_context.h"
#include "js_application_context_utils.h"
#include "js_context_utils.h"
#include "js_runtime_utils.h"
#include "native_engine/native_engine.h"
#include "sts_ability_stage_context.h"
#include "sts_context_utils.h"
#include "sts_error_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *ETS_CONTEXT_CLASS_NAME = "Lapplication/Context/Context;";
} // namespace

ani_object EtsContextModule::NativeTransferStatic(ani_env *aniEnv, ani_object self, ani_object input, ani_object type)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "transfer static Context");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null aniEnv");
        return nullptr;
    }
    void *unwrapResult = nullptr;
    bool success = arkts_esvalue_unwrap(aniEnv, input, &unwrapResult);
    if (!success) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed to unwrap");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }
    if (unwrapResult == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null unwrapResult");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }

    auto context = reinterpret_cast<std::weak_ptr<Context> *>(unwrapResult)->lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null Context");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }

    auto &bindingObj = context->GetBindingObject();
    if (bindingObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null bindingObj");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }

    auto staticContext = bindingObj->Get<ani_ref>();
    if (staticContext != nullptr) {
        TAG_LOGI(AAFwkTag::CONTEXT, "there exist a staticContext");
        return reinterpret_cast<ani_object>(*staticContext);
    }

    std::string contextType;
    if (!AppExecFwk::GetStdString(aniEnv, reinterpret_cast<ani_string>(type), contextType)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "GetStdString failed");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::CONTEXT, "contextType %{public}s", contextType.c_str());

    auto contextObj = GetOrCreateAniObject(aniEnv, context);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "contextObj invalid");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }

    return contextObj;
}

ani_object EtsContextModule::GetOrCreateAniObject(ani_env *aniEnv, std::shared_ptr<Context> context)
{
    // If context is UIAbilityContext, then the bindingObj->Get<ani_ref> will not nullptr,
    // So check ApplicationContext and AbilityStageContext.
    auto appContext = Context::ConvertTo<ApplicationContext>(context);
    if (appContext != nullptr) {
        TAG_LOGI(AAFwkTag::CONTEXT, "Context is ApplicationContext");
        EtsApplicationContextUtils::CreateEtsApplicationContext(aniEnv);
        auto appContextObj = ApplicationContextManager::GetApplicationContextManager().GetEtsGlobalObject();
        if (appContextObj != nullptr) {
            TAG_LOGI(AAFwkTag::CONTEXT, "appContextObj is valid");
            return appContextObj->aniObj;
        }
    }

    auto abilityStageContext = Context::ConvertTo<AbilityStageContext>(context);
    if (abilityStageContext != nullptr) {
        TAG_LOGI(AAFwkTag::CONTEXT, "Context is AbilityStageContext");
        auto newContext = STSAbilityStageContext::CreateStsAbilityStageContext(aniEnv, abilityStageContext);
        if (newContext != nullptr) {
            TAG_LOGI(AAFwkTag::CONTEXT, "newContext is valid");
            return newContext;
        }
    }

    ani_class cls {};
    ani_status status = ANI_ERROR;
    if ((status = aniEnv->FindClass("Lapplication/Context/Context;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "status: %{public}d", status);
        return nullptr;
    }
    return ContextUtil::CreateContextObject(aniEnv, cls, context);
}

std::unique_ptr<NativeReference> EtsContextModule::CreateNativeReference(napi_env napiEnv,
    std::shared_ptr<Context> context)
{
    if (napiEnv == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null param");
        return nullptr;
    }

    auto value = CreateJsBaseContext(napiEnv, context);
    auto systemModule = JsRuntime::LoadSystemModuleByEngine(napiEnv, "application.Context", &value, 1);
    if (systemModule == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null system module");
        return nullptr;
    }

    napi_value object = systemModule->GetNapiValue();
    if (!CheckTypeForNapiValue(napiEnv, object, napi_object)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "check type failed");
        return nullptr;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<Context>(context);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null workContext");
        return nullptr;
    }
    auto status = napi_coerce_to_native_binding_object(napiEnv, object, DetachCallbackFunc, AttachBaseContext,
        workContext, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "coerce context failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    status = napi_wrap(napiEnv, object, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::CONTEXT, "finalizer for weak_ptr context");
            delete static_cast<std::weak_ptr<Context> *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "wrap failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    return systemModule;
}

std::unique_ptr<NativeReference> EtsContextModule::CreateApplicationNativeReference(napi_env napiEnv,
    std::shared_ptr<ApplicationContext> applicationContext)
{
    if (napiEnv == nullptr || applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null param");
        return nullptr;
    }

    auto value = JsApplicationContextUtils::CreateJsApplicationContext(napiEnv);
    auto systemModule = JsRuntime::LoadSystemModuleByEngine(napiEnv, "application.ApplicationContext", &value, 1);
    if (systemModule == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null system module");
        return nullptr;
    }

    napi_value object = systemModule->GetNapiValue();
    if (!CheckTypeForNapiValue(napiEnv, object, napi_object)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "check type failed");
        return nullptr;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<ApplicationContext>(applicationContext);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null workContext");
        return nullptr;
    }
    auto status = napi_coerce_to_native_binding_object(napiEnv, object, DetachCallbackFunc, AttachApplicationContext,
        workContext, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "coerce applicationContext failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    status = napi_wrap(napiEnv, object, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::CONTEXT, "finalizer for weak_ptr applicationContext");
            delete static_cast<std::weak_ptr<ApplicationContext> *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "wrap failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    return systemModule;
}

std::unique_ptr<NativeReference> EtsContextModule::CreateAbilityStageNativeReference(napi_env napiEnv,
    std::shared_ptr<AbilityStageContext> abilityStageContext)
{
    if (napiEnv == nullptr || abilityStageContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null param");
        return nullptr;
    }

    auto value = CreateJsAbilityStageContext(napiEnv, abilityStageContext);
    auto systemModule = JsRuntime::LoadSystemModuleByEngine(napiEnv, "application.AbilityStageContext", &value, 1);
    if (systemModule == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null systemModule");
        return nullptr;
    }

    napi_value object = systemModule->GetNapiValue();
    if (!CheckTypeForNapiValue(napiEnv, object, napi_object)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "check type failed");
        return nullptr;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<AbilityStageContext>(abilityStageContext);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null workContext");
        return nullptr;
    }
    auto status = napi_coerce_to_native_binding_object(napiEnv, object, DetachCallbackFunc, AttachAbilityStageContext,
        workContext, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "coerce AbilityStageContext failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    status = napi_wrap(napiEnv, object, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::CONTEXT, "finalizer for weak_ptr AbilityStageContext");
            delete static_cast<std::weak_ptr<AbilityStageContext> *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "wrap failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    return systemModule;
}

std::unique_ptr<NativeReference> EtsContextModule::GetOrCreateNativeReference(napi_env napiEnv,
    std::shared_ptr<Context> context)
{
    if (napiEnv == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null param");
        return nullptr;
    }

    // if sub-thread, create a new context and return
    if (getpid() != syscall(SYS_gettid)) {
        return CreateNativeReference(napiEnv, context);
    }

    // if main-thread, get bindingObj firstly
    auto &bindingObj = context->GetBindingObject();
    if (bindingObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null bindingObj");
        return nullptr;
    }

    // if main-thread bindingObj exist, return it directly
    auto dynamicContext = bindingObj->Get<NativeReference>();
    if (dynamicContext != nullptr) {
        TAG_LOGI(AAFwkTag::UIABILITY, "there exist a dynamicContext");
        return std::unique_ptr<NativeReference>(dynamicContext);
    }

    // If context is UIAbilityContext, then the bindingObj->Get<NativeReference>() will not nullptr,
    // So check ApplicationContext and AbilityStageContext.
    std::unique_ptr<NativeReference> nativeRef;
    auto appContext = Context::ConvertTo<ApplicationContext>(context);
    if (appContext != nullptr) {
        TAG_LOGI(AAFwkTag::CONTEXT, "Context is ApplicationContext");
        nativeRef = CreateApplicationNativeReference(napiEnv, appContext);
    }

    auto abilityStageContext = Context::ConvertTo<AbilityStageContext>(context);
    if (abilityStageContext != nullptr) {
        TAG_LOGI(AAFwkTag::CONTEXT, "Context is AbilityStageContext");
        nativeRef = CreateAbilityStageNativeReference(napiEnv, abilityStageContext);
    }

    // if main-thread bindingObj didn't exist, create and bind
    if (nativeRef == nullptr) {
        return nullptr;
    }

    context->Bind(nativeRef.get());
    return nativeRef;
}

ani_object EtsContextModule::NativeTransferDynamic(ani_env *aniEnv, ani_class aniCls, ani_object input)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "transfer dynamic Context");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null aniEnv");
        return nullptr;
    }

    auto context = AbilityRuntime::GetStageModeContext(aniEnv, input);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }

    std::shared_ptr<Context> contextPtr = Context::ConvertTo<Context>(context);
    if (contextPtr == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "invalid Context");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }

    ani_object object = CreateDynamicObject(aniEnv, aniCls, contextPtr);
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "invalid object");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }

    return object;
}

ani_object EtsContextModule::CreateDynamicObject(ani_env *aniEnv, ani_class aniCls,
    std::shared_ptr<Context> contextPtr)
{
    std::string contextType;
    if (!AppExecFwk::GetStaticFieldString(aniEnv, aniCls, "contextType", contextType)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "get context type failed");
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::CONTEXT, "contextType %{public}s", contextType.c_str());

    // get napiEnv from aniEnv
    napi_env napiEnv = {};
    if (!arkts_napi_scope_open(aniEnv, &napiEnv)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "arkts_napi_scope_open failed");
        return nullptr;
    }

    // create normal context
    auto contextObj = ContextTransfer::GetInstance().GetDynamicObject(contextType, napiEnv, contextPtr);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "create Context failed");
        return nullptr;
    }

    hybridgref ref = nullptr;
    bool success = hybridgref_create_from_napi(napiEnv, contextObj, &ref);
    if (!success) {
        TAG_LOGE(AAFwkTag::CONTEXT, "hybridgref_create_from_napi failed");
        return nullptr;
    }

    ani_object result = nullptr;
    success = hybridgref_get_esvalue(aniEnv, ref, &result);
    if (!success) {
        TAG_LOGE(AAFwkTag::CONTEXT, "hybridgref_get_esvalue failed");
        return nullptr;
    }

    hybridgref_delete_from_napi(napiEnv, ref);

    if (!arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "arkts_napi_scope_close_n failed");
        return nullptr;
    }

    return result;
}

void EtsContextModuleInit(ani_env *aniEnv)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "Init Context kit");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null ani env");
        return;
    }

    ani_class contextCls = nullptr;
    auto status = aniEnv->FindClass(ETS_CONTEXT_CLASS_NAME, &contextCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "FindClass Context failed status: %{public}d", status);
        return;
    }

    std::array nativeFuncs = {
        ani_native_function { "nativeTransferStatic", "Lstd/interop/ESValue;Lstd/core/String;:Lstd/core/Object;",
            reinterpret_cast<void*>(EtsContextModule::NativeTransferStatic) },
        ani_native_function { "nativeTransferDynamic", "Lstd/core/Object;:Lstd/interop/ESValue;",
            reinterpret_cast<void*>(EtsContextModule::NativeTransferDynamic) },
    };
    status = aniEnv->Class_BindNativeMethods(contextCls, nativeFuncs.data(), nativeFuncs.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Class_BindNativeMethods failed status: %{public}d", status);
        return;
    }

    ContextTransfer::GetInstance().RegisterStaticObjectCreator("Context",
        [](ani_env *aniEnv, std::shared_ptr<Context> context) -> ani_object {
            ani_class cls {};
            ani_status status = ANI_ERROR;
            if ((status = aniEnv->FindClass("Lapplication/Context/Context;", &cls)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::CONTEXT, "status: %{public}d", status);
                return nullptr;
            }
            return ContextUtil::CreateContextObject(aniEnv, cls, context);
    });

    ContextTransfer::GetInstance().RegisterDynamicObjectCreator("Context",
        [](napi_env napiEnv, std::shared_ptr<Context> context) -> napi_value {
            auto ref = EtsContextModule::GetOrCreateNativeReference(napiEnv, context);
            if (ref == nullptr) {
                return nullptr;
            }
            return ref->Get();
    });

    TAG_LOGD(AAFwkTag::CONTEXT, "Init Context kit end");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "ANI_Constructor");
    if (vm == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null vm");
        return ANI_ERROR;
    }

    ani_env *aniEnv = nullptr;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &aniEnv);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    }

    EtsContextModuleInit(aniEnv);
    AbilityRuntime::EventHub::InitAniEventHub(aniEnv);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::CONTEXT, "ANI_Constructor finish");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS
