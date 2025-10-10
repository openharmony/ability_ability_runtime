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

#include "ets_app_service_extension_context_module.h"

#include <cstdio>
#include <sys/syscall.h>
#include <unistd.h>

#include "ani_base_context.h"
#include "ani_common_util.h"
#include "context_transfer.h"
#include "ets_app_service_extension_context.h"
#include "ets_context_utils.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "js_app_service_extension_context.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *ETS_APP_SERVICE_EXTENSION_CONTEXT_CLASS_NAME =
    "Lapplication/AppServiceExtensionContext/AppServiceExtensionContext;";
} // namespace

ani_object EtsAppServiceExtensionContextModule::NativeTransferStatic(ani_env *aniEnv, ani_object, ani_object input,
    ani_object type)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::CONTEXT, "transfer static AppServiceExtensionContext");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null aniEnv");
        return nullptr;
    }

    void *unwrapResult = nullptr;
    bool success = arkts_esvalue_unwrap(aniEnv, input, &unwrapResult);
    if (!success) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed to unwrap");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }
    if (unwrapResult == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null unwrapResult");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto context = reinterpret_cast<std::weak_ptr<AppServiceExtensionContext> *>(unwrapResult)->lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null AppServiceExtensionContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto appServiceExtensionContext = Context::ConvertTo<AppServiceExtensionContext>(context);
    if (appServiceExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "invalid appServiceExtensionContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto &bindingObj = appServiceExtensionContext->GetBindingObject();
    if (bindingObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null bindingObj");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto staticContext = bindingObj->Get<ani_ref>();
    if (staticContext != nullptr) {
        TAG_LOGI(AAFwkTag::CONTEXT, "there exist a staticContext");
        return reinterpret_cast<ani_object>(*staticContext);
    }

    // if not exist, create a new one
    auto newContext = CreateStaticObject(aniEnv, type, context);
    if (newContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "newContext invalid");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    return newContext;
}

ani_object EtsAppServiceExtensionContextModule::CreateStaticObject(ani_env *aniEnv, ani_object type,
    std::shared_ptr<AppServiceExtensionContext> appServiceExtensionContext)
{
    std::string contextType;
    if (!AppExecFwk::GetStdString(aniEnv, reinterpret_cast<ani_string>(type), contextType)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "GetStdString failed");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::CONTEXT, "contextType %{public}s", contextType.c_str());

    auto newContext = ContextTransfer::GetInstance().GetStaticObject(contextType, aniEnv, appServiceExtensionContext);
    if (newContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "create appServiceExtensionContext failed");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    return newContext;
}

std::unique_ptr<NativeReference> EtsAppServiceExtensionContextModule::CreateNativeReference(napi_env napiEnv,
    std::shared_ptr<AppServiceExtensionContext> appServiceExtensionContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (napiEnv == nullptr || appServiceExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null param");
        return nullptr;
    }

    auto value = CreateJsAppServiceExtensionContext(napiEnv, appServiceExtensionContext);
    auto systemModule = JsRuntime::LoadSystemModuleByEngine(napiEnv, "application.AppServiceExtensionContext", &value,
        1);
    if (systemModule == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null systemModule");
        return nullptr;
    }

    napi_value object = systemModule->GetNapiValue();
    if (!CheckTypeForNapiValue(napiEnv, object, napi_object)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "check type failed");
        return nullptr;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<AppServiceExtensionContext>(appServiceExtensionContext);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null workContext");
        return nullptr;
    }
    auto status = napi_coerce_to_native_binding_object(napiEnv, object, DetachCallbackFunc,
        AttachAppServiceExtensionContext, workContext, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "coerce AppServiceExtensionContext failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    status = napi_wrap(napiEnv, object, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::CONTEXT, "finalizer for weak_ptr AppServiceExtensionContext");
            delete static_cast<std::weak_ptr<AppServiceExtensionContext> *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "wrap failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    return systemModule;
}

napi_value EtsAppServiceExtensionContextModule::GetOrCreateDynamicObject(napi_env napiEnv,
    std::shared_ptr<AppServiceExtensionContext> appServiceExtensionContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (napiEnv == nullptr || appServiceExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null param");
        return nullptr;
    }

    // if sub-thread, create a new appServiceExtensionContext and return
    if (getpid() != syscall(SYS_gettid)) {
        auto subThreadObj = static_cast<NativeReference *>(
            appServiceExtensionContext->GetSubThreadObject(static_cast<void *>(napiEnv)));
        if (subThreadObj != nullptr) {
            return subThreadObj->Get();
        }
        auto subThreadRef = CreateNativeReference(napiEnv, appServiceExtensionContext);
        if (subThreadRef == nullptr) {
            return nullptr;
        }
        auto newObject = subThreadRef->Get();
        appServiceExtensionContext->BindSubThreadObject(
            static_cast<void *>(napiEnv), static_cast<void *>(subThreadRef.release()));
        return newObject;
    }

    // if main-thread, get bindingObj firstly
    auto &bindingObj = appServiceExtensionContext->GetBindingObject();
    if (bindingObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null bindingObj");
        return nullptr;
    }

    // if main-thread bindingObj exist, return it directly
    auto dynamicContext = bindingObj->Get<NativeReference>();
    if (dynamicContext != nullptr) {
        TAG_LOGI(AAFwkTag::UIABILITY, "there exist a dynamicContext");
        return dynamicContext->Get();
    }

    // if main-thread bindingObj didn't exist, create and bind
    auto nativeRef = CreateNativeReference(napiEnv, appServiceExtensionContext);
    if (nativeRef == nullptr) {
        return nullptr;
    }

    auto object = nativeRef->Get();
    appServiceExtensionContext->Bind(nativeRef.release());
    return object;
}

ani_object EtsAppServiceExtensionContextModule::NativeTransferDynamic(ani_env *aniEnv, ani_class aniCls,
    ani_object input)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::CONTEXT, "transfer dynamic AppServiceExtensionContext");
    if (!IsInstanceOf(aniEnv, input)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "not AppServiceExtensionContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto context = AbilityRuntime::GetStageModeContext(aniEnv, input);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    std::shared_ptr<AppServiceExtensionContext> appServiceExtensionContext =
        Context::ConvertTo<AppServiceExtensionContext>(context);
    if (appServiceExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "invalid appServiceExtensionContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    ani_object object = CreateDynamicObject(aniEnv, aniCls, appServiceExtensionContext);
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "invalid object");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    return object;
}

ani_object EtsAppServiceExtensionContextModule::CreateDynamicObject(ani_env *aniEnv, ani_class aniCls,
    std::shared_ptr<AppServiceExtensionContext> appServiceExtensionContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
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

    // create normal AppServiceExtensionContext
    auto contextObj = ContextTransfer::GetInstance().GetDynamicObject(contextType, napiEnv, appServiceExtensionContext);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "create AppServiceExtensionContext failed");
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    hybridgref ref = nullptr;
    bool success = hybridgref_create_from_napi(napiEnv, contextObj, &ref);
    if (!success) {
        TAG_LOGE(AAFwkTag::CONTEXT, "hybridgref_create_from_napi failed");
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    ani_object result = nullptr;
    success = hybridgref_get_esvalue(aniEnv, ref, &result);
    if (!success) {
        TAG_LOGE(AAFwkTag::CONTEXT, "hybridgref_get_esvalue failed");
        hybridgref_delete_from_napi(napiEnv, ref);
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    hybridgref_delete_from_napi(napiEnv, ref);

    if (!arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "arkts_napi_scope_close_n failed");
        return nullptr;
    }

    return result;
}

bool EtsAppServiceExtensionContextModule::IsInstanceOf(ani_env *aniEnv, ani_object aniObj)
{
    ani_class cls {};
    ani_status status = ANI_ERROR;
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null aniEnv");
        return false;
    }
    if ((status = aniEnv->FindClass(ETS_APP_SERVICE_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "FindClass status: %{public}d", status);
        return false;
    }
    ani_boolean isInstanceOf = false;
    if ((status = aniEnv->Object_InstanceOf(aniObj, cls, &isInstanceOf)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Object_InstanceOf status: %{public}d", status);
        return false;
    }
    return isInstanceOf;
}

void EtsAppServiceExtensionContextModule::RegisterContextObjectCreator()
{
    ContextTransfer::GetInstance().RegisterStaticObjectCreator("AppServiceExtensionContext",
        [](ani_env *aniEnv, std::shared_ptr<Context> context) -> ani_object {
            auto appServiceExtensionContext = Context::ConvertTo<AppServiceExtensionContext>(context);
            if (appServiceExtensionContext == nullptr) {
                TAG_LOGE(AAFwkTag::CONTEXT, "invalid appServiceExtensionContext");
                return nullptr;
            }
            auto newContext = CreateEtsAppServiceExtensionContext(aniEnv, appServiceExtensionContext);
            if (newContext == nullptr) {
                TAG_LOGE(AAFwkTag::CONTEXT, "create appServiceExtensionContext failed");
                return nullptr;
            }
            return newContext;
    });

    ContextTransfer::GetInstance().RegisterDynamicObjectCreator("AppServiceExtensionContext",
        [](napi_env napiEnv, std::shared_ptr<Context> context) -> napi_value {
            auto appServiceExtensionContext = Context::ConvertTo<AppServiceExtensionContext>(context);
            if (appServiceExtensionContext == nullptr) {
                TAG_LOGE(AAFwkTag::CONTEXT, "invalid appServiceExtensionContext");
                return nullptr;
            }

            auto object = EtsAppServiceExtensionContextModule::GetOrCreateDynamicObject(napiEnv,
                appServiceExtensionContext);
            if (object == nullptr) {
                TAG_LOGE(AAFwkTag::CONTEXT, "get or create object failed");
                return nullptr;
            }
            return object;
    });
}

napi_value EtsAppServiceExtensionContextModule::AttachAppServiceExtensionContext(napi_env env, void *value, void *hint)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "attach appServiceExtensionContext");
    if (env == nullptr || value == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "invalid params");
        return nullptr;
    }
    auto ptr = reinterpret_cast<std::weak_ptr<AppServiceExtensionContext> *>(value)->lock();
    if (ptr == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null ptr");
        return nullptr;
    }

    auto object = CreateJsAppServiceExtensionContext(env, ptr);
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null object");
        return nullptr;
    }
    auto systemModule = JsRuntime::LoadSystemModuleByEngine(env, "application.AppServiceExtensionContext", &object, 1);
    if (systemModule == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null systemModule");
        return nullptr;
    }
    auto contextObj = systemModule->GetNapiValue();
    if (!CheckTypeForNapiValue(env, contextObj, napi_object)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "not napi object");
        return nullptr;
    }

    auto status = napi_coerce_to_native_binding_object(
        env, contextObj, DetachCallbackFunc, AttachAppServiceExtensionContext, value, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "coerce appServiceExtensionContext failed: %{public}d", status);
        return nullptr;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<AppServiceExtensionContext>(ptr);
    status = napi_wrap(env, contextObj, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::CONTEXT, "finalizer for weak_ptr appServiceExtensionContext");
            delete static_cast<std::weak_ptr<AppServiceExtensionContext> *>(data);
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "wrap appServiceExtensionContext failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    return contextObj;
}

void EtsAppServiceExtensionContextModuleInit(ani_env *aniEnv)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "Init AppServiceExtensionContext kit");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null ani env");
        return;
    }

    ani_class appServiceExtensionContextCls = nullptr;
    auto status = aniEnv->FindClass(ETS_APP_SERVICE_EXTENSION_CONTEXT_CLASS_NAME, &appServiceExtensionContextCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "FindClass AppServiceExtensionContext failed status: %{public}d", status);
        return;
    }

    std::array nativeFuncs = {
        ani_native_function { "nativeTransferStatic", "Lstd/interop/ESValue;Lstd/core/String;:Lstd/core/Object;",
            reinterpret_cast<void*>(EtsAppServiceExtensionContextModule::NativeTransferStatic) },
        ani_native_function { "nativeTransferDynamic", "Lstd/core/Object;:Lstd/interop/ESValue;",
            reinterpret_cast<void*>(EtsAppServiceExtensionContextModule::NativeTransferDynamic) },
    };
    status = aniEnv->Class_BindStaticNativeMethods(appServiceExtensionContextCls, nativeFuncs.data(),
        nativeFuncs.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Class_BindStaticNativeMethods failed status: %{public}d", status);
        return;
    }

    EtsAppServiceExtensionContextModule::RegisterContextObjectCreator();
    TAG_LOGD(AAFwkTag::CONTEXT, "Init AppServiceExtensionContext kit end");
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

    EtsAppServiceExtensionContextModuleInit(aniEnv);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::CONTEXT, "ANI_Constructor finish");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS
