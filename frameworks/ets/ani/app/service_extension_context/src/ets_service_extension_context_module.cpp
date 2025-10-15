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

#include "ets_service_extension_context_module.h"

#include <cstdio>
#include <sys/syscall.h>
#include <unistd.h>

#include "ani_base_context.h"
#include "ani_common_util.h"
#include "context_transfer.h"
#include "ets_error_utils.h"
#include "ets_service_extension_context.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "js_runtime_utils.h"
#include "js_service_extension_context.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *SERVICE_EXTENSION_CONTEXT_CLASS_NAME =
    "Lapplication/ServiceExtensionContext/ServiceExtensionContext;";
} // namespace

ani_object EtsServiceExtensionContextModule::NativeTransferStatic(
    ani_env *aniEnv, ani_object, ani_object input, ani_object type)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "transfer static ServiceExtensionContext");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null aniEnv");
        return nullptr;
    }

    void *unwrapResult = nullptr;
    bool success = arkts_esvalue_unwrap(aniEnv, input, &unwrapResult);
    if (!success) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "failed to unwrap");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }
    if (unwrapResult == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null unwrapResult");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto context = reinterpret_cast<std::weak_ptr<ServiceExtensionContext> *>(unwrapResult)->lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null ServiceExtensionContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto serviceExtContext = Context::ConvertTo<ServiceExtensionContext>(context);
    if (serviceExtContext == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid serviceExtContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto &bindingObj = serviceExtContext->GetBindingObject();
    if (bindingObj == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null bindingObj");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto staticContext = bindingObj->Get<ani_ref>();
    if (staticContext != nullptr) {
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "there exist a staticContext");
        return reinterpret_cast<ani_object>(*staticContext);
    }

    // if not exist, create a new one
    std::string contextType;
    if (!AppExecFwk::GetStdString(aniEnv, reinterpret_cast<ani_string>(type), contextType)) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "GetStdString failed");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "contextType %{public}s", contextType.c_str());

    auto newContext = ContextTransfer::GetInstance().GetStaticObject(contextType, aniEnv, context);
    if (newContext == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "create serviceExtContext failed");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    return newContext;
}

napi_value AttachServiceExtensionContext(napi_env env, void *value, void *)
{
    if (value == nullptr) {
        TAG_LOGW(AAFwkTag::SERVICE_EXT, "null value");
        return nullptr;
    }
    auto ptr = reinterpret_cast<std::weak_ptr<ServiceExtensionContext> *>(value)->lock();
    if (ptr == nullptr) {
        TAG_LOGW(AAFwkTag::SERVICE_EXT, "null ptr");
        return nullptr;
    }
    napi_value object = CreateJsServiceExtensionContext(env, ptr);
    auto sysModule = JsRuntime::LoadSystemModuleByEngine(env, "application.ServiceExtensionContext", &object, 1);
    if (sysModule == nullptr) {
        TAG_LOGW(AAFwkTag::SERVICE_EXT, "null sysModule");
        return nullptr;
    }
    auto contextObj = sysModule->GetNapiValue();
    napi_coerce_to_native_binding_object(
        env, contextObj, DetachCallbackFunc, AttachServiceExtensionContext, value, nullptr);
    auto workContext = new (std::nothrow) std::weak_ptr<ServiceExtensionContext>(ptr);
    auto res = napi_wrap(env, contextObj, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "Finalizer for weak_ptr service extension context is called");
            delete static_cast<std::weak_ptr<ServiceExtensionContext> *>(data);
        },
        nullptr, nullptr);
    if (res != napi_ok && workContext != nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "napi_wrap failed:%{public}d", res);
        delete workContext;
        return nullptr;
    }
    return contextObj;
}

std::unique_ptr<NativeReference> EtsServiceExtensionContextModule::CreateNativeReference(
    napi_env napiEnv, std::shared_ptr<ServiceExtensionContext> serviceExtContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (napiEnv == nullptr || serviceExtContext == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null param");
        return nullptr;
    }

    auto value = CreateJsServiceExtensionContext(napiEnv, serviceExtContext);
    auto systemModule = JsRuntime::LoadSystemModuleByEngine(napiEnv, "application.ServiceExtensionContext", &value, 1);
    if (systemModule == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null systemModule");
        return nullptr;
    }

    napi_value object = systemModule->GetNapiValue();
    if (!CheckTypeForNapiValue(napiEnv, object, napi_object)) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "check type failed");
        return nullptr;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<ServiceExtensionContext>(serviceExtContext);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null workContext");
        return nullptr;
    }
    auto status = napi_coerce_to_native_binding_object(
        napiEnv, object, DetachCallbackFunc, AttachServiceExtensionContext, workContext, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "coerce ServiceExtensionContext failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    status = napi_wrap(
        napiEnv, object, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "finalizer for weak_ptr ServiceExtensionContext");
            delete static_cast<std::weak_ptr<ServiceExtensionContext> *>(data);
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "wrap failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    return systemModule;
}

napi_value EtsServiceExtensionContextModule::GetOrCreateDynamicObject(
    napi_env napiEnv, std::shared_ptr<ServiceExtensionContext> serviceExtContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (napiEnv == nullptr || serviceExtContext == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null param");
        return nullptr;
    }

    // if sub-thread, create a new serviceExtContext and return
    if (getpid() != syscall(SYS_gettid)) {
        auto subThreadObj =
            static_cast<NativeReference *>(serviceExtContext->GetSubThreadObject(static_cast<void *>(napiEnv)));
        if (subThreadObj != nullptr) {
            return subThreadObj->Get();
        }
        auto subThreadRef = CreateNativeReference(napiEnv, serviceExtContext);
        if (subThreadRef == nullptr) {
            return nullptr;
        }
        auto newObject = subThreadRef->Get();
        serviceExtContext->BindSubThreadObject(
            static_cast<void *>(napiEnv), static_cast<void *>(subThreadRef.release()));
        return newObject;
    }

    // if main-thread, get bindingObj firstly
    auto &bindingObj = serviceExtContext->GetBindingObject();
    if (bindingObj == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null bindingObj");
        return nullptr;
    }

    // if main-thread bindingObj exist, return it directly
    auto dynamicContext = bindingObj->Get<NativeReference>();
    if (dynamicContext != nullptr) {
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "there exist a dynamicContext");
        return dynamicContext->Get();
    }

    // if main-thread bindingObj didn't exist, create and bind
    auto nativeRef = CreateNativeReference(napiEnv, serviceExtContext);
    if (nativeRef == nullptr) {
        return nullptr;
    }

    auto object = nativeRef->Get();
    serviceExtContext->Bind(nativeRef.release());
    return object;
}

ani_object EtsServiceExtensionContextModule::NativeTransferDynamic(ani_env *aniEnv, ani_class aniCls, ani_object input)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "transfer dynamic ServiceExtensionContext");
    if (!IsInstanceOf(aniEnv, input)) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "not ServiceExtensionContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto context = AbilityRuntime::GetStageModeContext(aniEnv, input);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null context");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    std::shared_ptr<ServiceExtensionContext> serviceExtContext = Context::ConvertTo<ServiceExtensionContext>(context);
    if (serviceExtContext == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid serviceExtContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    ani_object object = CreateDynamicObject(aniEnv, aniCls, serviceExtContext);
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid object");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    return object;
}

ani_object EtsServiceExtensionContextModule::CreateDynamicObject(
    ani_env *aniEnv, ani_class aniCls, std::shared_ptr<ServiceExtensionContext> serviceExtContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::string contextType;
    if (!AppExecFwk::GetStaticFieldString(aniEnv, aniCls, "contextType", contextType)) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "get context type failed");
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "contextType %{public}s", contextType.c_str());

    // get napiEnv from aniEnv
    napi_env napiEnv = {};
    if (!arkts_napi_scope_open(aniEnv, &napiEnv)) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "arkts_napi_scope_open failed");
        return nullptr;
    }

    // create normal ability context
    auto contextObj = ContextTransfer::GetInstance().GetDynamicObject(contextType, napiEnv, serviceExtContext);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "create ServiceExtensionContext failed");
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    hybridgref ref = nullptr;
    bool success = hybridgref_create_from_napi(napiEnv, contextObj, &ref);
    if (!success) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "hybridgref_create_from_napi failed");
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    ani_object result = nullptr;
    success = hybridgref_get_esvalue(aniEnv, ref, &result);
    if (!success) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "hybridgref_get_esvalue failed");
        hybridgref_delete_from_napi(napiEnv, ref);
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    hybridgref_delete_from_napi(napiEnv, ref);

    if (!arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr)) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "arkts_napi_scope_close_n failed");
        return nullptr;
    }

    return result;
}

bool EtsServiceExtensionContextModule::IsInstanceOf(ani_env *aniEnv, ani_object aniObj)
{
    ani_class cls {};
    ani_status status = ANI_ERROR;
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null aniEnv");
        return false;
    }
    if ((status = aniEnv->FindClass(SERVICE_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "FindClass status: %{public}d", status);
        return false;
    }
    ani_boolean isInstanceOf = false;
    if ((status = aniEnv->Object_InstanceOf(aniObj, cls, &isInstanceOf)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "Object_InstanceOf status: %{public}d", status);
        return false;
    }
    return isInstanceOf;
}

void EtsServiceExtensionContextModuleInit(ani_env *aniEnv)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "Init ServiceExtensionContext kit");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null ani env");
        return;
    }

    ani_class serviceExtContextCls = nullptr;
    auto status = aniEnv->FindClass(SERVICE_EXTENSION_CONTEXT_CLASS_NAME, &serviceExtContextCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "FindClass ServiceExtensionContext failed status: %{public}d", status);
        return;
    }

    std::array nativeFuncs = {
        ani_native_function { "nativeTransferStatic", "Lstd/interop/ESValue;Lstd/core/String;:Lstd/core/Object;",
            reinterpret_cast<void *>(EtsServiceExtensionContextModule::NativeTransferStatic) },
        ani_native_function { "nativeTransferDynamic", "Lstd/core/Object;:Lstd/interop/ESValue;",
            reinterpret_cast<void *>(EtsServiceExtensionContextModule::NativeTransferDynamic) },
    };
    status = aniEnv->Class_BindStaticNativeMethods(serviceExtContextCls, nativeFuncs.data(), nativeFuncs.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "Class_BindStaticNativeMethods failed status: %{public}d", status);
        return;
    }

    ContextTransfer::GetInstance().RegisterStaticObjectCreator("ServiceExtensionContext",
        [](ani_env *aniEnv, std::shared_ptr<Context> context) -> ani_object {
            auto serviceExtContext = Context::ConvertTo<ServiceExtensionContext>(context);
            if (serviceExtContext == nullptr) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid serviceExtContext");
                return nullptr;
            }
            auto newContext = CreateEtsServiceExtensionContext(aniEnv, serviceExtContext);
            if (newContext == nullptr) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "create serviceExtContext failed");
                return nullptr;
            }
            return newContext;
        });

    ContextTransfer::GetInstance().RegisterDynamicObjectCreator("ServiceExtensionContext",
        [](napi_env napiEnv, std::shared_ptr<Context> context) -> napi_value {
            auto serviceExtContext = Context::ConvertTo<ServiceExtensionContext>(context);
            if (serviceExtContext == nullptr) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid serviceExtContext");
                return nullptr;
            }

            auto object = EtsServiceExtensionContextModule::GetOrCreateDynamicObject(napiEnv, serviceExtContext);
            if (object == nullptr) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "get or create object failed");
                return nullptr;
            }
            return object;
        });

    TAG_LOGD(AAFwkTag::SERVICE_EXT, "Init ServiceExtensionContext kit end");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "ANI_Constructor");
    if (vm == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null vm");
        return ANI_ERROR;
    }

    ani_env *aniEnv = nullptr;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &aniEnv);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    }

    EtsServiceExtensionContextModuleInit(aniEnv);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "ANI_Constructor finish");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS
