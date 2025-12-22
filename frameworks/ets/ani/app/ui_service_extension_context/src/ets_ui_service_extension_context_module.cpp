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

#include "ets_ui_service_extension_context_module.h"

#include <cstdio>
#include <sys/syscall.h>
#include <unistd.h>

#include "ani_base_context.h"
#include "ani_common_util.h"
#include "context_transfer.h"
#include "ets_error_utils.h"
#include "ets_ui_service_extension_context.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "js_runtime_utils.h"
#include "js_ui_service_extension_context.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *UI_SERVICE_EXTENSION_CONTEXT_CLASS_NAME =
    "application.UIServiceExtensionContext.UIServiceExtensionContext";
} // namespace

ani_object EtsUiServiceExtensionContextModule::NativeTransferStatic(
    ani_env *aniEnv, ani_object, ani_object input, ani_object type)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UISERVC_EXT, "transfer static UIServiceExtensionContext");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "null aniEnv");
        return nullptr;
    }

    void *unwrapResult = nullptr;
    bool success = arkts_esvalue_unwrap(aniEnv, input, &unwrapResult);
    if (!success) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "failed to unwrap");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }
    if (unwrapResult == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "null unwrapResult");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto context = reinterpret_cast<std::weak_ptr<UIServiceExtensionContext> *>(unwrapResult)->lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "null UIServiceExtensionContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto uiServiceExtContext = Context::ConvertTo<UIServiceExtensionContext>(context);
    if (uiServiceExtContext == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "invalid uiServiceExtContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto &bindingObj = uiServiceExtContext->GetBindingObject();
    if (bindingObj == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "null bindingObj");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto staticContext = bindingObj->Get<ani_ref>();
    if (staticContext != nullptr) {
        TAG_LOGI(AAFwkTag::UISERVC_EXT, "there exist a staticContext");
        return reinterpret_cast<ani_object>(*staticContext);
    }

    // if not exist, create a new one
    std::string contextType;
    if (!AppExecFwk::GetStdString(aniEnv, reinterpret_cast<ani_string>(type), contextType)) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "GetStdString failed");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::UISERVC_EXT, "contextType %{public}s", contextType.c_str());

    auto newContext = ContextTransfer::GetInstance().GetStaticObject(contextType, aniEnv, context);
    if (newContext == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "create uiServiceExtContext failed");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    return newContext;
}

napi_value AttachUIServiceExtensionContext(napi_env env, void *value, void *)
{
    if (value == nullptr) {
        TAG_LOGW(AAFwkTag::UISERVC_EXT, "null value");
        return nullptr;
    }
    auto ptr = reinterpret_cast<std::weak_ptr<AbilityRuntime::UIServiceExtensionContext> *>(value)->lock();
    if (ptr == nullptr) {
        TAG_LOGW(AAFwkTag::UISERVC_EXT, "null ptr");
        return nullptr;
    }
    napi_value object = AbilityRuntime::CreateJsUIServiceExtensionContext(env, ptr);
    auto sysModule =
        AbilityRuntime::JsRuntime::LoadSystemModuleByEngine(env, "application.UIServiceExtensionContext", &object, 1);
    if (sysModule == nullptr) {
        TAG_LOGW(AAFwkTag::UISERVC_EXT, "null sysModule");
        return nullptr;
    }
    auto contextObj = sysModule->GetNapiValue();
    napi_coerce_to_native_binding_object(
        env, contextObj, AbilityRuntime::DetachCallbackFunc, AttachUIServiceExtensionContext, value, nullptr);
    auto workContext = new (std::nothrow) std::weak_ptr<AbilityRuntime::UIServiceExtensionContext>(ptr);
    napi_wrap(env, contextObj, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::UISERVC_EXT, "Finalizer for weak_ptr service extension context is called");
            delete static_cast<std::weak_ptr<AbilityRuntime::UIServiceExtensionContext> *>(data);
        },
        nullptr, nullptr);
    return contextObj;
}

std::unique_ptr<NativeReference> EtsUiServiceExtensionContextModule::CreateNativeReference(
    napi_env napiEnv, std::shared_ptr<UIServiceExtensionContext> uiServiceExtContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (napiEnv == nullptr || uiServiceExtContext == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "null param");
        return nullptr;
    }

    auto value = CreateJsUIServiceExtensionContext(napiEnv, uiServiceExtContext);
    auto systemModule =
        JsRuntime::LoadSystemModuleByEngine(napiEnv, "application.UIServiceExtensionContext", &value, 1);
    if (systemModule == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "null systemModule");
        return nullptr;
    }

    napi_value object = systemModule->GetNapiValue();
    if (!CheckTypeForNapiValue(napiEnv, object, napi_object)) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "check type failed");
        return nullptr;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<UIServiceExtensionContext>(uiServiceExtContext);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "null workContext");
        return nullptr;
    }
    auto status = napi_coerce_to_native_binding_object(
        napiEnv, object, DetachCallbackFunc, AttachUIServiceExtensionContext, workContext, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "coerce UIServiceExtensionContext failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    status = napi_wrap(napiEnv, object, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::UISERVC_EXT, "finalizer for weak_ptr UIServiceExtensionContext");
            delete static_cast<std::weak_ptr<UIServiceExtensionContext> *>(data);
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "wrap failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    return systemModule;
}

napi_value EtsUiServiceExtensionContextModule::GetOrCreateDynamicObject(
    napi_env napiEnv, std::shared_ptr<UIServiceExtensionContext> uiServiceExtContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (napiEnv == nullptr || uiServiceExtContext == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "null param");
        return nullptr;
    }

    // if sub-thread, create a new uiServiceExtContext and return
    if (getpid() != syscall(SYS_gettid)) {
        auto subThreadObj =
            static_cast<NativeReference *>(uiServiceExtContext->GetSubThreadObject(static_cast<void *>(napiEnv)));
        if (subThreadObj != nullptr) {
            return subThreadObj->Get();
        }
        auto subThreadRef = CreateNativeReference(napiEnv, uiServiceExtContext);
        if (subThreadRef == nullptr) {
            return nullptr;
        }
        auto newObject = subThreadRef->Get();
        uiServiceExtContext->BindSubThreadObject(
            static_cast<void *>(napiEnv), static_cast<void *>(subThreadRef.release()));
        return newObject;
    }

    // if main-thread, get bindingObj firstly
    auto &bindingObj = uiServiceExtContext->GetBindingObject();
    if (bindingObj == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "null bindingObj");
        return nullptr;
    }

    // if main-thread bindingObj exist, return it directly
    auto dynamicContext = bindingObj->Get<NativeReference>();
    if (dynamicContext != nullptr) {
        TAG_LOGI(AAFwkTag::UISERVC_EXT, "there exist a dynamicContext");
        return dynamicContext->Get();
    }

    // if main-thread bindingObj didn't exist, create and bind
    auto nativeRef = CreateNativeReference(napiEnv, uiServiceExtContext);
    if (nativeRef == nullptr) {
        return nullptr;
    }

    auto object = nativeRef->Get();
    uiServiceExtContext->Bind(nativeRef.release());
    return object;
}

ani_object EtsUiServiceExtensionContextModule::NativeTransferDynamic(
    ani_env *aniEnv, ani_class aniCls, ani_object input)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UISERVC_EXT, "transfer dynamic UIServiceExtensionContext");
    if (!IsInstanceOf(aniEnv, input)) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "not UIServiceExtensionContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto context = AbilityRuntime::GetStageModeContext(aniEnv, input);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "null context");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    std::shared_ptr<UIServiceExtensionContext> uiServiceExtContext =
        Context::ConvertTo<UIServiceExtensionContext>(context);
    if (uiServiceExtContext == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "invalid uiServiceExtContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    ani_object object = CreateDynamicObject(aniEnv, aniCls, uiServiceExtContext);
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "invalid object");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    return object;
}

ani_object EtsUiServiceExtensionContextModule::CreateDynamicObject(
    ani_env *aniEnv, ani_class aniCls, std::shared_ptr<UIServiceExtensionContext> uiServiceExtContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::string contextType;
    if (!AppExecFwk::GetStaticFieldString(aniEnv, aniCls, "contextType", contextType)) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "get context type failed");
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::UISERVC_EXT, "contextType %{public}s", contextType.c_str());

    // get napiEnv from aniEnv
    napi_env napiEnv = {};
    if (!arkts_napi_scope_open(aniEnv, &napiEnv)) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "arkts_napi_scope_open failed");
        return nullptr;
    }

    // create normal ability context
    auto contextObj = ContextTransfer::GetInstance().GetDynamicObject(contextType, napiEnv, uiServiceExtContext);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "create UIServiceExtensionContext failed");
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    hybridgref ref = nullptr;
    bool success = hybridgref_create_from_napi(napiEnv, contextObj, &ref);
    if (!success) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "hybridgref_create_from_napi failed");
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    ani_object result = nullptr;
    success = hybridgref_get_esvalue(aniEnv, ref, &result);
    if (!success) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "hybridgref_get_esvalue failed");
        hybridgref_delete_from_napi(napiEnv, ref);
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    hybridgref_delete_from_napi(napiEnv, ref);

    if (!arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr)) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "arkts_napi_scope_close_n failed");
        return nullptr;
    }

    return result;
}

bool EtsUiServiceExtensionContextModule::IsInstanceOf(ani_env *aniEnv, ani_object aniObj)
{
    ani_class cls {};
    ani_status status = ANI_ERROR;
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "null aniEnv");
        return false;
    }
    if ((status = aniEnv->FindClass(UI_SERVICE_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "FindClass status: %{public}d", status);
        return false;
    }
    ani_boolean isInstanceOf = false;
    if ((status = aniEnv->Object_InstanceOf(aniObj, cls, &isInstanceOf)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "Object_InstanceOf status: %{public}d", status);
        return false;
    }
    return isInstanceOf;
}

void EtsUIServiceExtensionContextModuleInit(ani_env *aniEnv)
{
    TAG_LOGD(AAFwkTag::UISERVC_EXT, "Init UIServiceExtensionContext kit");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "null ani env");
        return;
    }

    ani_class uiServiceExtContextCls = nullptr;
    auto status = aniEnv->FindClass(UI_SERVICE_EXTENSION_CONTEXT_CLASS_NAME, &uiServiceExtContextCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "FindClass UIServiceExtensionContext failed status: %{public}d", status);
        return;
    }

    std::array nativeFuncs = {
        ani_native_function { "nativeTransferStatic", "C{std.interop.ESValue}C{std.core.String}:C{std.core.Object}",
            reinterpret_cast<void *>(EtsUiServiceExtensionContextModule::NativeTransferStatic) },
        ani_native_function { "nativeTransferDynamic", "C{std.core.Object}:C{std.interop.ESValue}",
            reinterpret_cast<void *>(EtsUiServiceExtensionContextModule::NativeTransferDynamic) },
    };
    status = aniEnv->Class_BindStaticNativeMethods(uiServiceExtContextCls, nativeFuncs.data(), nativeFuncs.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "Class_BindStaticNativeMethods failed status: %{public}d", status);
        return;
    }

    ContextTransfer::GetInstance().RegisterStaticObjectCreator("UIServiceExtensionContext",
        [](ani_env *aniEnv, std::shared_ptr<Context> context) -> ani_object {
            auto uiServiceExtContext = Context::ConvertTo<UIServiceExtensionContext>(context);
            if (uiServiceExtContext == nullptr) {
                TAG_LOGE(AAFwkTag::UISERVC_EXT, "invalid uiServiceExtContext");
                return nullptr;
            }
            auto newContext = CreateEtsUIServiceExtensionContext(aniEnv, uiServiceExtContext);
            if (newContext == nullptr) {
                TAG_LOGE(AAFwkTag::UISERVC_EXT, "create uiServiceExtContext failed");
                return nullptr;
            }
            return newContext;
        });

    ContextTransfer::GetInstance().RegisterDynamicObjectCreator("UIServiceExtensionContext",
        [](napi_env napiEnv, std::shared_ptr<Context> context) -> napi_value {
            auto uiServiceExtContext = Context::ConvertTo<UIServiceExtensionContext>(context);
            if (uiServiceExtContext == nullptr) {
                TAG_LOGE(AAFwkTag::UISERVC_EXT, "invalid uiServiceExtContext");
                return nullptr;
            }

            auto object = EtsUiServiceExtensionContextModule::GetOrCreateDynamicObject(napiEnv, uiServiceExtContext);
            if (object == nullptr) {
                TAG_LOGE(AAFwkTag::UISERVC_EXT, "get or create object failed");
                return nullptr;
            }
            return object;
        });

    TAG_LOGD(AAFwkTag::UISERVC_EXT, "Init UIServiceExtensionContext kit end");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::UISERVC_EXT, "ANI_Constructor");
    if (vm == nullptr) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "null vm");
        return ANI_ERROR;
    }

    ani_env *aniEnv = nullptr;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &aniEnv);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UISERVC_EXT, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    }

    EtsUIServiceExtensionContextModuleInit(aniEnv);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::UISERVC_EXT, "ANI_Constructor finish");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS