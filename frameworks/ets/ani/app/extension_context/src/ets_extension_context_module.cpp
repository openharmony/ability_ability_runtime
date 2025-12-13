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

#include "ets_extension_context_module.h"

#include <cstdio>
#include <sys/syscall.h>
#include <unistd.h>

#include "ani_base_context.h"
#include "ani_common_util.h"
#include "context_transfer.h"
#include "ets_context_utils.h"
#include "ets_error_utils.h"
#include "ets_extension_context.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "js_extension_context.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *ETS_EXTENSION_CONTEXT_CLASS_NAME = "application.ExtensionContext.ExtensionContext";

std::string GetClassNameByContextType(const std::string &contextType)
{
    std::string className;
    static const std::unordered_map<std::string, std::string> mapping = {
        {"ExtensionContext", "application.ExtensionContext.ExtensionContext"},
        {"UIExtensionContext", "application.UIExtensionContext.UIExtensionContext"},
        {"AutoFillExtensionContext", "application.AutoFillExtensionContext.AutoFillExtensionContext"}
    };
    auto it = mapping.find(contextType);
    if (it != mapping.end()) {
        className = it->second;
    }
    return className;
}
} // namespace

ani_object EtsExtensionContextModule::NativeTransferStatic(ani_env *aniEnv, ani_object, ani_object input,
    ani_object type)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::CONTEXT, "transfer static ExtensionContext");
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

    auto context = reinterpret_cast<std::weak_ptr<ExtensionContext> *>(unwrapResult)->lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null ExtensionContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto extensionContext = Context::ConvertTo<ExtensionContext>(context);
    if (extensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "invalid extensionContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto &bindingObj = extensionContext->GetBindingObject();
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

    auto extensionContextObj = CreateStaticObject(aniEnv, type, context);
    if (extensionContextObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "extensionContextObj invalid");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    return extensionContextObj;
}

ani_object EtsExtensionContextModule::CreateStaticObject(ani_env *aniEnv, ani_object type,
    std::shared_ptr<ExtensionContext> extensionContext)
{
    std::string contextType;
    if (!AppExecFwk::GetStdString(aniEnv, reinterpret_cast<ani_string>(type), contextType)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "GetStdString failed");
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::CONTEXT, "contextType %{public}s", contextType.c_str());

    if (!ContextTransfer::GetInstance().IsStaticCreatorExist(contextType)) {
        std::string className = GetClassNameByContextType(contextType);
        if (!LoadTargetModule(aniEnv, className)) {
            return nullptr;
        }
    }

    auto extensionContextObj = ContextTransfer::GetInstance().GetStaticObject(contextType, aniEnv, extensionContext);
    if (extensionContextObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "extensionContextObj invalid");
        return nullptr;
    }

    return extensionContextObj;
}

bool EtsExtensionContextModule::LoadTargetModule(ani_env *aniEnv, const std::string &className)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    ani_class contextCls = nullptr;
    auto status = aniEnv->FindClass(className.c_str(), &contextCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "FindClass %{public}s failed status: %{public}d", className.c_str(), status);
        return false;
    }

    std::string contextType;
    if (!AppExecFwk::GetStaticFieldString(aniEnv, contextCls, "contextType", contextType)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "get context type failed");
        return false;
    }

    TAG_LOGD(AAFwkTag::CONTEXT, "contextType %{public}s", contextType.c_str());
    return true;
}

std::unique_ptr<NativeReference> EtsExtensionContextModule::CreateNativeReference(napi_env napiEnv,
    std::shared_ptr<ExtensionContext> extensionContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (napiEnv == nullptr || extensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null param");
        return nullptr;
    }

    auto value = CreateJsExtensionContext(napiEnv, extensionContext, extensionContext->GetAbilityInfo());
    auto systemModule = JsRuntime::LoadSystemModuleByEngine(napiEnv, "application.ExtensionContext", &value, 1);
    if (systemModule == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null systemModule");
        return nullptr;
    }

    napi_value object = systemModule->GetNapiValue();
    if (!CheckTypeForNapiValue(napiEnv, object, napi_object)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "check type failed");
        return nullptr;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<ExtensionContext>(extensionContext);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null workContext");
        return nullptr;
    }
    auto status = napi_coerce_to_native_binding_object(napiEnv, object, DetachCallbackFunc, AttachExtensionContext,
        workContext, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "coerce ExtensionContext failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    status = napi_wrap(napiEnv, object, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::CONTEXT, "finalizer for weak_ptr ExtensionContext");
            delete static_cast<std::weak_ptr<ExtensionContext> *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "wrap failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    return systemModule;
}

napi_value EtsExtensionContextModule::GetOrCreateDynamicObject(napi_env napiEnv,
    std::shared_ptr<ExtensionContext> extensionContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (napiEnv == nullptr || extensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null param");
        return nullptr;
    }

    // if sub-thread, create a new extensionContext and return
    if (getpid() != syscall(SYS_gettid)) {
        auto subThreadObj = static_cast<NativeReference *>(
            extensionContext->GetSubThreadObject(static_cast<void *>(napiEnv)));
        if (subThreadObj != nullptr) {
            return subThreadObj->Get();
        }
        auto subThreadRef = CreateNativeReference(napiEnv, extensionContext);
        if (subThreadRef == nullptr) {
            return nullptr;
        }
        auto newObject = subThreadRef->Get();
        extensionContext->BindSubThreadObject(
            static_cast<void *>(napiEnv), static_cast<void *>(subThreadRef.release()));
        return newObject;
    }

    // if main-thread, get bindingObj firstly
    auto &bindingObj = extensionContext->GetBindingObject();
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
    auto nativeRef = CreateNativeReference(napiEnv, extensionContext);
    if (nativeRef == nullptr) {
        return nullptr;
    }

    auto object = nativeRef->Get();
    extensionContext->Bind(nativeRef.release());
    return object;
}

ani_object EtsExtensionContextModule::NativeTransferDynamic(ani_env *aniEnv, ani_class aniCls, ani_object input)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::CONTEXT, "transfer dynamic ExtensionContext");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null aniEnv");
        return nullptr;
    }

    auto context = AbilityRuntime::GetStageModeContext(aniEnv, input);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    std::shared_ptr<ExtensionContext> extensionContext = Context::ConvertTo<ExtensionContext>(context);
    if (extensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "invalid extensionContext");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    ani_object object = CreateDynamicObject(aniEnv, aniCls, extensionContext);
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "invalid object");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    return object;
}

ani_object EtsExtensionContextModule::CreateDynamicObject(ani_env *aniEnv, ani_class aniCls,
    std::shared_ptr<ExtensionContext> extensionContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::string contextType;
    if (!AppExecFwk::GetStaticFieldString(aniEnv, aniCls, "contextType", contextType)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "get context type failed");
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::CONTEXT, "contextType %{public}s", contextType.c_str());

    if (!ContextTransfer::GetInstance().IsDynamicCreatorExist(contextType)) {
        std::string className = GetClassNameByContextType(contextType);
        if (!LoadTargetModule(aniEnv, className)) {
            return nullptr;
        }
    }

    // get napiEnv from aniEnv
    napi_env napiEnv = {};
    if (!arkts_napi_scope_open(aniEnv, &napiEnv)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "arkts_napi_scope_open failed");
        return nullptr;
    }

    // create normal ExtensionContext
    auto contextObj = ContextTransfer::GetInstance().GetDynamicObject(contextType, napiEnv, extensionContext);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "create ExtensionContext failed");
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

void EtsExtensionContextModule::RegisterContextObjectCreator()
{
    ContextTransfer::GetInstance().RegisterStaticObjectCreator("ExtensionContext",
        [](ani_env *aniEnv, std::shared_ptr<Context> context) -> ani_object {
            ani_class cls {};
            ani_status status = ANI_ERROR;
            if ((status = aniEnv->FindClass("application.Context.Context", &cls)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::CONTEXT, "status: %{public}d", status);
                return nullptr;
            }
            auto newContext = ContextUtil::CreateContextObject(aniEnv, cls, context);
            if (newContext == nullptr) {
                TAG_LOGE(AAFwkTag::CONTEXT, "create context failed");
                return nullptr;
            }
            auto extensionContext = Context::ConvertTo<ExtensionContext>(context);
            if (extensionContext == nullptr) {
                TAG_LOGE(AAFwkTag::CONTEXT, "invalid extensionContext");
                return nullptr;
            }
            if ((status = aniEnv->FindClass("application.ExtensionContext.ExtensionContext", &cls)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::CONTEXT, "status: %{public}d", status);
                return nullptr;
            }
            CreateEtsExtensionContext(aniEnv, cls, newContext, extensionContext, extensionContext->GetAbilityInfo());
            ani_ref *contextGlobalRef = new (std::nothrow) ani_ref;
            if (contextGlobalRef == nullptr) {
                TAG_LOGE(AAFwkTag::CONTEXT, "new contextGlobalRef failed");
                return nullptr;
            }
            if ((status = aniEnv->GlobalReference_Create(newContext, contextGlobalRef)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::CONTEXT, "GlobalReference_Create failed status: %{public}d", status);
                delete contextGlobalRef;
                return nullptr;
            }
            extensionContext->Bind(contextGlobalRef);
            return newContext;
    });

    EtsExtensionContextModule::RegisterDynamicContextObjectCreator();
}

void EtsExtensionContextModule::RegisterDynamicContextObjectCreator()
{
    ContextTransfer::GetInstance().RegisterDynamicObjectCreator("ExtensionContext",
        [](napi_env napiEnv, std::shared_ptr<Context> context) -> napi_value {
            auto extensionContext = Context::ConvertTo<ExtensionContext>(context);
            if (extensionContext == nullptr) {
                TAG_LOGE(AAFwkTag::CONTEXT, "invalid extensionContext");
                return nullptr;
            }

            auto object = EtsExtensionContextModule::GetOrCreateDynamicObject(napiEnv, extensionContext);
            if (object == nullptr) {
                TAG_LOGE(AAFwkTag::CONTEXT, "get or create object failed");
                return nullptr;
            }
            return object;
    });
}

napi_value EtsExtensionContextModule::AttachExtensionContext(napi_env env, void *value, void *hint)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "attach extension context");
    if (env == nullptr || value == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "invalid params");
        return nullptr;
    }
    auto ptr = reinterpret_cast<std::weak_ptr<ExtensionContext> *>(value)->lock();
    if (ptr == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null ptr");
        return nullptr;
    }

    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = ptr->GetAbilityInfo();
    auto object = CreateJsExtensionContext(env, ptr, abilityInfo);
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null object");
        return nullptr;
    }
    auto systemModule = JsRuntime::LoadSystemModuleByEngine(env, "application.ExtensionContext", &object, 1);
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
        env, contextObj, DetachCallbackFunc, AttachExtensionContext, value, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "coerce extension context failed: %{public}d", status);
        return nullptr;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<ExtensionContext>(ptr);
    status = napi_wrap(env, contextObj, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::CONTEXT, "finalizer for weak_ptr extension context");
            delete static_cast<std::weak_ptr<ExtensionContext> *>(data);
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "wrap extension context failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    return contextObj;
}

void EtsExtensionContextModuleInit(ani_env *aniEnv)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "Init ExtensionContext kit");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null ani env");
        return;
    }

    ani_class extensionContextCls = nullptr;
    auto status = aniEnv->FindClass(ETS_EXTENSION_CONTEXT_CLASS_NAME, &extensionContextCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "FindClass ExtensionContext failed status: %{public}d", status);
        return;
    }

    std::array nativeFuncs = {
        ani_native_function { "nativeTransferStatic", "C{std.interop.ESValue}C{std.core.String}:C{std.core.Object}",
            reinterpret_cast<void*>(EtsExtensionContextModule::NativeTransferStatic) },
        ani_native_function { "nativeTransferDynamic", "C{std.core.Object}:C{std.interop.ESValue}",
            reinterpret_cast<void*>(EtsExtensionContextModule::NativeTransferDynamic) },
    };
    status = aniEnv->Class_BindStaticNativeMethods(extensionContextCls, nativeFuncs.data(), nativeFuncs.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Class_BindStaticNativeMethods failed status: %{public}d", status);
        return;
    }

    EtsExtensionContextModule::RegisterContextObjectCreator();
    TAG_LOGD(AAFwkTag::CONTEXT, "Init ExtensionContext kit end");
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

    EtsExtensionContextModuleInit(aniEnv);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::CONTEXT, "ANI_Constructor finish");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS
