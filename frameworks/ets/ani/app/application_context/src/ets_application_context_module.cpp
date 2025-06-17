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

#include "ets_application_context_module.h"

#include <cstdio>
#include <sys/syscall.h>
#include <unistd.h>
#include "ani_base_context.h"
#include "application_context_manager.h"
#include "ets_application_context_utils.h"
#include "hilog_tag_wrapper.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "js_application_context_utils.h"
#include "js_context_utils.h"
#include "js_runtime_utils.h"
#include "native_engine/native_engine.h"
#include "sts_error_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *ETS_APPLICATION_CONTEXT_CLASS_NAME = "Lapplication/ApplicationContext/ApplicationContext;";
} // namespace

ani_object EtsApplicationContextModule::NativeTransferStatic(ani_env *aniEnv, ani_object, ani_object input)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "transfer static ApplicationContext");
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
    auto context = reinterpret_cast<std::weak_ptr<ApplicationContext> *>(unwrapResult)->lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null application context");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }

    auto applicationContext = Context::ConvertTo<ApplicationContext>(context);
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null ApplicationContext");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }

    auto &bindingObj = applicationContext->GetBindingObject();
    if (bindingObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null bindingObj");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }

    // get binding obj
    auto staticContext = bindingObj->Get<ani_ref>();
    if (staticContext != nullptr) {
        TAG_LOGI(AAFwkTag::CONTEXT, "got an exist staticContext");
        return reinterpret_cast<ani_object>(*staticContext);
    }

    // create a new one
    EtsApplicationContextUtils::CreateEtsApplicationContext(aniEnv);
    auto appContextObj = ApplicationContextManager::GetApplicationContextManager().GetEtsGlobalObject();
    if (appContextObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "appContextObj is nullptr");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }

    return appContextObj->aniObj;
}

std::unique_ptr<NativeReference> EtsApplicationContextModule::CreateNativeReference(napi_env napiEnv,
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

std::unique_ptr<NativeReference> EtsApplicationContextModule::GetOrCreateNativeReference(napi_env napiEnv,
    std::shared_ptr<ApplicationContext> applicationContext)
{
    if (napiEnv == nullptr || applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null param");
        return nullptr;
    }

    // if sub-thread, create a new applicationContext and return
    if (getpid() != syscall(SYS_gettid)) {
        return CreateNativeReference(napiEnv, applicationContext);
    }

    // if main-thread, get bindingObj firstly
    auto &bindingObj = applicationContext->GetBindingObject();
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

    // if main-thread bindingObj didn't exist, create and bind
    auto nativeRef = CreateNativeReference(napiEnv, applicationContext);
    if (nativeRef == nullptr) {
        return nullptr;
    }

    applicationContext->Bind(nativeRef.get());
    return nativeRef;
}

ani_object EtsApplicationContextModule::NativeTransferDynamic(ani_env *aniEnv, ani_object, ani_object input)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "transfer dynamic ApplicationContext");
    if (!IsInstanceOf(aniEnv, input)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "not AbilityStageContext");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }

    auto context = AbilityRuntime::GetStageModeContext(aniEnv, input);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }

    auto applicationContext = Context::ConvertTo<ApplicationContext>(context);
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "invalid applicationContext");
        ThrowStsTransferClassError(aniEnv);
        return nullptr;
    }

    // Not support yet
    ThrowStsTransferClassError(aniEnv);
    return nullptr;
}

bool EtsApplicationContextModule::IsInstanceOf(ani_env *aniEnv, ani_object aniObj)
{
    ani_class cls {};
    ani_status status = ANI_ERROR;
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null aniEnv");
        return false;
    }
    if ((status = aniEnv->FindClass(ETS_APPLICATION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
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

void EtsApplicationContextModuleInit(ani_env *aniEnv)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "Init application context kit");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null ani env");
        return;
    }

    ani_class applicationContextCls = nullptr;
    auto status = aniEnv->FindClass(ETS_APPLICATION_CONTEXT_CLASS_NAME, &applicationContextCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "FindClass ApplicationContext failed status: %{public}d", status);
        return;
    }

    std::array nativeFuncs = {
        ani_native_function { "nativeTransferStatic", "Lstd/interop/ESValue;:Lstd/core/Object;",
            reinterpret_cast<void*>(EtsApplicationContextModule::NativeTransferStatic) },
        ani_native_function { "nativeTransferDynamic", "Lstd/core/Object;:Lstd/interop/ESValue;",
            reinterpret_cast<void*>(EtsApplicationContextModule::NativeTransferDynamic) },
    };
    status = aniEnv->Class_BindNativeMethods(applicationContextCls, nativeFuncs.data(), nativeFuncs.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Class_BindNativeMethods failed status: %{public}d", status);
        return;
    }

    TAG_LOGD(AAFwkTag::CONTEXT, "Init application context kit end");
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

    EtsApplicationContextModuleInit(aniEnv);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::CONTEXT, "ANI_Constructor finish");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS
