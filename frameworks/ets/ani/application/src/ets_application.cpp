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
#include "ets_application.h"

#include "ani_base_context.h"
#include "ani_common_util.h"
#include "application_context.h"
#include "application_context_manager.h"
#include "context_impl.h"
#include "ets_application_context_utils.h"
#include "ets_context_utils.h"
#include "ets_error_utils.h"
#include "ets_native_reference.h"
#include "hilog_tag_wrapper.h"
#include "permission_verification.h"
#include "application_env.h"
#include "ani_enum_convert.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* PERMISSION_GET_BUNDLE_INFO = "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
constexpr const char* CONTEXT_CLASS_NAME = "Lapplication/Context/Context;";
constexpr const char* APPLICATION_SPACE_NAME = "L@ohos/app/ability/application/application;";
constexpr const char* APP_PRELOAD_TYPE_NAME = "L@ohos/app/ability/application/application/AppPreloadType;";
}

ani_object CreateEmptyContextObject(ani_env *env)
{
    ani_class cls = nullptr;
    ani_status status = env->FindClass(CONTEXT_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "find Context failed status: %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    status = env->Class_FindMethod(cls, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod ctor failed status: %{public}d", status);
        return nullptr;
    }
    ani_object objValue = nullptr;
    if (env->Object_New(cls, method, &objValue) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_New failed status: %{public}d", status);
        return nullptr;
    }
    return objValue;
}

bool CheckIsSystemAppOrPermisson(ani_env *env, ani_object callback)
{
    auto emptyObject = CreateEmptyContextObject(env);
    if (!AAFwk::PermissionVerification::GetInstance()->IsSystemAppCall()) {
        TAG_LOGE(AAFwkTag::APPKIT, "no system app");
            AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateError(env,
            static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP),
                "The application is not system-app, can not use system-api."), emptyObject);
        return false;
    }
    if (!AAFwk::PermissionVerification::GetInstance()->VerifyGetBundleInfoPrivilegedPermission()) {
        TAG_LOGE(AAFwkTag::APPKIT, "no permission");
        AppExecFwk::AsyncCallback(env, callback,
            EtsErrorUtil::CreateNoPermissionError(env, PERMISSION_GET_BUNDLE_INFO), emptyObject);
        return false;
    }
    return true;
}

bool SetNativeContextLong(ani_env *env, std::shared_ptr<Context> context, ani_class& cls, ani_object& contextObj)
{
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env or context is null");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_method method {};
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return false;
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return false;
    }
    ani_field field = nullptr;
    if ((status = env->Class_FindField(cls, "nativeContext", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return false;
    }
    auto workContext = new (std::nothrow) std::weak_ptr<Context>(context);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "workContext nullptr");
        return false;
    }
    ani_long nativeContextLong = reinterpret_cast<ani_long>(workContext);
    if (!ContextUtil::SetNativeContextLong(env, contextObj, nativeContextLong)) {
        TAG_LOGE(AAFwkTag::APPKIT, "SetNativeContextLong failed");
        delete workContext;
        workContext = nullptr;
        return false;
    }
    return true;
}

void SetCreateCompleteCallback(ani_env *env, std::shared_ptr<std::shared_ptr<Context>> contextPtr, ani_object callback)
{
    if (env == nullptr || contextPtr == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env or contextPtr is nullptr");
        return;
    }
    auto context = *contextPtr;
    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed to create context");
        auto emptyObject = CreateEmptyContextObject(env);
        AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateError(env,
            AbilityErrorCode::ERROR_CODE_INVALID_PARAM), emptyObject);
        return;
    }
    ani_class cls {};
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return;
    }
    ani_object contextObj = nullptr;
    if (!SetNativeContextLong(env, context, cls, contextObj)) {
        TAG_LOGE(AAFwkTag::APPKIT, "set nativeContextLong failed");
        return;
    }
    ContextUtil::CreateEtsBaseContext(env, cls, contextObj, context);
    AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), contextObj);
}

std::shared_ptr<Context> GetContextByStageMode(ani_env *env, ani_object &contextObj,
    ani_object callback, ani_object emptyObject)
{
    ani_boolean stageMode = false;
    ani_status status = IsStageContext(env, contextObj, stageMode);
    if (status != ANI_OK || !stageMode) {
        TAG_LOGE(AAFwkTag::APPKIT, "not stageMode");
        AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateInvalidParamError(env,
            "Parse param context failed, must be a context of stageMode."), emptyObject);
        return nullptr;
    }
    auto context = GetStageModeContext(env, contextObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateInvalidParamError(env,
            "Parse param context failed, must not be nullptr."), emptyObject);
        return nullptr;
    }
    return context;
}

void EtsApplication::CreateModuleContext(ani_env *env,
    ani_object contextObj, ani_string bundleName, ani_string moduleName, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "CreateModuleContext Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    ani_object emptyObject = CreateEmptyContextObject(env);
    std::string stdBundleName = "";
    std::string stdModuleName = "";
    AppExecFwk::GetStdString(env, bundleName, stdBundleName);
    AppExecFwk::GetStdString(env, moduleName, stdModuleName);
    auto context = GetContextByStageMode(env, contextObj, callback, emptyObject);
    if (context == nullptr) {
        return;
    }
    auto inputContextPtr = Context::ConvertTo<Context>(context);
    if (inputContextPtr == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "Convert to context failed");
        AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateInvalidParamError(env,
            "Parse param context failed, must be a context."), emptyObject);
        return;
    }
    std::shared_ptr<std::shared_ptr<Context>> moduleContext = std::make_shared<std::shared_ptr<Context>>();
    std::shared_ptr<ContextImpl> contextImpl = std::make_shared<ContextImpl>();
    if (contextImpl == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null contextImpl");
        AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateInvalidParamError(env,
            "create context failed."), emptyObject);
        return;
    }
    contextImpl->SetProcessName(context->GetProcessName());
    if (stdBundleName.empty()) {
        *moduleContext = contextImpl->CreateModuleContext(stdModuleName, inputContextPtr);
    } else {
        if (!CheckIsSystemAppOrPermisson(env, callback)) {
            TAG_LOGE(AAFwkTag::APPKIT, "CheckCaller failed");
        }
        *moduleContext = contextImpl->CreateModuleContext(stdBundleName, stdModuleName, inputContextPtr);
    }
    SetCreateCompleteCallback(env, moduleContext, callback);
}

void EtsApplication::CreateBundleContext(ani_env *env,
    ani_object contextObj, ani_string bundleName, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "CreateBundleContext Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    ani_object emptyObject = CreateEmptyContextObject(env);
    if (!CheckIsSystemAppOrPermisson(env, callback)) {
        TAG_LOGE(AAFwkTag::APPKIT, "CheckCaller failed");
        return;
    }
    std::string stdBundleName = "";
    AppExecFwk::GetStdString(env, bundleName, stdBundleName);
    auto context = GetContextByStageMode(env, contextObj, callback, emptyObject);
    if (context == nullptr) {
        return;
    }
    auto inputContextPtr = Context::ConvertTo<Context>(context);
    if (inputContextPtr == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "Convert to context failed");
        AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateInvalidParamError(env,
            "Parse param context failed, must be a context."), emptyObject);
        return;
    }
    auto bundleContext = std::make_shared<std::shared_ptr<Context>>();
    std::shared_ptr<ContextImpl> contextImpl = std::make_shared<ContextImpl>();
    if (contextImpl == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null contextImpl");
        AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateInvalidParamError(env,
            "create context failed."), emptyObject);
        return;
    }
    contextImpl->SetProcessName(context->GetProcessName());
    contextImpl->CreateBundleContext(*bundleContext, stdBundleName, inputContextPtr);
    SetCreateCompleteCallback(env, bundleContext, callback);
}

ani_object GetApplicationContextInstance(ani_env *env)
{
    TAG_LOGD(AAFwkTag::APPKIT, "GetApplicationContextInstance Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    auto etsReference =
        AbilityRuntime::ApplicationContextManager::GetApplicationContextManager().GetEtsGlobalObject();
    if (etsReference == nullptr || etsReference->aniRef == nullptr) {
        auto applicationContext = ApplicationContext::GetInstance();
        ani_object applicationContextObject =
            EtsApplicationContextUtils::CreateEtsApplicationContext(env, applicationContext);
        if (applicationContextObject == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null applicationContextObject");
            AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
            ani_ref result = nullptr;
            env->GetNull(&result);
            return static_cast<ani_object>(result);
        }
        return applicationContextObject;
    }
    return reinterpret_cast<ani_object>(etsReference->aniRef);
}

ani_object EtsApplication::GetApplicationContext(ani_env *env)
{
    TAG_LOGD(AAFwkTag::APPKIT, "GetApplicationContext Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }

    auto applicationContext = ApplicationContext::GetInstance();
    ani_object applicationContextObject =
        EtsApplicationContextUtils::CreateEtsApplicationContext(env, applicationContext);
    if (applicationContextObject == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null applicationContextObject");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        ani_ref result = nullptr;
        env->GetNull(&result);
        return static_cast<ani_object>(result);
    }
    return applicationContextObject;
}

ani_enum_item EtsApplication::GetAppPreloadType(ani_env *env)
{
    TAG_LOGD(AAFwkTag::APPKIT, "GetAppPreloadType Call");
    ani_enum_item appPreloadTypeItem = nullptr;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return appPreloadTypeItem;
    }
    auto appPreload = GetAppPreload();
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToEts(
        env, APP_PRELOAD_TYPE_NAME, appPreload, appPreloadTypeItem);
    return appPreloadTypeItem;
}

void ApplicationInit(ani_env *env)
{
    TAG_LOGD(AAFwkTag::APPKIT, "ApplicationInit Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_namespace ns;
    status = env->FindNamespace(APPLICATION_SPACE_NAME, &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindNamespace application failed status: %{public}d", status);
        return;
    }
    std::array methods = {
        ani_native_function {
            "nativeCreateModuleContext",
            "Lapplication/Context/Context;Lstd/core/String;Lstd/core/String;"
            "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsApplication::CreateModuleContext)
        },
        ani_native_function {
            "nativeCreateBundleContext",
            "Lapplication/Context/Context;Lstd/core/String;"
            "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsApplication::CreateBundleContext)
        },
        ani_native_function {
            "nativeGetApplicationContext",
            ":Lapplication/ApplicationContext/ApplicationContext;",
            reinterpret_cast<void *>(EtsApplication::GetApplicationContext)
        },
        ani_native_function {
            "nativeGetAppPreloadType",
            ":L@ohos/app/ability/application/application/AppPreloadType;",
            reinterpret_cast<void *>(EtsApplication::GetAppPreloadType)
        },
    };
    status = env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Namespace_BindNativeFunctions failed status: %{public}d", status);
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::APPKIT, "in ApplicationETS.ANI_Constructor");
    if (vm == nullptr || result == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null vm or result");
        return ANI_INVALID_ARGS;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed, status: %{public}d", status);
        return ANI_NOT_FOUND;
    }
    ApplicationInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::APPKIT, "AbilityManagerEts.ANI_Constructor finished");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS