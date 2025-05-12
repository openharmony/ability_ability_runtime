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
#include "sts_error_utils.h"
#include "ani_base_context.h"
#include "ani_common_util.h"
#include "sts_context_utils.h"
#include "application_context.h"
#include "context_impl.h"

namespace OHOS {
namespace AbilityRuntime {
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
        ThrowStsInvalidParamError(env, "find method failed.");
        return false;
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        ThrowStsInvalidParamError(env, "new object failed.");
        return false;
    }
    ani_field field = nullptr;
    if ((status = env->Class_FindField(cls, "nativeContext", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        ThrowStsInvalidParamError(env, "find nativeContext failed.");
        return false;
    }
    auto workContext = new (std::nothrow) std::weak_ptr<Context>(context);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "workContext nullptr");
        ThrowStsInvalidParamError(env, "workContext is null.");
        return false;
    }
    ani_long nativeContextLong = (ani_long)workContext;
    if ((status = env->Object_SetField_Long(contextObj, field, nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        ThrowStsInvalidParamError(env, "set field failed.");
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
        ani_class cls = nullptr;
        ani_status status = env->FindClass("Lapplication/Context/Context;", &cls);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "find Context failed status: %{public}d", status);
        }
        ani_method method = nullptr;
        status = env->Class_FindMethod(cls, "<ctor>", ":V", &method);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod ctor failed status: %{public}d", status);
        }
        ani_object objValue = nullptr;
        if (env->Object_New(cls, method, &objValue) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "Object_New failed status: %{public}d", status);
        }
        AppExecFwk::AsyncCallback(env, callback, CreateStsError(env,
            AbilityErrorCode::ERROR_CODE_INVALID_PARAM), objValue);
        return;
    }
    ani_class cls {};
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("Lapplication/Context/Context;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        ThrowStsInvalidParamError(env, "find class failed.");
        return;
    }
    ani_object contextObj = nullptr;
    if (!SetNativeContextLong(env, context, cls, contextObj)) {
        TAG_LOGE(AAFwkTag::APPKIT, "set nativeContextLong failed");
        return;
    }
    auto application = context->GetApplicationContext();
    if (application == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "application is null");
        ThrowStsInvalidParamError(env, "application is nullptr.");
        return;
    }
    ContextUtil::StsCreatContext(env, cls, contextObj, application->GetApplicationCtxObjRef(), context);
    AppExecFwk::AsyncCallback(env, callback, CreateStsError(env, AbilityErrorCode::ERROR_OK), contextObj);
}

static void CreateModuleContext([[maybe_unused]] ani_env *env,
    ani_object contextObj, ani_string bundleName, ani_string moduleName, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "CreateModuleContext Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    std::string stdBundleName = "";
    std::string stdModuleName = "";
    AppExecFwk::GetStdString(env, bundleName, stdBundleName);
    AppExecFwk::GetStdString(env, moduleName, stdModuleName);
    ani_boolean stageMode = false;
    ani_status status = OHOS::AbilityRuntime::IsStageContext(env, contextObj, stageMode);
    if (status != ANI_OK || !stageMode) {
        TAG_LOGE(AAFwkTag::APPKIT, "not stageMode");
        ThrowStsInvalidParamError(env, "Parse param context failed, must be a context of stageMode.");
        return;
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, contextObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        ThrowStsInvalidParamError(env, "Parse param context failed, must not be nullptr.");
        return;
    }
    auto inputContextPtr = Context::ConvertTo<Context>(context);
    if (inputContextPtr == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "Convert to context failed");
        ThrowStsInvalidParamError(env, "Parse param context failed, must be a context.");
        return;
    }
    std::shared_ptr<std::shared_ptr<Context>> moduleContext = std::make_shared<std::shared_ptr<Context>>();
    std::shared_ptr<ContextImpl> contextImpl = std::make_shared<ContextImpl>();
    if (contextImpl == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null contextImpl");
        ThrowStsInvalidParamError(env, "create context failed.");
        return;
    }
    contextImpl->SetProcessName(context->GetProcessName());
    if (stdBundleName.empty()) {
        *moduleContext = contextImpl->CreateModuleContext(stdModuleName, inputContextPtr);
    } else {
        *moduleContext = contextImpl->CreateModuleContext(stdBundleName, stdModuleName, inputContextPtr);
    }
    SetCreateCompleteCallback(env, moduleContext, callback);
}

static void CreateBundleContext([[maybe_unused]] ani_env *env,
    ani_object contextObj, ani_string bundleName, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "CreateBundleContext Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    std::string stdBundleName = "";
    AppExecFwk::GetStdString(env, bundleName, stdBundleName);
    ani_boolean stageMode = false;
    ani_status status = OHOS::AbilityRuntime::IsStageContext(env, contextObj, stageMode);
    if (status != ANI_OK || !stageMode) {
        TAG_LOGE(AAFwkTag::APPKIT, "not stageMode");
        ThrowStsInvalidParamError(env, "Parse param context failed, must be a context of stageMode.");
        return;
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, contextObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        ThrowStsInvalidParamError(env, "Parse param context failed, must not be nullptr.");
        return;
    }
    auto inputContextPtr = Context::ConvertTo<Context>(context);
    if (inputContextPtr == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "Convert to context failed");
        ThrowStsInvalidParamError(env, "Parse param context failed, must be a context.");
        return;
    }
    auto bundleContext = std::make_shared<std::shared_ptr<Context>>();
    std::shared_ptr<ContextImpl> contextImpl = std::make_shared<ContextImpl>();
    if (contextImpl == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null contextImpl");
        ThrowStsInvalidParamError(env, "create context failed.");
        return;
    }
    contextImpl->SetProcessName(context->GetProcessName());
    contextImpl->CreateBundleContext(*bundleContext, stdBundleName, inputContextPtr);
    SetCreateCompleteCallback(env, bundleContext, callback);
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
    status = env->FindNamespace("L@ohos/app/ability/application/application;", &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindNamespace application failed status: %{public}d", status);
        return;
    }
    std::array methods = {
        ani_native_function {
            "nativeCreateModuleContext", nullptr, reinterpret_cast<void *>(CreateModuleContext)
        },
        ani_native_function {
            "nativeCreateBundleContext", nullptr, reinterpret_cast<void *>(CreateBundleContext)
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
    TAG_LOGD(AAFwkTag::APPKIT, "AbilityManagerSts.ANI_Constructor finished");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS