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

#include "ets_auto_fill_extension_context.h"

#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ets_auto_fill_extension_util.h"
#include "ets_context_utils.h"
#include "ets_error_utils.h"
#include "ets_extension_context.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* AUTO_FILL_EXTENSION_CONTEXT_CLASS_NAME =
    "application.AutoFillExtensionContext.AutoFillExtensionContext";
constexpr const char* CLEANER_CLASS = "application.AutoFillExtensionContext.Cleaner";
}

ani_object EtsAutoFillExtensionContext::SetEtsAutoFillExtensionContext(ani_env *env,
    std::shared_ptr<AutoFillExtensionContext> context)
{
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env or context");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(AUTO_FILL_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "find class status: %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "l:", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "find method status: %{public}d", status);
        return nullptr;
    }
    auto etsAutoFillExtensionContext = new (std::nothrow) EtsAutoFillExtensionContext(context);
    if (etsAutoFillExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "etsAutoFillExtensionContext nullptr");
        return nullptr;
    }
    ani_object contextObj = nullptr;
    if ((status = env->Object_New(cls, method, &contextObj, reinterpret_cast<ani_long>(etsAutoFillExtensionContext)))
        != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "new object status: %{public}d", status);
        delete etsAutoFillExtensionContext;
        etsAutoFillExtensionContext = nullptr;
        return nullptr;
    }
    auto workContext = new (std::nothrow) std::weak_ptr<AutoFillExtensionContext>(
        etsAutoFillExtensionContext->context_);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "workContext nullptr");
        delete etsAutoFillExtensionContext;
        etsAutoFillExtensionContext = nullptr;
        return nullptr;
    }
    if (!ContextUtil::SetNativeContextLong(env, contextObj, reinterpret_cast<ani_long>(workContext))) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "SetNativeContextLong failed");
        delete workContext;
        workContext = nullptr;
        delete etsAutoFillExtensionContext;
        etsAutoFillExtensionContext = nullptr;
        return nullptr;
    }
    return contextObj;
}

EtsAutoFillExtensionContext *EtsAutoFillExtensionContext::GetEtsAutoFillExtensionContext(ani_env *env,
    ani_object object)
{
    if (env == nullptr || object == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env or object");
        return nullptr;
    }
    ani_long autoFillExtensionContextPtr = 0;
    ani_status status = env->Object_GetFieldByName_Long(object, "autoFillExtensionContextPtr",
        &autoFillExtensionContextPtr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "autoFillExtensionContextPtr GetField status: %{public}d", status);
        return nullptr;
    }
    auto etsAutoFillExtensionContext = reinterpret_cast<EtsAutoFillExtensionContext *>(autoFillExtensionContextPtr);
    if (etsAutoFillExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "etsAutoFillExtensionContext null");
        return nullptr;
    }
    return etsAutoFillExtensionContext;
}

void EtsAutoFillExtensionContext::Clean(ani_env *env, ani_object object)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return;
    }
    ani_long ptr = 0;
    ani_status status = env->Object_GetFieldByName_Long(object, "ptr", &ptr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "ptr GetField status: %{public}d", status);
        return;
    }
    if (ptr != 0) {
        delete reinterpret_cast<EtsAutoFillExtensionContext *>(ptr);
    }
}

void EtsAutoFillExtensionContext::ReloadInModal(ani_env *env, ani_object object, ani_object customDataObj,
    ani_object callback)
{
    auto etsAutoFillExtensionContext = GetEtsAutoFillExtensionContext(env, object);
    if (etsAutoFillExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null etsAutoFillExtensionContext");
        return;
    }
    etsAutoFillExtensionContext->OnReloadInModal(env, object, customDataObj, callback);
}

void EtsAutoFillExtensionContext::OnReloadInModal(ani_env *env, ani_object object, ani_object customDataObj,
    ani_object callback)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_ref etsCustomData = nullptr;
    if ((status = env->Object_GetPropertyByName_Ref(customDataObj, "data", &etsCustomData)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "Object_GetPropertyByName_Ref failed, status: %{public}d", status);
        return;
    }
    CustomData customData;
    if (etsCustomData == nullptr || !AppExecFwk::UnwrapWantParams(env, etsCustomData, customData.data)) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "Parse custom data failed");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return;
    }
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null context");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        return;
    }
    auto ret = context->ReloadInModal(customData);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "error is %{public}d", ret);
    }
    AppExecFwk::AsyncCallback(env, callback,
        AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret)), nullptr);
}

ani_object EtsAutoFillExtensionContext::CreateEtsAutoFillExtensionContext(ani_env *env,
    std::shared_ptr<AutoFillExtensionContext> context)
{
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env or context");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(AUTO_FILL_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "find class status: %{public}d", status);
        return nullptr;
    }
    std::array functions = {
        ani_native_function { "nativeReloadInModal",
            "C{application.CustomData.CustomData}C{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void*>(EtsAutoFillExtensionContext::ReloadInModal) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK
        && status != ANI_ALREADY_BINDED) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "bind method status : %{public}d", status);
        return nullptr;
    }
    ani_class cleanerCls = nullptr;
    if ((status = env->FindClass(CLEANER_CLASS, &cleanerCls)) != ANI_OK || cleanerCls == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "Cleaner FindClass failed status: %{public}d, or null cleanerCls", status);
        return nullptr;
    }
    std::array cleanerMethods = {
        ani_native_function {"clean", nullptr, reinterpret_cast<void *>(EtsAutoFillExtensionContext::Clean) },
    };
    if ((status = env->Class_BindNativeMethods(cleanerCls, cleanerMethods.data(), cleanerMethods.size())) !=
        ANI_OK && status != ANI_ALREADY_BINDED) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "cleanerCls Class_BindNativeMethods failed status: %{public}d", status);
        return nullptr;
    }
    ani_object contextObj = SetEtsAutoFillExtensionContext(env, context);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null contextObj");
        return nullptr;
    }
    AbilityRuntime::ContextUtil::CreateEtsBaseContext(env, cls, contextObj, context);
    AbilityRuntime::CreateEtsExtensionContext(env, cls, contextObj, context, context->GetAbilityInfo());
    return contextObj;
}
}
}