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

#include "ability_runtime/ets_ability_context.h"

#include "ani_common_ability_result.h"
#include "ani_common_configuration.h"
#include "ani_common_start_options.h"
#include "ani_common_want.h"
#include "app_utils.h"
#include "common_fun_ani.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "ets_context_utils.h"
#include "ets_error_utils.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
std::mutex EtsAbilityContext::requestCodeMutex_;
namespace {
static std::once_flag g_bindNativeMethodsFlag;
constexpr const char *UI_ABILITY_CONTEXT_CLASS_NAME = "Lapplication/UIAbilityContext/UIAbilityContext;";
constexpr const char *CLASSNAME_ASYNC_CALLBACK_WRAPPER = "Lutils/AbilityUtils/AsyncCallbackWrapper;";
} // namespace

std::shared_ptr<AbilityContext> EtsAbilityContext::GetAbilityContext(ani_env *env, ani_object aniObj)
{
    if (env == nullptr || aniObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null env or aniObj");
        return nullptr;
    }
    ani_long nativeContextLong;
    ani_status status = env->Object_GetFieldByName_Long(aniObj, "nativeContext", &nativeContextLong);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Object_GetFieldByName_Long status: %{public}d", status);
        return nullptr;
    }
    auto weakContext = reinterpret_cast<std::weak_ptr<AbilityContext> *>(nativeContextLong);
    return weakContext != nullptr ? weakContext->lock() : nullptr;
}

ani_object EtsAbilityContext::SetAbilityContext(ani_env *env, const std::shared_ptr<AbilityContext> &context)
{
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null env or context");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_object contextObj = nullptr;
    ani_method method = nullptr;
    ani_status status = env->FindClass(UI_ABILITY_CONTEXT_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "FindClass status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Class_FindMethod status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Object_New status: %{public}d", status);
        return nullptr;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<AbilityContext>(context);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "workContext nullptr");
        return nullptr;
    }
    ani_long nativeContextLong = (ani_long)workContext;
    if ((status = env->Object_SetFieldByName_Long(contextObj, "nativeContext", nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Object_SetFieldByName_Long status: %{public}d", status);
        delete workContext;
        workContext = nullptr;
        return nullptr;
    }
    return contextObj;
}

// to be done: free install
void EtsAbilityContext::StartAbility(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object call)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::CONTEXT, "StartAbility called");
    GetInstance().OnStartAbility(env, aniObj, wantObj, nullptr, call);
}

void EtsAbilityContext::StartAbilityWithOptions(
    ani_env *env, ani_object aniObj, ani_object wantObj, ani_object opt, ani_object call)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::CONTEXT, "StartAbilityWithOptions called");
    GetInstance().OnStartAbility(env, aniObj, wantObj, opt, call);
}

// to be done: free install
void EtsAbilityContext::StartAbilityForResult(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "StartAbilityForResult called");
    GetInstance().OnStartAbilityForResult(env, aniObj, wantObj, nullptr, callback);
}

// to be done: free install
void EtsAbilityContext::StartAbilityForResultWithOptions(
    ani_env *env, ani_object aniObj, ani_object wantObj, ani_object startOptionsObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "StartAbilityForResultWithOptions called");
    GetInstance().OnStartAbilityForResult(env, aniObj, wantObj, startOptionsObj, callback);
}

void EtsAbilityContext::TerminateSelf(ani_env *env, ani_object aniObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "TerminateSelf called");
    GetInstance().OnTerminateSelf(env, aniObj, callback);
}

void EtsAbilityContext::TerminateSelfWithResult(
    ani_env *env, ani_object aniObj, ani_object abilityResult, ani_object callback)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "TerminateSelfWithResult called");
    GetInstance().OnTerminateSelfWithResult(env, aniObj, abilityResult, callback);
}

void EtsAbilityContext::ReportDrawnCompleted(ani_env *env, ani_object aniObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "ReportDrawnCompleted called");
    GetInstance().OnReportDrawnCompleted(env, aniObj, callback);
}

int32_t EtsAbilityContext::GenerateRequestCode()
{
    static int32_t curRequestCode_ = 0;
    std::lock_guard lock(requestCodeMutex_);
    curRequestCode_ = (curRequestCode_ == INT_MAX) ? 0 : (curRequestCode_ + 1);
    return curRequestCode_;
}

void EtsAbilityContext::InheritWindowMode(ani_env *env, ani_object aniObj, AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "InheritWindowMode");
#ifdef SUPPORT_SCREEN
    // only split mode need inherit
    auto context = GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "context null");
        return;
    }
    auto windowMode = context->GetCurrentWindowMode();
    if (AAFwk::AppUtils::GetInstance().IsInheritWindowSplitScreenMode() &&
        (windowMode == AAFwk::AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_PRIMARY ||
            windowMode == AAFwk::AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_SECONDARY)) {
        want.SetParam(AAFwk::Want::PARAM_RESV_WINDOW_MODE, windowMode);
    }
    TAG_LOGD(AAFwkTag::CONTEXT, "window mode is %{public}d", windowMode);
#endif
}

bool EtsAbilityContext::AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result)
{
    if (env == nullptr || call == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "env or call is nullptr");
        return false;
    }
    ani_class clsCall = nullptr;
    ani_status status = env->FindClass(CLASSNAME_ASYNC_CALLBACK_WRAPPER, &clsCall);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "FindClass status: %{public}d", status);
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(clsCall, "invoke", "L@ohos/base/BusinessError;Lstd/core/Object;:V", &method)) !=
        ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Class_FindMethod status: %{public}d", status);
        return false;
    }
    if (error == nullptr) {
        ani_ref nullRef = nullptr;
        env->GetNull(&nullRef);
        error = reinterpret_cast<ani_object>(nullRef);
    }
    if (result == nullptr) {
        ani_ref undefinedRef = nullptr;
        env->GetUndefined(&undefinedRef);
        result = reinterpret_cast<ani_object>(undefinedRef);
    }
    if ((status = env->Object_CallMethod_Void(call, method, error, result)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "status: %{public}d", status);
        return false;
    }
    return true;
}

void EtsAbilityContext::OnStartAbility(
    ani_env *env, ani_object aniObj, ani_object wantObj, ani_object opt, ani_object call)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    AAFwk::Want want;
    if (!OHOS::AppExecFwk::UnwrapWant(env, wantObj, want)) {
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param want failed, must be a Want");
        return;
    }
    InheritWindowMode(env, aniObj, want);
    auto context = EtsAbilityContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        EtsErrorUtil::ThrowInvalidParamError(env, "null context");
        return;
    }
    if ((want.GetFlags() & AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == AAFwk::Want::FLAG_INSTALL_ON_DEMAND) {
        std::string startTime = std::to_string(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
        want.SetParam(AAFwk::Want::PARAM_RESV_START_TIME, startTime);
        AddFreeInstallObserver(env, want, call, context);
    }
    ErrCode innerErrCode = ERR_OK;
    if (opt != nullptr) {
        AAFwk::StartOptions startOptions;
        if (!OHOS::AppExecFwk::UnwrapStartOptions(env, opt, startOptions)) {
            EtsErrorUtil::ThrowInvalidParamError(env,
                "Parse param startOptions failed, startOptions must be StartOptions.");
            TAG_LOGE(AAFwkTag::CONTEXT, "invalid options");
            return;
        }
        innerErrCode = context->StartAbility(want, startOptions, -1);
    } else {
        innerErrCode = context->StartAbility(want, -1);
    }
    ani_object aniObject = EtsErrorUtil::CreateErrorByNativeErr(env, innerErrCode);
    if ((want.GetFlags() & AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == AAFwk::Want::FLAG_INSTALL_ON_DEMAND) {
        if (innerErrCode != ERR_OK && freeInstallObserver_ != nullptr) {
            std::string bundleName = want.GetElement().GetBundleName();
            std::string abilityName = want.GetElement().GetAbilityName();
            std::string startTime = want.GetStringParam(AAFwk::Want::PARAM_RESV_START_TIME);
            freeInstallObserver_->OnInstallFinished(bundleName, abilityName, startTime, innerErrCode);
        }
        return;
    }
    AsyncCallback(env, call, aniObject, nullptr);
}

void EtsAbilityContext::OnStartAbilityForResult(
    ani_env *env, ani_object aniObj, ani_object wantObj, ani_object startOptionsObj, ani_object callback)
{
    auto context = EtsAbilityContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "GetAbilityContext is nullptr");
        EtsErrorUtil::ThrowErrorByNativeErr(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
        return;
    }
    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(env, wantObj, want);
    AAFwk::StartOptions startOptions;
    if (startOptionsObj) {
        OHOS::AppExecFwk::UnwrapStartOptions(env, startOptionsObj, startOptions);
    }
    TAG_LOGE(AAFwkTag::CONTEXT, "displayId:%{public}d", startOptions.GetDisplayID());
    StartAbilityForResultInner(env, startOptions, want, context, startOptionsObj, callback);
}

void EtsAbilityContext::StartAbilityForResultInner(ani_env *env, const AAFwk::StartOptions &startOptions,
    AAFwk::Want &want, std::shared_ptr<AbilityContext> context, ani_object startOptionsObj, ani_object callback)
{
    std::string startTime = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    ani_ref callbackRef = nullptr;
    env->GlobalReference_Create(callback, &callbackRef);
    ani_vm *etsVm = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GetVM(&etsVm)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "status: %{public}d", status);
        return;
    }
    if ((want.GetFlags() & AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == AAFwk::Want::FLAG_INSTALL_ON_DEMAND) {
        want.SetParam(AAFwk::Want::PARAM_RESV_START_TIME, startTime);
        AddFreeInstallObserver(env, want, callback, context, true);
    }
    RuntimeTask task = [etsVm, callbackRef, element = want.GetElement(), flags = want.GetFlags(), startTime,
        observer = freeInstallObserver_](int resultCode, const AAFwk::Want &want, bool isInner) {
        TAG_LOGD(AAFwkTag::CONTEXT, "start async callback");
        ani_status status = ANI_ERROR;
        ani_env *env = nullptr;
        if ((status = etsVm->GetEnv(ANI_VERSION_1, &env)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::CONTEXT, "status: %{public}d", status);
            return;
        }
        std::string bundleName = element.GetBundleName();
        std::string abilityName = element.GetAbilityName();
        ani_object abilityResult = AppExecFwk::WrapAbilityResult(env, resultCode, want);
        if (abilityResult == nullptr) {
            TAG_LOGW(AAFwkTag::CONTEXT, "null abilityResult");
            isInner = true;
            resultCode = ERR_INVALID_VALUE;
        }
        if ((flags & AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == AAFwk::Want::FLAG_INSTALL_ON_DEMAND
            && observer != nullptr) {
            isInner ? observer->OnInstallFinished(bundleName, abilityName, startTime, resultCode)
                    : observer->OnInstallFinished(bundleName, abilityName, startTime, abilityResult);
            return;
        }
        auto errCode = isInner ? resultCode : 0;
        AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
            OHOS::AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, errCode), abilityResult);
    };
    auto requestCode = GenerateRequestCode();
    (startOptionsObj == nullptr) ? context->StartAbilityForResult(want, requestCode, std::move(task))
                                 : context->StartAbilityForResult(want, startOptions, requestCode, std::move(task));
    return;
}

void EtsAbilityContext::OnTerminateSelf(ani_env *env, ani_object aniObj, ani_object callback)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null env or aniObj");
        ani_object aniObject = EtsErrorUtil::CreateInvalidParamError(env, "env null");
        AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    ani_object aniObject = nullptr;
    auto context = EtsAbilityContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        aniObject = EtsErrorUtil::CreateInvalidParamError(env, "context null");
        AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    ErrCode ret = context->TerminateSelf();
    if (ret == static_cast<ErrCode>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT) || ret == ERR_OK) {
        aniObject = EtsErrorUtil::CreateError(env, static_cast<AbilityErrorCode>(ret));
    } else {
        aniObject = EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret));
    }
    AsyncCallback(env, callback, aniObject, nullptr);
}

void EtsAbilityContext::OnTerminateSelfWithResult(
    ani_env *env, ani_object aniObj, ani_object abilityResult, ani_object callback)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null env");
        ani_object aniObject = EtsErrorUtil::CreateInvalidParamError(env, "env null");
        AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    ani_object aniObject = nullptr;
    auto context = EtsAbilityContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "GetAbilityContext is nullptr");
        aniObject = EtsErrorUtil::CreateInvalidParamError(env, "context null");
        AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    AAFwk::Want want;
    int resultCode = 0;
    OHOS::AppExecFwk::UnWrapAbilityResult(env, abilityResult, resultCode, want);
    context->SetTerminating(true);
    ErrCode ret = context->TerminateAbilityWithResult(want, resultCode);
    if (ret == static_cast<ErrCode>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT) || ret == ERR_OK) {
        aniObject = EtsErrorUtil::CreateError(env, static_cast<AbilityErrorCode>(ret));
    } else {
        aniObject = EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret));
    }
    AsyncCallback(env, callback, aniObject, nullptr);
}

void EtsAbilityContext::OnReportDrawnCompleted(ani_env *env, ani_object aniObj, ani_object callback)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null env");
        ani_object aniObject = EtsErrorUtil::CreateInvalidParamError(env, "env null");
        AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    ani_object aniObject = nullptr;
    auto context = GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "context null");
        aniObject = EtsErrorUtil::CreateInvalidParamError(env, "context null");
        AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    ErrCode ret = context->ReportDrawnCompleted();
    if (ret == ERR_OK) {
        aniObject = EtsErrorUtil::CreateError(env, static_cast<AbilityErrorCode>(ret));
    } else {
        aniObject = EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret));
    }
    AsyncCallback(env, callback, aniObject, nullptr);
}

void EtsAbilityContext::AddFreeInstallObserver(ani_env *env, const AAFwk::Want &want, ani_object callback,
    const std::shared_ptr<AbilityContext> &context, bool isAbilityResult, bool isOpenLink)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "AddFreeInstallObserver");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null env");
        return;
    }
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return;
    }
    if (freeInstallObserver_ == nullptr) {
        ani_vm *etsVm = nullptr;
        ani_status status = ANI_ERROR;
        if ((status = env->GetVM(&etsVm)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::CONTEXT, "status: %{public}d", status);
        }
        if (etsVm == nullptr) {
            TAG_LOGE(AAFwkTag::CONTEXT, "null etsVm");
            return;
        }
        freeInstallObserver_ = new (std::nothrow) EtsFreeInstallObserver(etsVm);
        if (freeInstallObserver_ == nullptr) {
            TAG_LOGE(AAFwkTag::CONTEXT, "null freeInstallObserver");
            return;
        }
        if (context->AddFreeInstallObserver(freeInstallObserver_) != ERR_OK) {
            TAG_LOGE(AAFwkTag::CONTEXT, "addFreeInstallObserver error");
            return;
        }
    }
    std::string startTime = want.GetStringParam(AAFwk::Want::PARAM_RESV_START_TIME);
    if (isOpenLink) {
        std::string url = want.GetUriString();
        freeInstallObserver_->AddEtsObserverObject(env, startTime, url, callback, isAbilityResult);
        return;
    }
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    freeInstallObserver_->AddEtsObserverObject(env, bundleName, abilityName, startTime, callback, isAbilityResult);
}

namespace {
bool BindNativeMethods(ani_env *env, ani_class &cls)
{
    ani_status status = env->FindClass(UI_ABILITY_CONTEXT_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "FindClass status: %{public}d", status);
        return false;
    }
    std::call_once(g_bindNativeMethodsFlag, [&status, env, cls]() {
        std::array functions = {
            ani_native_function { "nativeStartAbilitySync",
                "L@ohos/app/ability/Want/Want;Lapplication/UIAbilityContext/AsyncCallbackWrapper;:V",
                reinterpret_cast<void *>(EtsAbilityContext::StartAbility) },
            ani_native_function { "nativeStartAbilitySync",
                "L@ohos/app/ability/Want/Want;L@ohos/app/ability/StartOptions/StartOptions;Lapplication/"
                "UIAbilityContext/AsyncCallbackWrapper;:V",
                reinterpret_cast<void *>(EtsAbilityContext::StartAbilityWithOptions) },
            ani_native_function { "nativeStartAbilityForResult",
                "L@ohos/app/ability/Want/Want;Lapplication/UIAbilityContext/AsyncCallbackWrapper;:V",
                reinterpret_cast<void *>(EtsAbilityContext::StartAbilityForResult) },
            ani_native_function { "nativeStartAbilityForResult",
                "L@ohos/app/ability/Want/Want;L@ohos/app/ability/StartOptions/StartOptions;Lapplication/"
                "UIAbilityContext/AsyncCallbackWrapper;:V",
                reinterpret_cast<void *>(EtsAbilityContext::StartAbilityForResultWithOptions) },
            ani_native_function { "nativeTerminateSelfSync", "Lapplication/UIAbilityContext/AsyncCallbackWrapper;:V",
                reinterpret_cast<void *>(EtsAbilityContext::TerminateSelf) },
            ani_native_function { "nativeTerminateSelfWithResult",
                "Lability/abilityResult/AbilityResult;Lapplication/UIAbilityContext/AsyncCallbackWrapper;:V",
                reinterpret_cast<void *>(EtsAbilityContext::TerminateSelfWithResult) },
            ani_native_function { "nativeReportDrawnCompletedSync",
                "Lapplication/UIAbilityContext/AsyncCallbackWrapper;:V",
                reinterpret_cast<ani_int *>(EtsAbilityContext::ReportDrawnCompleted) },
        };
        status = env->Class_BindNativeMethods(cls, functions.data(), functions.size());
    });
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Class_BindNativeMethods status: %{public}d", status);
        return false;
    }
    return true;
}
} // namespace

ani_object CreateEtsAbilityContext(
    ani_env *env, const std::shared_ptr<AbilityContext> &context, const std::shared_ptr<OHOSApplication> &application)
{
    if (env == nullptr || context == nullptr || application == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null env or context or application");
        return nullptr;
    }
    ani_class cls = nullptr;
    if (!BindNativeMethods(env, cls)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "BindNativeMethods failed");
        return nullptr;
    }
    ani_object contextObj = EtsAbilityContext::SetAbilityContext(env, context);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null contextObj");
        return nullptr;
    }
    ContextUtil::CreateEtsBaseContext(env, cls, contextObj, context);

    auto abilityInfo = context->GetAbilityInfo();
    if (abilityInfo == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null abilityInfo");
        return nullptr;
    }
    ani_ref abilityInfoRef = AppExecFwk::CommonFunAni::ConvertAbilityInfo(env, *abilityInfo);
    ani_status status = env->Object_SetFieldByName_Ref(contextObj, "abilityInfo", abilityInfoRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Object_SetFieldByName_Ref status: %{public}d", status);
        return nullptr;
    }

    auto configuration = context->GetConfiguration();
    if (configuration == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null configuration");
        return nullptr;
    }
    ani_object configurationObj = OHOS::AppExecFwk::WrapConfiguration(env, *configuration);
    if ((status = env->Object_SetFieldByName_Ref(contextObj, "config", configurationObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Object_SetFieldByName_Ref status: %{public}d", status);
        return nullptr;
    }
    return contextObj;
}
} // namespace AbilityRuntime
} // namespace OHOS
