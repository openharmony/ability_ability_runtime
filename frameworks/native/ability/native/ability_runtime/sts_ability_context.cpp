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

#include "ability_runtime/sts_ability_context.h"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <regex>

#include "ability_manager_client.h"
#include "ability_manager_errors.h"
#include "ability_business_error.h"
#include "app_utils.h"
#include "event_handler.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "sts_data_struct_converter.h"
#include "mission_info.h"
#include "ani_common_want.h"
#include "ani_common_start_options.h"
#include "ani_common_configuration.h"
#include "ani_common_ability_result.h"
#include "open_link_options.h"
#include "start_options.h"
#include "sts_ui_extension_callback.h"
#include "tokenid_kit.h"
#include "ui_ability_servicehost_stub_impl.h"
#include "ui_service_extension_connection_constants.h"
#include "uri.h"
#include "want.h"
#include "common_fun_ani.h"
#include "sts_context_utils.h"
#include "sts_error_utils.h"

namespace OHOS {
namespace AbilityRuntime {
const char *INVOKE_METHOD_NAME = "invoke";
std::mutex StsAbilityContext::requestCodeMutex_;


std::shared_ptr<AbilityContext> StsAbilityContext::GetAbilityContext(ani_env *env, ani_object aniObj)
{
    ani_long nativeContextLong;
    ani_class cls {};
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return nullptr;
    }
    if ((status = env->FindClass("Lapplication/UIAbilityContext/UIAbilityContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_GetField_Long(aniObj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    auto weakContext = reinterpret_cast<std::weak_ptr<AbilityContext>*>(nativeContextLong);
    return weakContext != nullptr ? weakContext->lock() : nullptr;
}

ani_object StsAbilityContext::SetAbilityContext(ani_env *env, const std::shared_ptr<AbilityContext> &context)
{
    auto workContext = new (std::nothrow) std::weak_ptr<AbilityContext>(context);
    ani_long nativeContextLong = (ani_long)workContext;
    ani_class cls {};
    ani_status status = ANI_ERROR;
    ani_object contextObj = nullptr;
    ani_method method {};
    ani_field field = nullptr;

    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null context");
        return nullptr;
    }
    if ((status = env->FindClass("Lapplication/UIAbilityContext/UIAbilityContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetField_Long(contextObj, field, nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    return contextObj;
}

void StsAbilityContext::InheritWindowMode(ani_env *env, ani_object aniObj, AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
#ifdef SUPPORT_SCREEN
    // only split mode need inherit
    auto context = GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "context null");
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

bool StsAbilityContext::AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result)
{
    ani_status status = ANI_ERROR;
    ani_class clsCall {};

    if ((status = env->FindClass("Lapplication/UIAbilityContext/AsyncCallbackWrapper;", &clsCall)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return false;
    }
    ani_method method {};
    if ((status = env->Class_FindMethod(
        clsCall, INVOKE_METHOD_NAME, "L@ohos/base/BusinessError;Lstd/core/Object;:V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return false;
    }
    if (result == nullptr) {
        ani_ref nullRef = nullptr;
        env->GetNull(&nullRef);
        result = reinterpret_cast<ani_object>(nullRef);
    }
    if ((status = env->Object_CallMethod_Void(call, method, error, result)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return false;
    }
    return true;
}

std::string StsAbilityContext::GetErrMsg(int32_t err, const std::string &permission)
{
    auto errCode = GetJsErrorCodeByNativeError(err);
    auto errMsg = (errCode == AbilityErrorCode::ERROR_CODE_PERMISSION_DENIED && !permission.empty())
                      ? GetNoPermissionErrorMsg(permission)
                      : GetErrorMsg(errCode);
    return errMsg;
}

ani_object StsAbilityContext::WrapError(ani_env *env, const std::string &msg)
{
    ani_class cls {};
    ani_method method {};
    ani_object obj = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return nullptr;
    }
    ani_string aniMsg = AppExecFwk::GetAniString(env, msg);

    ani_ref undefRef;
    env->GetUndefined(&undefRef);

    if ((status = env->FindClass("Lescompat/Error;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "Lstd/core/String;Lescompat/ErrorOptions;:V", &method)) !=
        ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }

    if ((status = env->Object_New(cls, method, &obj, aniMsg, undefRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    return obj;
}

ani_object StsAbilityContext::WrapBusinessError(ani_env *env, int32_t code)
{
    ani_class cls {};
    ani_method method {};
    ani_object obj = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return nullptr;
    }
    if ((status = env->FindClass("L@ohos/base/BusinessError;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "DLescompat/Error;:V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    ani_object error = WrapError(env, GetErrMsg(code));
    if (error == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "error nulll");
        return nullptr;
    }
    ani_double dCode(code);
    if ((status = env->Object_New(cls, method, &obj, dCode, error)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    return obj;
}

void StsAbilityContext::AddFreeInstallObserver(
    ani_env *env, const AAFwk::Want &want, ani_object callback, const std::shared_ptr<AbilityContext> &context)
{
    // adapter free install async return install and start result
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    int ret = 0;
    if (!context) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return;
    }
    if (freeInstallObserver_ == nullptr) {
        ani_vm *etsVm = nullptr;
        ani_status status = ANI_ERROR;
        if ((status = env->GetVM(&etsVm)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "status : %{public}d", status);
        }
        freeInstallObserver_ = new StsFreeInstallObserver(etsVm);
        ret = context->AddFreeInstallObserver(freeInstallObserver_);
    }
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "addFreeInstallObserver error");
    }
    std::string startTime = want.GetStringParam(AAFwk::Want::PARAM_RESV_START_TIME);
    TAG_LOGI(AAFwkTag::CONTEXT, "addStsObserver");
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    freeInstallObserver_->AddStsObserverObject(
        env, bundleName, abilityName, startTime, callback);
}

void StsAbilityContext::StartAbilityInner([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
    ani_object wantObj, ani_object opt, ani_object call)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(env, wantObj, want);
    auto context = StsAbilityContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "context null");
        ThrowStsInvalidParamError(env, "context null");
        return;
    }
    InheritWindowMode(env, aniObj, want);

    if ((want.GetFlags() & AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == AAFwk::Want::FLAG_INSTALL_ON_DEMAND) {
        std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
            system_clock::now().time_since_epoch()).count());
        want.SetParam(AAFwk::Want::PARAM_RESV_START_TIME, startTime);
        AddFreeInstallObserver(env, want, call, context);
    }
    auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
    if (opt != nullptr) {
        AAFwk::StartOptions startOptions;
        OHOS::AppExecFwk::UnwrapStartOptionsWithProcessOption(env, opt, startOptions);
        *innerErrCode = context->StartAbility(want, startOptions, -1);
    } else {
        *innerErrCode = context->StartAbility(want, -1);
    }
    ani_object aniObject = CreateStsError(env, AbilityErrorCode::ERROR_OK);
    if (*innerErrCode != ERR_OK) {
        aniObject = CreateStsErrorByNativeErr(env, *innerErrCode);
    }
    if ((want.GetFlags() & AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == AAFwk::Want::FLAG_INSTALL_ON_DEMAND) {
        if (*innerErrCode != ERR_OK && freeInstallObserver_ != nullptr) {
            std::string bundleName = want.GetElement().GetBundleName();
            std::string abilityName = want.GetElement().GetAbilityName();
            std::string startTime = want.GetStringParam(AAFwk::Want::PARAM_RESV_START_TIME);
            freeInstallObserver_->OnInstallFinished(bundleName, abilityName, startTime, *innerErrCode);
        }
    } else {
        AsyncCallback(env, call, aniObject, nullptr);
    }
}

void StsAbilityContext::StartAbility1(
    [[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj, ani_object wantObj, ani_object call)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    GetInstance().StartAbilityInner(env, aniObj, wantObj, nullptr, call);
}

void StsAbilityContext::StartAbility2([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
    ani_object wantObj, ani_object opt, ani_object call)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    GetInstance().StartAbilityInner(env, aniObj, wantObj, opt, call);
}

int32_t StsAbilityContext::GenerateRequestCode()
{
    static int32_t curRequestCode_ = 0;
    std::lock_guard lock(requestCodeMutex_);
    curRequestCode_ = (curRequestCode_ == INT_MAX) ? 0 : (curRequestCode_ + 1);
    return curRequestCode_;
}

// TO DO: free install
void StsAbilityContext::StartAbilityForResultInner(ani_env *env, ani_object aniObj, ani_object wantObj,
    ani_object startOptionsObj, ani_object callback)
{
    auto context = StsAbilityContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "GetAbilityContext is nullptr");
        ThrowStsErrorByNativeErr(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
        return;
    }
    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(env, wantObj, want);
    AAFwk::StartOptions startOptions;
    if (startOptionsObj) {
        OHOS::AppExecFwk::UnwrapStartOptions(env, startOptionsObj, startOptions);
    }
    TAG_LOGE(AAFwkTag::UIABILITY, "displayId:%{public}d", startOptions.GetDisplayID());
    std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
        system_clock::now().time_since_epoch()).count());
    ani_ref callbackRef = nullptr;
    env->GlobalReference_Create(callback, &callbackRef);
    ani_vm *etsVm = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GetVM(&etsVm)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "status : %{public}d", status);
        return;
    }
    RuntimeTask task = [etsVm, callbackRef, element = want.GetElement(), flags = want.GetFlags(), startTime]
        (int resultCode, const AAFwk::Want &want, bool isInner) {
        TAG_LOGD(AAFwkTag::CONTEXT, "start async callback");
        ani_status status = ANI_ERROR;
        ani_env *env = nullptr;
        if ((status = etsVm->GetEnv(ANI_VERSION_1, &env)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "status : %{public}d", status);
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
        auto errCode = isInner ? resultCode : 0;
        AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, errCode), abilityResult);
    };
    auto requestCode = GenerateRequestCode();
    (startOptionsObj == nullptr) ? context->StartAbilityForResult(want, requestCode, std::move(task)) :
        context->StartAbilityForResult(want, startOptions, requestCode, std::move(task));
    return;
}

// TO DO: free install
void StsAbilityContext::StartAbilityForResult1(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    StartAbilityForResultInner(env, aniObj, wantObj, nullptr, callback);
}

// TO DO: free install
void StsAbilityContext::StartAbilityForResult2(ani_env *env, ani_object aniObj, ani_object wantObj,
    ani_object startOptionsObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    StartAbilityForResultInner(env, aniObj, wantObj, startOptionsObj, callback);
}

void StsAbilityContext::TerminateSelf(
    ani_env *env, ani_object aniObj, ani_object callback)
{
    ani_object aniObject = nullptr;
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    auto context = StsAbilityContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "context null");
        aniObject = CreateStsInvalidParamError(env, "context null");
        AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    ErrCode ret = context->TerminateSelf();
    if (ret == static_cast<ErrCode>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT) || ret == ERR_OK) {
        aniObject = CreateStsError(env, static_cast<AbilityErrorCode>(ret));
    } else {
        aniObject = CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret));
    }
    AsyncCallback(env, callback, aniObject, nullptr);
}

void StsAbilityContext::TerminateSelfWithResult(
    ani_env *env, ani_object aniObj, ani_object abilityResult, ani_object callback)
{
    ani_object aniObject = nullptr;
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    auto context = StsAbilityContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "GetAbilityContext is nullptr");
        aniObject = CreateStsInvalidParamError(env, "context null");
        AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    AAFwk::Want want;
    int resultCode = 0;
    OHOS::AppExecFwk::UnWrapAbilityResult(env, abilityResult, resultCode, want);
    context->SetTerminating(true);
    ErrCode ret = context->TerminateAbilityWithResult(want, resultCode);
    if (ret == static_cast<ErrCode>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT) || ret == ERR_OK) {
        aniObject = CreateStsError(env, static_cast<AbilityErrorCode>(ret));
    } else {
        aniObject = CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret));
    }
    AsyncCallback(env, callback, aniObject, nullptr);
}

void StsAbilityContext::reportDrawnCompletedSync(
    [[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj, ani_object callback)
{
    ani_object aniObject = nullptr;
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    auto context = GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "context null");
        aniObject = CreateStsInvalidParamError(env, "context null");
        AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    ErrCode ret = context->ReportDrawnCompleted();
    if (ret == ERR_OK) {
        aniObject = CreateStsError(env, static_cast<AbilityErrorCode>(ret));
    } else {
        aniObject = CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret));
    }
    AsyncCallback(env, callback, aniObject, nullptr);
}

ani_object StsAbilityContext::StartAbilityByTypeSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_string aniType, ani_ref aniWantParam, ani_object startCallback)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "call");
    auto context = GetAbilityContext(env, aniObj);
    ani_object aniObject = CreateStsError(env, AbilityErrorCode::ERROR_OK);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "get abilityContext failed.");
        ThrowStsInvalidParamError(env, "context null");
        return aniObject;
    }

    std::string type;
    if (!AppExecFwk::GetStdString(env, aniType, type)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "parse type failed");
        ThrowStsInvalidParamError(env, "Parse param type failed, type must be string.");
        return aniObject;
    }

    AAFwk::WantParams wantParam;
    if (!AppExecFwk::UnwrapWantParams(env, aniWantParam, wantParam)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "parse wantParam failed");
        ThrowStsInvalidParamError(env, "Parse param want failed, want must be Want.");
        return aniObject;
    }

    ani_vm *aniVM = nullptr;
    if (env->GetVM(&aniVM) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "get aniVM failed");
        ThrowStsInvalidParamError(env, "Get aniVm failed.");
        return aniObject;
    }
    auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
    std::shared_ptr<StsUIExtensionCallback> callback = std::make_shared<StsUIExtensionCallback>();
    callback->SetStsCallbackObject(aniVM, startCallback);
    *innerErrCode = context->StartAbilityByType(type, wantParam, callback);
    if (*innerErrCode == ERR_OK) {
        return aniObject;
    } else if (*innerErrCode == static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT)) {
        return CreateStsError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    } else {
        return CreateStsErrorByNativeErr(env, *innerErrCode);
    }
}

bool BindNativeMethods(ani_env *env, ani_class &cls)
{
    ani_status status = env->FindClass("Lapplication/UIAbilityContext/UIAbilityContext;", &cls);
    if (status != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return false;
    }

    std::array functions = {
        ani_native_function { "nativeStartAbilitySync",
            "L@ohos/app/ability/Want/Want;Lapplication/UIAbilityContext/AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(StsAbilityContext::StartAbility1) },
        ani_native_function { "nativeStartAbilitySync",
            "L@ohos/app/ability/Want/Want;L@ohos/app/ability/StartOptions/StartOptions;Lapplication/UIAbilityContext/"
            "AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(StsAbilityContext::StartAbility2) },
        ani_native_function { "nativeStartAbilityForResult",
            "L@ohos/app/ability/Want/Want;Lapplication/UIAbilityContext/AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(StsAbilityContext::StartAbilityForResult1) },
        ani_native_function { "nativeStartAbilityForResult",
            "L@ohos/app/ability/Want/Want;L@ohos/app/ability/StartOptions/StartOptions;Lapplication/UIAbilityContext/"
            "AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(StsAbilityContext::StartAbilityForResult2) },
        ani_native_function { "nativeTerminateSelfSync",
            "Lapplication/UIAbilityContext/AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(StsAbilityContext::TerminateSelf) },
        ani_native_function { "nativeTerminateSelfWithResult",
            "Lability/abilityResult/AbilityResult;Lapplication/UIAbilityContext/AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(StsAbilityContext::TerminateSelfWithResult) },
        ani_native_function { "nativeReportDrawnCompletedSync", "Lapplication/UIAbilityContext/AsyncCallbackWrapper;:V",
            reinterpret_cast<ani_int*>(StsAbilityContext::reportDrawnCompletedSync) },
        ani_native_function { "nativeStartAbilityByTypeSync", nullptr,
            reinterpret_cast<void*>(StsAbilityContext::StartAbilityByTypeSync) },
    };

    status = env->Class_BindNativeMethods(cls, functions.data(), functions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return false;
    }
    return true;
}

bool SetAbilityInfo(ani_env *env, ani_class cls, ani_object contextObj, const std::shared_ptr<AbilityContext> &context)
{
    ani_field field = nullptr;
    auto abilityInfo = context->GetAbilityInfo();
    ani_ref abilityInfoRef = AppExecFwk::CommonFunAni::ConvertAbilityInfo(env, *abilityInfo);

    ani_status status = env->Class_FindField(cls, "abilityInfo", &field);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return false;
    }

    status = env->Object_SetField_Ref(contextObj, field, abilityInfoRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return false;
    }
    return true;
}

bool SetConfiguration(
    ani_env *env, ani_class cls, ani_object contextObj, const std::shared_ptr<AbilityContext> &context)
{
    ani_field field = nullptr;
    auto configuration = context->GetConfiguration();
    ani_ref configurationRef = OHOS::AppExecFwk::WrapConfiguration(env, *configuration);

    ani_status status = env->Class_FindField(cls, "config", &field);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return false;
    }

    status = env->Object_SetField_Ref(contextObj, field, configurationRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return false;
    }
    return true;
}

ani_ref CreateStsAbilityContext(
    ani_env *env, const std::shared_ptr<AbilityContext> &context, const std::shared_ptr<OHOSApplication> &application)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    ani_class cls {};
    if (!BindNativeMethods(env, cls)) {
        TAG_LOGE(AAFwkTag::UIABILITY, "BindNativeMethods failed");
        return nullptr;
    }
    ani_object contextObj = StsAbilityContext::SetAbilityContext(env, context);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null contextObj");
        return nullptr;
    }
    if (application == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null application");
        return nullptr;
    }
    ContextUtil::StsCreatContext(env, cls, contextObj, application->GetApplicationCtxObjRef(), context);
    if (!SetAbilityInfo(env, cls, contextObj, context)) {
        TAG_LOGE(AAFwkTag::UIABILITY, "SetAbilityInfo failed");
        return nullptr;
    }
    if (!SetConfiguration(env, cls, contextObj, context)) {
        TAG_LOGE(AAFwkTag::UIABILITY, "SetConfiguration failed");
        return nullptr;
    }
    return contextObj;
}
} // namespace AbilityRuntime
} // namespace OHOS
