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
#include "ani_enum_convert.h"
#include "open_link_options.h"
#include "start_options.h"
#include "sts_ui_extension_callback.h"
#include "tokenid_kit.h"
#include "ui_ability_servicehost_stub_impl.h"
#include "ui_service_extension_connection_constants.h"
#include "uri.h"
#include "want.h"
#include "common_fun_ani.h"
#include "sts_caller_complex.h"
#include "sts_context_utils.h"
#include "sts_error_utils.h"

namespace OHOS {
namespace AbilityRuntime {
std::mutex StsAbilityContext::requestCodeMutex_;
const std::string APP_LINKING_ONLY = "appLinkingOnly";
namespace {
    static std::once_flag g_bindNativeMethodsFlag;

constexpr const char* UI_ABILITY_CONTEXT_CLASS_NAME = "Lapplication/UIAbilityContext/UIAbilityContext;";
constexpr int32_t CALLER_TIME_OUT = 10; // 10s
struct StartAbilityByCallData {
    sptr<IRemoteObject> remoteCallee;
    std::mutex mutexlock;
    std::condition_variable condition;
};

void GenerateCallerCallBack(std::shared_ptr<StartAbilityByCallData> calls,
    std::shared_ptr<CallerCallBack> callerCallBack)
{
    if (calls == nullptr || callerCallBack == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null calls or null callerCallBack");
        return;
    }
    auto callBackDone = [weakData = std::weak_ptr<StartAbilityByCallData>(calls)] (const sptr<IRemoteObject> &obj) {
        TAG_LOGI(AAFwkTag::UIABILITY, "callBackDone called start");
        auto calldata = weakData.lock();
        if (calldata == nullptr) {
            TAG_LOGW(AAFwkTag::UIABILITY, "calldata released");
            return;
        }
        std::lock_guard lock(calldata->mutexlock);
        calldata->remoteCallee = obj;
        calldata->condition.notify_all();
    };

    callerCallBack->SetCallBack(callBackDone);
}

void WaitForCalleeObj(std::shared_ptr<StartAbilityByCallData> callData)
{
    if (callData == nullptr) {
        return;
    }
    if (callData->remoteCallee == nullptr) {
        std::unique_lock lock(callData->mutexlock);
        if (callData->remoteCallee != nullptr) {
            return;
        }
        if (callData->condition.wait_for(lock, std::chrono::seconds(CALLER_TIME_OUT)) == std::cv_status::timeout) {
            TAG_LOGE(AAFwkTag::UIABILITY, "callExecute waiting callee timeout");
        }
    }
}
}
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
    if ((status = env->FindClass(UI_ABILITY_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_GetField_Long(aniObj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return nullptr;
    }
    auto weakContext = reinterpret_cast<std::weak_ptr<AbilityContext>*>(nativeContextLong);
    return weakContext != nullptr ? weakContext->lock() : nullptr;
}

ani_object StsAbilityContext::SetAbilityContext(ani_env *env, const std::shared_ptr<AbilityContext> &context)
{
    ani_class cls {};
    ani_status status = ANI_ERROR;
    ani_object contextObj = nullptr;
    ani_method method {};
    ani_field field = nullptr;
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null context");
        return nullptr;
    }
    if ((status = env->FindClass(UI_ABILITY_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return nullptr;
    }
    auto workContext = new (std::nothrow) std::weak_ptr<AbilityContext>(context);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "workContext nullptr");
        return nullptr;
    }
    ani_long nativeContextLong = (ani_long)workContext;

    if ((status = env->Object_SetField_Long(contextObj, field, nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        delete workContext;
        workContext = nullptr;
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

void StsAbilityContext::AddFreeInstallObserver(ani_env *env, const AAFwk::Want &want, ani_object callback,
    const std::shared_ptr<AbilityContext> &context, bool isOpenLink)
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
            TAG_LOGE(AAFwkTag::STSRUNTIME, "status: %{public}d", status);
        }
        freeInstallObserver_ = new StsFreeInstallObserver(etsVm);
        ret = context->AddFreeInstallObserver(freeInstallObserver_);
    }
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "addFreeInstallObserver error");
    }
    std::string startTime = want.GetStringParam(AAFwk::Want::PARAM_RESV_START_TIME);
    if (isOpenLink) {
        std::string url = want.GetUriString();
        freeInstallObserver_->AddStsObserverObject(env, startTime, url, callback);
        return;
    }
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
    ErrCode innerErrCode = ERR_OK;
    if (opt != nullptr) {
        AAFwk::StartOptions startOptions;
        OHOS::AppExecFwk::UnwrapStartOptionsWithProcessOption(env, opt, startOptions);
        innerErrCode = context->StartAbility(want, startOptions, -1);
    } else {
        innerErrCode = context->StartAbility(want, -1);
    }
    ani_object aniObject = CreateStsError(env, AbilityErrorCode::ERROR_OK);
    if (innerErrCode != ERR_OK) {
        aniObject = CreateStsErrorByNativeErr(env, innerErrCode);
    }
    if ((want.GetFlags() & AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == AAFwk::Want::FLAG_INSTALL_ON_DEMAND) {
        if (innerErrCode != ERR_OK && freeInstallObserver_ != nullptr) {
            std::string bundleName = want.GetElement().GetBundleName();
            std::string abilityName = want.GetElement().GetAbilityName();
            std::string startTime = want.GetStringParam(AAFwk::Want::PARAM_RESV_START_TIME);
            freeInstallObserver_->OnInstallFinished(bundleName, abilityName, startTime, innerErrCode);
        }
    } else {
        AppExecFwk::AsyncCallback(env, call, aniObject, nullptr);
    }
}

void StsAbilityContext::StartAbility1([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
    ani_object wantObj, ani_object call)
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
        TAG_LOGE(AAFwkTag::STSRUNTIME, "status: %{public}d", status);
        return;
    }
    RuntimeTask task = [etsVm, callbackRef, element = want.GetElement(), flags = want.GetFlags(), startTime]
        (int resultCode, const AAFwk::Want &want, bool isInner) {
        TAG_LOGD(AAFwkTag::CONTEXT, "start async callback");
        ani_status status = ANI_ERROR;
        ani_env *env = nullptr;
        if ((status = etsVm->GetEnv(ANI_VERSION_1, &env)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "status: %{public}d", status);
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
        AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
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
        AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    ErrCode ret = context->TerminateSelf();
    if (ret == static_cast<ErrCode>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT) || ret == ERR_OK) {
        aniObject = CreateStsError(env, static_cast<AbilityErrorCode>(ret));
    } else {
        aniObject = CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret));
    }
    AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
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
        AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
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
    AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
}

void StsAbilityContext::reportDrawnCompletedSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
    ani_object callback)
{
    ani_object aniObject = nullptr;
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    auto context = GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "context null");
        aniObject = CreateStsInvalidParamError(env, "context null");
        AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    ErrCode ret = context->ReportDrawnCompleted();
    if (ret == ERR_OK) {
        aniObject = CreateStsError(env, static_cast<AbilityErrorCode>(ret));
    } else {
        aniObject = CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret));
    }
    AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
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
    ErrCode innerErrCode = ERR_OK;
    std::shared_ptr<StsUIExtensionCallback> callback = std::make_shared<StsUIExtensionCallback>();
    callback->SetStsCallbackObject(aniVM, startCallback);
    innerErrCode = context->StartAbilityByType(type, wantParam, callback);
    if (innerErrCode == ERR_OK) {
        return aniObject;
    } else if (innerErrCode == static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT)) {
        return CreateStsError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    } else {
        return CreateStsErrorByNativeErr(env, innerErrCode);
    }
}

void StsAbilityContext::StartServiceExtensionAbilitySync([[maybe_unused]]ani_env *env,
    [[maybe_unused]]ani_object aniObj, [[maybe_unused]] ani_object wantObj, [[maybe_unused]] ani_object callbackobj)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "call");
    ani_object errorObject = nullptr;
    ErrCode ret = ERR_OK;
    auto context = StsAbilityContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "GetAbilityContext is nullptr");
        ret = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        errorObject = CreateStsError(env, static_cast<AbilityErrorCode>(ret));
        AppExecFwk::AsyncCallback(env, callbackobj, errorObject, nullptr);
        return;
    }
    AAFwk::Want want;
    if (!OHOS::AppExecFwk::UnwrapWant(env, wantObj, want)) {
        TAG_LOGE(AAFwkTag::UIABILITY, "UnwrapWant filed");
        errorObject = CreateStsInvalidParamError(env, "UnwrapWant filed");
        AppExecFwk::AsyncCallback(env, callbackobj, errorObject, nullptr);
    }
    ret = context->StartServiceExtensionAbility(want);
    if (ret == ERR_OK) {
        errorObject = CreateStsError(env, static_cast<AbilityErrorCode>(ret));
    } else {
        errorObject = CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret));
    }
    AppExecFwk::AsyncCallback(env, callbackobj, errorObject, nullptr);
}

ani_object StsAbilityContext::StartAbilityByCall(ani_env *env, ani_object aniObj, ani_object wantObj)
{
    TAG_LOGI(AAFwkTag::UIABILITY, "StartAbilityByCall");
    auto context = GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "GetAbilityContext is nullptr");
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        return nullptr;
    }

    AAFwk::Want want;
    if (!AppExecFwk::UnwrapWant(env, wantObj, want)) {
        TAG_LOGE(AAFwkTag::UIABILITY, "parse want failed");
        ThrowStsInvalidParamError(env, "Parse param want failed, want must be Want.");
        return nullptr;
    }
    auto callData = std::make_shared<StartAbilityByCallData>();
    auto callerCallBack = std::make_shared<CallerCallBack>();
    GenerateCallerCallBack(callData, callerCallBack);
    auto ret = context->StartAbilityByCall(want, callerCallBack, -1);
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::UIABILITY, "startAbility failed");
        ThrowStsErrorByNativeErr(env, ret);
        return nullptr;
    }
    WaitForCalleeObj(callData);

    if (callData->remoteCallee == nullptr) {
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return nullptr;
    }

    std::weak_ptr<AbilityContext> abilityContext(context);
    auto releaseCallFunc = [abilityContext] (std::shared_ptr<CallerCallBack> callback) -> ErrCode {
        auto contextForRelease = abilityContext.lock();
        if (contextForRelease == nullptr) {
            return -1;
        }
        return contextForRelease->ReleaseCall(callback);
    };
    auto caller = CreateEtsCaller(env, releaseCallFunc, callData->remoteCallee, callerCallBack);
    if (caller == nullptr) {
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
    }
    return caller;
}

void StsAbilityContext::NativeOpenLinkSync(ani_env *env, ani_object aniObj, ani_string aniLink,
    ani_object myCallbackobj, ani_object optionsObj, ani_object callbackobj)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "NativeOpenLinkSync");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_boolean isOptionsUndefined = true;
    if ((status = env->Reference_IsUndefined(optionsObj, &isOptionsUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
    }
    ani_boolean isCallbackUndefined = true;
    if ((status = env->Reference_IsUndefined(callbackobj, &isCallbackUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
    }
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
    }
    GetInstance().OpenLinkInner(env, aniObj, aniLink, myCallbackobj, optionsObj, callbackobj,
        !isOptionsUndefined, !isCallbackUndefined);
}

void StsAbilityContext::NativeRestoreWindowStage(ani_env *env, ani_object aniObj, ani_object localStorage)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "NativeRestoreWindowStage");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    auto context = StsAbilityContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        return;
    }
    ani_status status = ANI_ERROR;
    ani_boolean isLocalStorageUndefined = true;
    if ((status = env->Reference_IsUndefined(localStorage, &isLocalStorageUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return;
    }
    if (isLocalStorageUndefined) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null localStorage");
        ThrowStsTooFewParametersError(env);
        return;
    }
    ani_ref global = nullptr;
    if ((status = env->GlobalReference_Create(localStorage, &global)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        return;
    }
    STSNativeReferenceWrapper* etsNativeRef = nullptr;
    etsNativeRef = new STSNativeReferenceWrapper();
    etsNativeRef->ref_ = std::make_shared<STSNativeReference>();
    etsNativeRef->ref_->aniRef = global;
    auto errcode = context->RestoreWindowStage(etsNativeRef);
    if (errcode != 0) {
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
}

bool StsAbilityContext::NativeIsTerminating(ani_env *env, ani_object aniObj)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "NativeIsTerminating");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return false;
    }
    auto context = StsAbilityContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        return false;
    }
    return context->IsTerminating();
}

void StsAbilityContext::NativeMoveAbilityToBackground(ani_env *env, ani_object aniObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "NativeMoveAbilityToBackground");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    auto context = StsAbilityContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT)), nullptr);
        return;
    }
    ErrCode ret = ERR_OK;
    ani_object errorObject = nullptr;
    ret = context->MoveUIAbilityToBackground();
    errorObject = CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret));
    AppExecFwk::AsyncCallback(env, callback, errorObject, nullptr);
}

void StsAbilityContext::NativeRequestModalUIExtension(ani_env *env, ani_object aniObj,
    ani_string pickerWantObj, ani_object callbackObj)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "NativeRequestModalUIExtension");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    ani_object errorObject = nullptr;
    AAFwk::Want want;
    if (!AppExecFwk::UnwrapWant(env, pickerWantObj, want)) {
        TAG_LOGE(AAFwkTag::UIABILITY, "parse want failed");
        ThrowStsInvalidParamError(env, "Parse param want failed, want must be Want.");
        return;
    }
    auto context = StsAbilityContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        errorObject = CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
        AppExecFwk::AsyncCallback(env, callbackObj, errorObject, nullptr);
        return;
    }

    ErrCode ret = ERR_OK;
    ret = AAFwk::AbilityManagerClient::GetInstance()->RequestModalUIExtension(want);
    errorObject = CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret));
    AppExecFwk::AsyncCallback(env, callbackObj, errorObject, nullptr);
}

bool BindNativeMethods(ani_env *env, ani_class &cls)
{
    ani_status status = env->FindClass(UI_ABILITY_CONTEXT_CLASS_NAME, &cls);
    if (status != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return false;
    }
    std::call_once(g_bindNativeMethodsFlag, [&status, env, cls]() {
        std::array functions = {
            ani_native_function { "nativeStartAbilitySync",
                "L@ohos/app/ability/Want/Want;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
                reinterpret_cast<void*>(StsAbilityContext::StartAbility1) },
            ani_native_function { "nativeStartAbilitySync",
                "L@ohos/app/ability/Want/Want;L@ohos/app/ability/StartOptions/StartOptions;Lutils/AbilityUtils/"
                "AsyncCallbackWrapper;:V",
                reinterpret_cast<void*>(StsAbilityContext::StartAbility2) },
            ani_native_function { "nativeStartAbilityForResult",
                "L@ohos/app/ability/Want/Want;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
                reinterpret_cast<void*>(StsAbilityContext::StartAbilityForResult1) },
            ani_native_function { "nativeStartAbilityForResult",
                "L@ohos/app/ability/Want/Want;L@ohos/app/ability/StartOptions/StartOptions;Lutils/AbilityUtils/"
                "AsyncCallbackWrapper;:V",
                reinterpret_cast<void*>(StsAbilityContext::StartAbilityForResult2) },
            ani_native_function { "nativeTerminateSelfSync", "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
                reinterpret_cast<void*>(StsAbilityContext::TerminateSelf) },
            ani_native_function { "nativeTerminateSelfWithResult",
                "Lability/abilityResult/AbilityResult;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
                reinterpret_cast<void*>(StsAbilityContext::TerminateSelfWithResult) },
            ani_native_function { "nativeReportDrawnCompletedSync", "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
                reinterpret_cast<ani_int*>(StsAbilityContext::reportDrawnCompletedSync) },
            ani_native_function { "nativeStartAbilityByTypeSync", nullptr,
                reinterpret_cast<void*>(StsAbilityContext::StartAbilityByTypeSync) },
            ani_native_function { "nativeStartServiceExtensionAbilitySync", nullptr,
                reinterpret_cast<void*>(StsAbilityContext::StartServiceExtensionAbilitySync) },
            ani_native_function { "nativeStartAbilityByCallSync",
                "L@ohos/app/ability/Want/Want;:L@ohos/app/ability/UIAbility/Caller;",
                reinterpret_cast<void*>(StsAbilityContext::StartAbilityByCall) },
            ani_native_function { "nativeOpenLinkSync", nullptr,
                reinterpret_cast<void*>(StsAbilityContext::NativeOpenLinkSync) },
            ani_native_function { "nativeRestoreWindowStage", nullptr,
                reinterpret_cast<void*>(StsAbilityContext::NativeRestoreWindowStage) },
            ani_native_function { "nativeIsTerminating", nullptr,
                reinterpret_cast<void*>(StsAbilityContext::NativeIsTerminating) },
            ani_native_function { "nativeMoveAbilityToBackground", nullptr,
                reinterpret_cast<void*>(StsAbilityContext::NativeMoveAbilityToBackground) },
            ani_native_function { "nativeRequestModalUIExtension", nullptr,
                reinterpret_cast<void*>(StsAbilityContext::NativeRequestModalUIExtension) },
        };
        status = env->Class_BindNativeMethods(cls, functions.data(), functions.size());
    });
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return false;
    }
    return true;
}

void StsAbilityContext::OpenLinkInner(ani_env *env, ani_object aniObj, ani_string aniLink, ani_object myCallbackobj,
    ani_object optionsObj, ani_object callbackobj, bool haveOptionsParm, bool haveCallBackParm)
{
    ani_object aniObject = nullptr;
    std::string link("");
    AAFwk::OpenLinkOptions openLinkOptions;
    AAFwk::Want want;
    want.SetParam(APP_LINKING_ONLY, false);
    if (!AppExecFwk::GetStdString(env, aniLink, link)) {
        TAG_LOGE(AAFwkTag::UIABILITY, "parse link failed");
        aniObject = CreateStsInvalidParamError(env, "Parse param link failed, link must be string.");
        AppExecFwk::AsyncCallback(env, myCallbackobj, aniObject, nullptr);
        return;
    }
    if (haveOptionsParm) {
        TAG_LOGD(AAFwkTag::UIABILITY, "OpenLink Have option");
        StsAbilityContext::UnWrapOpenLinkOptions(env, optionsObj, openLinkOptions, want);
    }
    want.SetUri(link);
    std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
        system_clock::now().time_since_epoch()).count());
    want.SetParam(AAFwk::Want::PARAM_RESV_START_TIME, startTime);
    int requestCode = -1;
    ErrCode ErrCode = ERR_OK;
    auto context = StsAbilityContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "GetAbilityContext is nullptr");
        ErrCode = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        aniObject = CreateStsError(env, static_cast<AbilityErrorCode>(ErrCode));
        AppExecFwk::AsyncCallback(env, myCallbackobj, aniObject, nullptr);
        return;
    }
    AddFreeInstallObserver(env, want, myCallbackobj, context, true);
    if (haveCallBackParm) {
        TAG_LOGD(AAFwkTag::UIABILITY, "OpenLink Have Callback");
        CreateOpenLinkTask(env, callbackobj, context, want, requestCode);
    }
    ErrCode = context->OpenLink(want, requestCode);
    if (ErrCode == AAFwk::ERR_OPEN_LINK_START_ABILITY_DEFAULT_OK) {
        aniObject = CreateStsError(env, static_cast<AbilityErrorCode>(ERR_OK));
    } else {
        aniObject = CreateStsErrorByNativeErr(env, static_cast<int32_t>(ErrCode));
    }
    AppExecFwk::AsyncCallback(env, myCallbackobj, aniObject, nullptr);
}

void StsAbilityContext::UnWrapOpenLinkOptions(ani_env *env, ani_object optionsObj,
    AAFwk::OpenLinkOptions &openLinkOptions, AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "UnWrapOpenLinkOptions");
    ani_status status = ANI_ERROR;
    ani_ref ParamRef = nullptr;
    if ((status = env->Object_GetPropertyByName_Ref(optionsObj, "parameters", &ParamRef))  == ANI_OK) {
        AAFwk::WantParams wantParam;
        if (AppExecFwk::UnwrapWantParams(env, ParamRef, wantParam)) {
            want.SetParams(wantParam);
        } else {
            TAG_LOGE(AAFwkTag::UIABILITY, "UnwrapWantParams failed");
        }
    }
    if ((status = env->Object_GetPropertyByName_Ref(optionsObj, APP_LINKING_ONLY.c_str(), &ParamRef))  == ANI_OK) {
        bool appLinkingOnly = AppExecFwk::GetBoolOrUndefined(env, optionsObj, "appLinkingOnly");
        openLinkOptions.SetAppLinkingOnly(appLinkingOnly);
        want.SetParam(APP_LINKING_ONLY, appLinkingOnly);
    }
    if (!want.HasParameter(APP_LINKING_ONLY)) {
        want.SetParam(APP_LINKING_ONLY, false);
    }
}

void StsAbilityContext::CreateOpenLinkTask(ani_env *env, const ani_object callbackobj,
    std::shared_ptr<AbilityContext> context, AAFwk::Want &want, int &requestCode)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "CreateOpenLinkTask");
    want.SetParam(AAFwk::Want::PARAM_RESV_FOR_RESULT, true);
    ani_vm *etsVm = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GetVM(&etsVm)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "status: %{public}d", status);
        return;
    }
    ani_ref callbackRef = nullptr;
    if ((status = env->GlobalReference_Create(callbackobj, &callbackRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return;
    }
    RuntimeTask task = [etsVm, callbackRef] (int resultCode, const AAFwk::Want &want, bool isInner) {
    TAG_LOGD(AAFwkTag::CONTEXT, "start async callback");
    ani_status status = ANI_ERROR;
    ani_env *env = nullptr;
    if ((status = etsVm->GetEnv(ANI_VERSION_1, &env)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "status: %{public}d", status);
        return;
    }
    ani_object abilityResult = AppExecFwk::WrapAbilityResult(env, resultCode, want);
    if (abilityResult == nullptr) {
        TAG_LOGW(AAFwkTag::CONTEXT, "null abilityResult");
        isInner = true;
        resultCode = ERR_INVALID_VALUE;
    }
    auto errCode = isInner ? resultCode : 0;
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, errCode), abilityResult);
    };
    requestCode = GenerateRequestCode();
    context->InsertResultCallbackTask(requestCode, std::move(task));
}

bool SetAbilityInfo(ani_env *env, ani_class cls, ani_object contextObj, const std::shared_ptr<AbilityContext> &context)
{
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env or context");
        return false;
    }
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
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env or context");
        return false;
    }
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

bool SetHapModuleInfo(
    ani_env *env, ani_class cls, ani_object contextObj, const std::shared_ptr<AbilityContext> &context)
{
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env or context");
        return false;
    }
    ani_status status = ANI_OK;
    auto hapModuleInfo = context->GetHapModuleInfo();
    if (hapModuleInfo == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "hapModuleInfo is nullptr");
        return false;
    }
    ani_ref hapModuleInfoRef = AppExecFwk::CommonFunAni::ConvertHapModuleInfo(env, *hapModuleInfo);
    if (hapModuleInfoRef != nullptr) {
        status = env->Object_SetPropertyByName_Ref(contextObj, "currentHapModuleInfo", hapModuleInfoRef);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::ABILITY, "Object_SetPropertyByName_Ref failed, status: %{public}d", status);
            return false;
        }
    }
    return true;
}


ani_ref CreateStsAbilityContext(
    ani_env *env, const std::shared_ptr<AbilityContext> &context, const std::shared_ptr<OHOSApplication> &application)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env or context");
        return nullptr;
    }
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
    if (!SetHapModuleInfo(env, cls, contextObj, context)) {
        TAG_LOGE(AAFwkTag::UIABILITY, "SetHapModuleInfo failed");
        return nullptr;
    }
    return contextObj;
}
} // namespace AbilityRuntime
} // namespace OHOS
