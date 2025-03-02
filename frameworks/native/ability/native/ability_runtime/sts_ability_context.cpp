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
#include "app_utils.h"
#include "event_handler.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "sts_data_struct_converter.h"
#include "mission_info.h"
#include "ani_common/ani_common_want.h"
#include "ani_common/ani_common_start_options.h"
#include "ani_common/ani_common_configuration.h"
#include "ani_common/ani_common_ability_info.h"
#include "open_link_options.h"
#include "start_options.h"
#include "tokenid_kit.h"
#include "ui_ability_servicehost_stub_impl.h"
#include "ui_service_extension_connection_constants.h"
#include "uri.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
const char *INVOKE_METHOD_NAME = "invoke";
std::mutex StsAbilityContext::requestCodeMutex_;


AbilityRuntime::AbilityContext* StsAbilityContext::GetAbilityContext(ani_env *env, ani_object aniObj)
{
    ani_long nativeContextLong;
    ani_class cls = nullptr;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("LUIAbilityContext/UIAbilityContext;", &cls)) != ANI_OK) {
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
    return ((AbilityRuntime::AbilityContext*)nativeContextLong);
}

ani_object StsAbilityContext::SetAbilityContext(ani_env *env, const std::shared_ptr<AbilityContext> &context)
{
    ani_long nativeContextLong = (ani_long)context.get();
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_object contextObj = nullptr;
    ani_method method = nullptr;
    ani_field field = nullptr;

    if ((status = env->FindClass("LUIAbilityContext/UIAbilityContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_SetField_Long(contextObj, field, nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    return contextObj;
}

void StsAbilityContext::InheritWindowMode(ani_env *env, ani_object aniObj, AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
#ifdef SUPPORT_SCREEN
    // only split mode need inherit
    auto windowMode = GetAbilityContext(env, aniObj)->GetCurrentWindowMode();
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
    ani_class clsCall = nullptr;

    if ((status = env->FindClass("LUIAbilityContext/AsyncCallback;", &clsCall)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(
             clsCall, INVOKE_METHOD_NAME, "LUIAbilityContext/BusinessError;Lstd/core/Object;:V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return false;
    }
    if ((status = env->Object_CallMethod_Void(call, method, error, result)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return false;
    }
    return true;
}

ani_object StsAbilityContext::WrapAbilityResult(ani_env *env, ani_int code)
{
    ani_class cls = nullptr;
    ani_field field = nullptr;
    ani_method method = nullptr;
    ani_object obj = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("LUIAbilityContext/AbilityResult;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", nullptr, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &obj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "resultCode", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetField_Int(obj, field, code)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    return obj;
}

ani_object StsAbilityContext::WrapBusinessError(ani_env *env, ani_int code)
{
    ani_class cls = nullptr;
    ani_field field = nullptr;
    ani_method method = nullptr;
    ani_object obj = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("LUIAbilityContext/BusinessError;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", nullptr, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &obj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "code", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetField_Int(obj, field, code)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    return obj;
}

// TO DO: free install
void StsAbilityContext::StartAbilityInner([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
    ani_object wantObj, ani_object opt, ani_object call)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGE(AAFwkTag::UIABILITY, "start");
    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(env, wantObj, want);

    InheritWindowMode(env, aniObj, want);

    if ((want.GetFlags() & AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == AAFwk::Want::FLAG_INSTALL_ON_DEMAND) {
        std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
            system_clock::now().time_since_epoch()).count());
        want.SetParam(AAFwk::Want::PARAM_RESV_START_TIME, startTime);
    }
    ErrCode resultCode = ERR_INVALID_VALUE;
    if (opt != nullptr) {
        AAFwk::StartOptions startOptions;
        OHOS::AppExecFwk::UnwrapStartOptionsWithProcessOption(env, opt, startOptions);
        resultCode = GetAbilityContext(env, aniObj)->StartAbility(want, startOptions, -1);
    } else {
        resultCode = GetAbilityContext(env, aniObj)->StartAbility(want, -1);
    }

    if ((want.GetFlags() & AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == AAFwk::Want::FLAG_INSTALL_ON_DEMAND) {
        // TODO
    } else {
        ani_object abilityResult = WrapAbilityResult(env, resultCode);
        AsyncCallback(env, call, WrapBusinessError(env, 0), abilityResult);
    }
    TAG_LOGE(AAFwkTag::UIABILITY, "end");
}

void StsAbilityContext::StartAbility1(
    [[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj, ani_object wantObj, ani_object call)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGE(AAFwkTag::UIABILITY, "start");
    StartAbilityInner(env, aniObj, wantObj, nullptr, call);
    TAG_LOGE(AAFwkTag::UIABILITY, "end");
}

void StsAbilityContext::StartAbility2([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object aniObj,
    ani_object wantObj, ani_object opt, ani_object call)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGE(AAFwkTag::UIABILITY, "start");
    StartAbilityInner(env, aniObj, wantObj, opt, call);
    TAG_LOGE(AAFwkTag::UIABILITY, "end");
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
    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(env, wantObj, want);
    AAFwk::StartOptions startOptions;
    if (startOptionsObj) {
        OHOS::AppExecFwk::UnwrapStartOptions(env, startOptionsObj, startOptions);
    }
    std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
        system_clock::now().time_since_epoch()).count());
    ani_ref callbackRef = nullptr;
    env->GlobalReference_Create(callback, &callbackRef);
    RuntimeTask task = [env, callbackRef, element = want.GetElement(), flags = want.GetFlags(), startTime]
        (int resultCode, const AAFwk::Want& want, bool isInner) {
        TAG_LOGD(AAFwkTag::CONTEXT, "start async callback");
        // HandleScope handleScope(env);
        std::string bundleName = element.GetBundleName();
        std::string abilityName = element.GetAbilityName();
        ani_object abilityResult = WrapAbilityResult(env, resultCode);
        // TO DO
        // napi_value abilityResult = AppExecFwk::WrapAbilityResult(env, resultCode, want);
        if (abilityResult == nullptr) {
            TAG_LOGW(AAFwkTag::CONTEXT, "null abilityResult");
            isInner = true;
            resultCode = ERR_INVALID_VALUE;
        }
        AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef), WrapBusinessError(env, 0), abilityResult);
    };
    auto requestCode = GenerateRequestCode();
    TAG_LOGE(AAFwkTag::UIABILITY, "GenerateRequestCode end ");
    (startOptionsObj == nullptr) ? context->StartAbilityForResult(want, requestCode, std::move(task)) :
        context->StartAbilityForResult(want, startOptions, requestCode, std::move(task));
    TAG_LOGE(AAFwkTag::UIABILITY, "end");
    return;
}

// TO DO: free install
void StsAbilityContext::StartAbilityForResult1(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object callback)
{
    TAG_LOGE(AAFwkTag::UIABILITY, "start");
    StartAbilityForResultInner(env, aniObj, wantObj, nullptr, callback);
}

// TO DO: free install
void StsAbilityContext::StartAbilityForResult2(ani_env *env, ani_object aniObj, ani_object wantObj,
    ani_object startOptionsObj, ani_object callback)
{
    TAG_LOGE(AAFwkTag::UIABILITY, "start");
    StartAbilityForResultInner(env, aniObj, wantObj, startOptionsObj, callback);
}

void StsAbilityContext::TerminateSelfWithResult(ani_env *env, ani_object aniObj, ani_object abilityResult, ani_object callback)
{
    TAG_LOGE(AAFwkTag::UIABILITY, "start");

    auto context = StsAbilityContext::GetAbilityContext(env, aniObj);
    AAFwk::Want want;
    int resultCode = 0;
    OHOS::AppExecFwk::UnWrapAbilityResult(env, abilityResult, resultCode, want);

    if (context != nullptr) {
        context->SetTerminating(true);
    }

    auto ret = context->TerminateAbilityWithResult(want, resultCode);
    ani_object result = StsAbilityContext::WrapAbilityResult(env, resultCode);
    AsyncCallback(env, callback, WrapBusinessError(env, ret), result);
    TAG_LOGE(AAFwkTag::UIABILITY, "end");
}

void StsAbilityContext::reportDrawnCompletedSync(
    [[maybe_unused]] ani_env* env, [[maybe_unused]] ani_class aniClass)
{
    ani_class cls = nullptr;
    ani_long nativeContextLong;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    TAG_LOGE(AAFwkTag::UIABILITY, "reportDrawnCompletedSync 111");

    if ((status = env->FindClass("LUIAbilityContext/UIAbilityContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }

    if ((status = env->Object_GetField_Long(aniClass, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    TAG_LOGE(AAFwkTag::UIABILITY, "reportDrawnCompletedSync 222");
    ((AbilityRuntime::AbilityContext*)nativeContextLong)->ReportDrawnCompleted();
    TAG_LOGE(AAFwkTag::UIABILITY, "reportDrawnCompletedSync end");
}

ani_ref CreateStsAbilityContext(ani_env *env, const std::shared_ptr<AbilityContext> &context)
{
    TAG_LOGE(AAFwkTag::UIABILITY, "start");
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;

    if ((env->FindClass("LUIAbilityContext/UIAbilityContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }

    std::array functions = {
        ani_native_function { "nativeStartAbilitySync",
            "L@ohos/app/ability/Want/Want;LUIAbilityContext/AsyncCallback;:V",
            reinterpret_cast<void*>(StsAbilityContext::StartAbility1) },
        ani_native_function { "nativeStartAbilitySync",
            "L@ohos/app/ability/Want/Want;L@ohos/app/ability/StartOptions/StartOptions;LUIAbilityContext/"
            "AsyncCallback;:V",
            reinterpret_cast<void*>(StsAbilityContext::StartAbility2) },
        ani_native_function { "nativeStartAbilityForResult",
            "L@ohos/app/ability/Want/Want;LUIAbilityContext/AsyncCallback;:V",
            reinterpret_cast<void*>(StsAbilityContext::StartAbilityForResult1) },
        ani_native_function { "nativeStartAbilityForResult",
            "L@ohos/app/ability/Want/Want;L@ohos/app/ability/StartOptions/StartOptions;LUIAbilityContext/"
            "AsyncCallback;:V",
            reinterpret_cast<void*>(StsAbilityContext::StartAbilityForResult2) },
        ani_native_function { "nativeTerminateSelfWithResult",
            "LUIAbilityContext/AbilityResult;LUIAbilityContext/AsyncCallback;:V",
            reinterpret_cast<void*>(StsAbilityContext::TerminateSelfWithResult) },
        ani_native_function {
            "reportDrawnCompletedSync", ":V", reinterpret_cast<ani_int*>(StsAbilityContext::reportDrawnCompletedSync) },
    };

    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    ani_object contextObj = StsAbilityContext::SetAbilityContext(env, context);


    ani_field field = nullptr;
    auto abilityInfo = context->GetAbilityInfo();
    ani_ref abilityInfoRef = OHOS::AppExecFwk::WrapAbilityInfo(env, *abilityInfo);
    if ((status = env->Class_FindField(cls, "abilityInfo", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_SetField_Ref(contextObj, field, abilityInfoRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }

    auto configuration = context->GetConfiguration();
    ani_ref configurationRef = OHOS::AppExecFwk::WrapConfiguration(env, *configuration);
    if ((status = env->Class_FindField(cls, "config", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_SetField_Ref(contextObj, field, configurationRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    TAG_LOGE(AAFwkTag::UIABILITY, "end");
    return contextObj;
}
} // namespace AbilityRuntime
} // namespace OHOS
