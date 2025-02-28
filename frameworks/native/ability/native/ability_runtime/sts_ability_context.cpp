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
#include "ani_common/ani_common_start_options.h"
#include "app_utils.h"
#include "event_handler.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "sts_data_struct_converter.h"
#include "mission_info.h"
#include "ani_common/ani_common_want.h"
#include "open_link_options.h"
#include "open_link/napi_common_open_link_options.h"
#include "start_options.h"
#include "tokenid_kit.h"
#include "ui_ability_servicehost_stub_impl.h"
#include "ui_service_extension_connection_constants.h"
#include "uri.h"
#include "want.h"

#ifdef SUPPORT_GRAPHICS
#include "pixel_map_napi.h"
#endif

namespace OHOS {
namespace AbilityRuntime {

static ani_int startAbilityByCall(
    [[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj, ani_object wantObj, ani_object call)
{
    TAG_LOGE(AAFwkTag::UIABILITY, "start");
    ani_long nativeContextLong;
    ani_class cls = nullptr;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;

    if ((status = env->FindClass("LUIAbilityContext/UIAbilityContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_GetField_Long(aniObj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    TAG_LOGE(AAFwkTag::UIABILITY, "nativeContext %{public}lld", nativeContextLong);
    ani_class clsCall = nullptr;
    if ((status = env->FindClass("LUIAbilityContext/AsyncCallback;", &clsCall)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    static constexpr const char *LAMBDA_METHOD_NAME = "invoke";
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(clsCall, LAMBDA_METHOD_NAME, "I:V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    ani_int result = 111;
    if ((status = env->Object_CallMethod_Void(call, method, result)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    AAFwk::Want *want = new (std::nothrow) AAFwk::Want();
    OHOS::AppExecFwk::UnwrapWant(env, wantObj, *want);
    ((AbilityRuntime::AbilityContext*)nativeContextLong)->StartAbility(*want, -1);
    TAG_LOGE(AAFwkTag::UIABILITY, "end");
    return -1;
}

static ani_int startAbility([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj, ani_object wantObj)
{
    TAG_LOGE(AAFwkTag::UIABILITY, "start");
    ani_long nativeContextLong;
    ani_class cls = nullptr;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;

    if ((status = env->FindClass("LUIAbilityContext/UIAbilityContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_GetField_Long(aniObj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    TAG_LOGE(AAFwkTag::UIABILITY, "nativeContext %{public}lld", nativeContextLong);

    AAFwk::Want *want = new (std::nothrow) AAFwk::Want();
    OHOS::AppExecFwk::UnwrapWant(env, wantObj, *want);
    ((AbilityRuntime::AbilityContext*)nativeContextLong)->StartAbility(*want, -1);

    TAG_LOGE(AAFwkTag::UIABILITY, "end");
    return -1;
}

static void InvokeAsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result)
{
    ani_class clsCall = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("LUIAbilityContext/AsyncCallback;", &clsCall)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(clsCall, "invoke",
        "LUIAbilityContext/BusinessError;Lstd/core/Object;:V",&method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return;
    }
    if ((status = env->Object_CallMethod_Void(call, method, error, result)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return;
    }
}

static AbilityRuntime::AbilityContext* GetAbilityContext(ani_env *env, ani_object aniObj)
{
    ani_long nativeContextLong = 0;
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
    TAG_LOGE(AAFwkTag::UIABILITY, "nativeContext %{public}lld", nativeContextLong);
    return reinterpret_cast<AbilityRuntime::AbilityContext*>(nativeContextLong);
}

static ani_object WrapAbilityResult(ani_env *env, ani_int code)
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

static ani_object WrapBusinessError(ani_env *env, ani_int code)
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

static std::mutex requestCodeMutex_;
static int32_t GenerateRequestCode()
{
    static int32_t curRequestCode_ = 0;
    std::lock_guard lock(requestCodeMutex_);
    curRequestCode_ = (curRequestCode_ == INT_MAX) ? 0 : (curRequestCode_ + 1);
    return curRequestCode_;
}

// TO DO: free install
static void StartAbilityForResultInner(ani_env *env, ani_object aniObj, ani_object wantObj,
    ani_object startOptionsObj, ani_object callback)
{
    auto context = GetAbilityContext(env, aniObj);
    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(env, wantObj, want);
    AAFwk::StartOptions startOptions;
    if (startOptionsObj) {
        OHOS::AppExecFwk::AniUnwrapStartOptions(env, startOptionsObj, startOptions);
    }
    std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
        system_clock::now().time_since_epoch()).count());
    RuntimeTask task = [env, callback, element = want.GetElement(), flags = want.GetFlags(), startTime]
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
        InvokeAsyncCallback(env, callback, WrapBusinessError(env, 0), abilityResult);
    };
    auto requestCode = GenerateRequestCode();
    (startOptionsObj == nullptr) ? context->StartAbilityForResult(want, requestCode, std::move(task)) :
        context->StartAbilityForResult(want, startOptions, requestCode, std::move(task));
    return;
}

// TO DO: free install
static void StartAbilityForResult1(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object callback)
{
    TAG_LOGE(AAFwkTag::UIABILITY, "start");
    StartAbilityForResultInner(env, aniObj, wantObj, nullptr, callback);
}

// TO DO: free install
static void StartAbilityForResult2(ani_env *env, ani_object aniObj, ani_object wantObj,
    ani_object startOptionsObj, ani_object callback)
{
    TAG_LOGE(AAFwkTag::UIABILITY, "start");
    StartAbilityForResultInner(env, aniObj, wantObj, startOptionsObj, callback);
}

static void terminateSelfSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class aniClass)
{
    TAG_LOGE(AAFwkTag::UIABILITY, "terminateSelfSynccpp 111");
    ani_class cls = nullptr;
    ani_long nativeContextLong;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;

    if ((status = env->FindClass("LUIAbilityContext/UIAbilityContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }

    if ((status = env->Object_GetField_Long(aniClass, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    TAG_LOGE(AAFwkTag::UIABILITY, "nativeContext %{public}lld", nativeContextLong);

    TAG_LOGE(AAFwkTag::UIABILITY, "terminateSelfSynccpp 222");
    ((AbilityRuntime::AbilityContext*)nativeContextLong)->TerminateSelf();
    TAG_LOGE(AAFwkTag::UIABILITY, "terminateSelfSynccpp end");
}

static void terminateSelfSyncPromise([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class aniClass)
{
    TAG_LOGE(AAFwkTag::UIABILITY, "terminateSelfSyncPromise 111");
    ani_class cls = nullptr;
    ani_long nativeContextLong;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;

    if ((status = env->FindClass("LUIAbilityContext/UIAbilityContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }

    if ((status = env->Object_GetField_Long(aniClass, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    TAG_LOGE(AAFwkTag::UIABILITY, "nativeContext %{public}lld", nativeContextLong);

    TAG_LOGE(AAFwkTag::UIABILITY, "terminateSelfSyncPromise 222");
    ((AbilityRuntime::AbilityContext*)nativeContextLong)->TerminateSelf();
    TAG_LOGE(AAFwkTag::UIABILITY, "terminateSelfSyncPromise end");
}

static void reportDrawnCompletedSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class aniClass)
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
    TAG_LOGE(AAFwkTag::UIABILITY, "nativeContext %{public}lld", nativeContextLong);

    TAG_LOGE(AAFwkTag::UIABILITY, "reportDrawnCompletedSync 222");
    ((AbilityRuntime::AbilityContext*)nativeContextLong)->ReportDrawnCompleted();
    TAG_LOGE(AAFwkTag::UIABILITY, "reportDrawnCompletedSync end");
}

ani_ref CreateStsAbilityContext(ani_env *env, const std::shared_ptr<AbilityContext> &context)
{
    TAG_LOGE(AAFwkTag::UIABILITY, "start");
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_field field = nullptr;
    ani_object contextObj = nullptr;

    if ((env->FindClass("LUIAbilityContext/UIAbilityContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    std::array functions = {
        ani_native_function { "startAbilitySync", "L@ohos/app/ability/Want/Want;LUIAbilityContext/AsyncCallback;:I",
            reinterpret_cast<ani_int*>(startAbilityByCall) },
        ani_native_function {
            "startAbilitySync", "L@ohos/app/ability/Want/Want;:I", reinterpret_cast<ani_int*>(startAbility) },
        ani_native_function {
            "nativeStartAbilityForResult", "L@ohos/app/ability/Want/Want;LUIAbilityContext/AsyncCallback;:V",
            reinterpret_cast<void*>(StartAbilityForResult1) },
        ani_native_function {
            "nativeStartAbilityForResult",
            "L@ohos/app/ability/Want/Want;L@ohos/app/ability/StartOptions/StartOptions;LUIAbilityContext/AsyncCallback;:V",
            reinterpret_cast<void*>(StartAbilityForResult2) },
        ani_native_function { "terminateSelfSync", ":V", reinterpret_cast<ani_int*>(terminateSelfSync) },
        ani_native_function { "terminateSelfSyncPromise", ":V", reinterpret_cast<ani_int*>(terminateSelfSyncPromise) },
        ani_native_function { "reportDrawnCompletedSync", ":V", reinterpret_cast<ani_int*>(reportDrawnCompletedSync) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
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
    ani_long nativeContextLong = (ani_long)context.get();
    if ((status = env->Object_SetField_Long(contextObj, field, nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    TAG_LOGE(AAFwkTag::UIABILITY, "end");
    return contextObj;
}
} // namespace AbilityRuntime
} // namespace OHOS
