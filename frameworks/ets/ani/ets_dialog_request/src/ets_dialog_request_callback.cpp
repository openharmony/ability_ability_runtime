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

#include "ets_dialog_request_callback.h"

#include "hilog_tag_wrapper.h"
#include "ets_context_utils.h"
#include "ets_error_utils.h"
#include "js_runtime_utils.h"
#include "ani_common_want.h"
#include "ani_common_util.h"
#include "ani_enum_convert.h"

namespace OHOS {
namespace AbilityRuntime {
EtsDialogRequestCallback *EtsDialogRequestCallback::GetEtsDialogReqCallback(ani_env *env, ani_object aniObj)
{
    if (env == nullptr || aniObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null env or aniObj");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return nullptr;
    }
    ani_long dialogReqCallbackPtr = 0;
    ani_status status = env->Object_GetFieldByName_Long(aniObj, "nativeRequestCallback", &dialogReqCallbackPtr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "nativeRequestCallback GetField status: %{public}d", status);
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        return nullptr;
    }
    auto dialogReqCallback = reinterpret_cast<EtsDialogRequestCallback *>(dialogReqCallbackPtr);
    if (dialogReqCallback == nullptr) {
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        TAG_LOGE(AAFwkTag::CONTEXT, "dialogReqCallback null");
    }
    return dialogReqCallback;
}
void EtsDialogRequestCallback::SetRequestResult(ani_env *env, ani_object param, ani_object result)
{
    if (env == nullptr || result == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null %{public}s", ((env == nullptr) ? "env" : "result"));
        return;
    }
    auto dialogReqCallback = GetEtsDialogReqCallback(env, param);
    if (dialogReqCallback == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "dialogReqCallback null");
        return;
    }
    dialogReqCallback->OnSetRequestResult(env, param, result);
}
void EtsDialogRequestCallback::OnSetRequestResult(ani_env *env, ani_object param, ani_object result)
{
    TAG_LOGI(AAFwkTag::DIALOG, "call");
    ani_boolean isResultCodeUndefined = true;
    ani_ref resultCodeRef = nullptr;
    if (AppExecFwk::GetPropertyRef(env, result, "result",
        resultCodeRef, isResultCodeUndefined) && isResultCodeUndefined) {
        TAG_LOGE(AAFwkTag::DIALOG, " resultCode is undefined");
        return;
    }
    int32_t resultCode = 0;
    ani_boolean isConvertSucess = false;
    isConvertSucess = AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(
        env, reinterpret_cast<ani_enum_item>(resultCodeRef), resultCode);
    if (!isConvertSucess) {
        TAG_LOGE(AAFwkTag::DIALOG, "Convert result failed");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return;
    }
    TAG_LOGD(AAFwkTag::DIALOG, "processMode: %{public}d", resultCode);
    AAFwk::Want wantValue;
    ani_boolean isWantUndefined = true;
    ani_ref wantObject = nullptr;
    if (AppExecFwk::GetPropertyRef(env, result, "want", wantObject, isWantUndefined) && !isWantUndefined) {
        AppExecFwk::UnwrapWant(env, static_cast<ani_object>(wantObject), wantValue);
    } else {
        TAG_LOGW(AAFwkTag::DIALOG, "want is undefined");
    }
    sptr<IDialogRequestCallback> callback = callback_;
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "callback is null");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    callback->SendResult(resultCode, wantValue);
    return;
}

ani_object CreateEtsDialogRequestCallback(ani_env *env, const sptr<IDialogRequestCallback> &remoteObj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null env");
        return nullptr;
    }
    ani_object object = nullptr;
    ani_method method = nullptr;
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    status = env->FindClass("@ohos.app.ability.dialogRequest.dialogRequest.RequestCallbackInner", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "FindClass failed, status = %{public}d", status);
        return nullptr;
    }
    status = env->Class_FindMethod(cls, "<ctor>", "l:", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "FindMethod failed, status = %{public}d", status);
        return nullptr;
    }
    auto etsDialogRequestCallback = std::make_unique<EtsDialogRequestCallback>(remoteObj);
    ani_long ptr = reinterpret_cast<ani_long>(etsDialogRequestCallback.release());
    status = env->Object_New(cls, method, &object, ptr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "ObjectNew failed, status = %{public}d", status);
        return nullptr;
    }

    std::array methods = {
        ani_native_function {"setRequestResult", nullptr,
            reinterpret_cast<void *>(EtsDialogRequestCallback::SetRequestResult)},
    };
    
    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK && status != ANI_ALREADY_BINDED) {
        TAG_LOGE(AAFwkTag::DIALOG, "Class_BindNativeMethod failed, status = %{public}d", status);
        return nullptr;
    }

    return object;
}
} // AbilityRuntime
} // OHOS
