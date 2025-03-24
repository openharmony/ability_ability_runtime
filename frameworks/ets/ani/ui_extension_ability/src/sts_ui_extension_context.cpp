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
#include "sts_ui_extension_context.h"
#include "ui_extension_context.h"
#include "ani_common_want.h"
#include "ability_manager_client.h"
static void TerminateSelfSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object obj,
    [[maybe_unused]] ani_object callback)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "terminateSelfSync start");
    ani_class cls = nullptr;
    ani_long nativeContextLong;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    OHOS::ErrCode ret = OHOS::ERR_INVALID_VALUE;
    if ((status = env->FindClass("Lapplication/UIExtensionContext/UIExtensionContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "terminateSelfSync find class status : %{public}d", status);
    }
    if ((status = env->Class_FindField(cls, "nativeUIExtensionContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "terminateSelfSync find field status : %{public}d", status);
    }
    if ((status = env->Object_GetField_Long(obj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "terminateSelfSync get filed status : %{public}d", status);
    }
    TAG_LOGE(AAFwkTag::UI_EXT, "nativeUIExtensionContext %{public}lld", nativeContextLong);
    ret = ((OHOS::AbilityRuntime::UIExtensionContext*)nativeContextLong)->TerminateSelf();
    StsUIExtensionContext::AsyncCallback(env, callback,
        StsUIExtensionContext::WrapBusinessError(env, static_cast<int32_t>(ret)), nullptr);
    TAG_LOGE(AAFwkTag::UI_EXT, "terminateSelfSync end");
}
static void TerminateSelfWithResultSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object obj,
    [[maybe_unused]] ani_object abilityResult, [[maybe_unused]] ani_object callback)
{
    TAG_LOGE(AAFwkTag::UI_EXT, "TerminateSelfWithResult start");
    ani_class cls = nullptr;
    ani_long nativeContextLong;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    OHOS::ErrCode ret = OHOS::ERR_INVALID_VALUE;
    if ((status = env->FindClass("Lapplication/UIExtensionContext/UIExtensionContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "TerminateSelfWithResult find class status : %{public}d", status);
    }
    if ((status = env->Class_FindField(cls, "nativeUIExtensionContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "TerminateSelfWithResult find field status : %{public}d", status);
    }
    if ((status = env->Object_GetField_Long(obj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "TerminateSelfWithResult get filed status : %{public}d", status);
    }
    TAG_LOGE(AAFwkTag::UI_EXT, "nativeUIExtensionContext %{public}lld", nativeContextLong);
    auto context = ((OHOS::AbilityRuntime::UIExtensionContext*)nativeContextLong);
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "TerminateSelfWithResult context is released");
    }

    OHOS::AAFwk::Want want;
    int resultCode = 0;
    OHOS::AppExecFwk::UnWrapAbilityResult(env, abilityResult, resultCode, want);
    auto token = context->GetToken();
    OHOS::AAFwk::AbilityManagerClient::GetInstance()->TransferAbilityResultForExtension(token, resultCode, want);
    ret = context->TerminateSelf();
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::UI_EXT, "TerminateSelfWithResult TerminateSelf failed, errorCode is %{public}d", ret);
    }
    StsUIExtensionContext::AsyncCallback(env, callback,
        StsUIExtensionContext::WrapBusinessError(env, static_cast<int32_t>(ret)), nullptr);
    TAG_LOGE(AAFwkTag::UI_EXT, "TerminateSelfWithResult end");
}

ani_object StsUIExtensionContext::WrapBusinessError(ani_env *env, ani_int code)
{
    ani_class cls = nullptr;
    ani_field field = nullptr;
    ani_method method = nullptr;
    ani_object obj = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("L@ohos/application/UIAbilityContext/BusinessError;", &cls)) != ANI_OK) {
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

bool StsUIExtensionContext::AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result)
{
    ani_status status = ANI_ERROR;
    ani_class clsCall = nullptr;

    if ((status = env->FindClass("L@ohos/application/UIAbilityContext/AsyncCallbackWrapper;", &clsCall)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return false;
    }
    ani_method method = nullptr;
    const char *INVOKE_METHOD_NAME = "invoke";
    if ((status = env->Class_FindMethod(clsCall, INVOKE_METHOD_NAME,
        "L@ohos/application/UIAbilityContext/BusinessError;Lstd/core/Object;:V", &method)) != ANI_OK) {
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

ani_object CreateStsUiExtensionContext(ani_env *env, std::shared_ptr<OHOS::AbilityRuntime::UIExtensionContext> context)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext start");
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_field field = nullptr;
    ani_object contextObj = nullptr;
    if ((env->FindClass("Lapplication/UIExtensionContext/UIExtensionContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext find class status : %{public}d", status);
    }
    std::array functions = {
        ani_native_function { "terminateSelfSync", nullptr, reinterpret_cast<ani_int*>(TerminateSelfSync) },
        ani_native_function { "terminateSelfWithResultSync", nullptr,
            reinterpret_cast<ani_int*>(TerminateSelfWithResultSync) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext bind method status : %{public}d", status);
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext find method status : %{public}d", status);
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext new object status : %{public}d", status);
    }
    if ((status = env->Class_FindField(cls, "nativeUIExtensionContext", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext find field status : %{public}d", status);
    }
    ani_long nativeContextLong = (ani_long)context.get();
    if ((status = env->Object_SetField_Long(contextObj, field, nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext set filed status : %{public}d", status);
    }
    TAG_LOGI(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext end");
    return contextObj;
}
