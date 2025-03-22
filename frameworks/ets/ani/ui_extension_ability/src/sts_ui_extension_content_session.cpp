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
#include <array>
#include "sts_ui_extension_content_session.h"
#include "sts_ui_extension_context.h"
#include "hilog_tag_wrapper.h"
#ifdef SUPPORT_SCREEN
#include "ui_content.h"
#endif // SUPPORT_SCREEN
#include "want.h"
#include "window.h"
#include "ability_manager_client.h"

#include "ani_common_want.h"
#include "ani_common_util.h"
#include "array_wrapper.h"
#include "bool_wrapper.h"
#include "byte_wrapper.h"
#include "double_wrapper.h"
#include "float_wrapper.h"
#include "hilog_tag_wrapper.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "js_runtime_utils.h"
#include "long_wrapper.h"
#include "napi_remote_object.h"
#include "remote_object_wrapper.h"
#include "short_wrapper.h"
#include "string_wrapper.h"
#include "tokenid_kit.h"
#include "want_params_wrapper.h"
#include "zchar_wrapper.h"

ani_object NativeSetReceiveDataCallback(ani_env* env, ani_object obj)
{
    ani_object object = nullptr;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeSetReceiveDataCallback null env");
        return object;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("L@ohos/app/ability/UIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "FindClass status : %{public}d", status);
        return object;
    }
    OHOS::AbilityRuntime::StsUIExtensionContentSession *stsContentSession = nullptr;
    ani_field stsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &stsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_FindFieldstatus : %{public}d", status);
        return object;
    }
    status = env->Object_GetField_Long(obj, stsContentSessionField, reinterpret_cast<ani_long*>(&stsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Object_GetField_Long status : %{public}d", status);
        return object;
    }
    if (stsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "stsContentSession is null");
        return object;
    }
    return stsContentSession->SetReceiveDataCallback(env, obj);
}

void NativeSendData(ani_env* env, ani_object obj, ani_string data)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeSendData null env");
        return;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("L@ohos/app/ability/UIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "FindClass status : %{public}d", status);
        return;
    }
    OHOS::AbilityRuntime::StsUIExtensionContentSession *stsContentSession = nullptr;
    ani_field stsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &stsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_FindFieldstatus : %{public}d", status);
        return;
    }
    status = env->Object_GetField_Long(obj, stsContentSessionField, reinterpret_cast<ani_long*>(&stsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Object_GetField_Long status : %{public}d", status);
        return;
    }
    if (stsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "stsContentSession is null");
        return;
    }
    return stsContentSession->SendData(env, obj, data);
}

void NativeLoadContent(ani_env* env, ani_object obj, ani_string path, ani_object storage)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeLoadContent null env");
        return;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("L@ohos/app/ability/UIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "FindClass status : %{public}d", status);
        return;
    }
    OHOS::AbilityRuntime::StsUIExtensionContentSession *stsContentSession = nullptr;
    ani_field stsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &stsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_FindFieldstatus : %{public}d", status);
        return;
    }
    status = env->Object_GetField_Long(obj, stsContentSessionField, reinterpret_cast<ani_long*>(&stsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Object_GetField_Long status : %{public}d", status);
        return;
    }
    if (stsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "stsContentSession is null");
        return;
    }
    return stsContentSession->LoadContent(env, obj, path, storage);
}

void NativeTerminateSelf(ani_env* env, ani_object obj, [[maybe_unused]] ani_object callback)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeTerminateSelf null env");
        return;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("L@ohos/app/ability/UIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "FindClass status : %{public}d", status);
        return;
    }
    OHOS::AbilityRuntime::StsUIExtensionContentSession *stsContentSession = nullptr;
    ani_field stsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &stsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_FindFieldstatus : %{public}d", status);
        return;
    }
    status = env->Object_GetField_Long(obj, stsContentSessionField, reinterpret_cast<ani_long*>(&stsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Object_GetField_Long status : %{public}d", status);
        return;
    }
    if (stsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "stsContentSession is null");
        return;
    }
    stsContentSession->TerminateSelf();
    int resultCode = 0;
    OHOS::AbilityRuntime::StsUIExtensionContentSession::AsyncCallback(env, callback,
        OHOS::AbilityRuntime::StsUIExtensionContentSession::WrapBusinessError(env,
            static_cast<int32_t>(resultCode)), nullptr);
    return;
}

int NativeTerminateSelfWithResult(ani_env* env, ani_object obj, [[maybe_unused]] ani_object abilityResult,
    [[maybe_unused]] ani_object callback)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "NativeTerminateSelfWithResult called");
    int ret = 0;
    if (env == nullptr) {
        TAG_LOGW(AAFwkTag::UI_EXT, "NativeTerminateSelf null env");
        return ret;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("L@ohos/app/ability/UIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "FindClass status : %{public}d", status);
        return ret;
    }
    OHOS::AbilityRuntime::StsUIExtensionContentSession *stsContentSession = nullptr;
    ani_field stsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &stsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_FindFieldstatus : %{public}d", status);
        return ret;
    }
    status = env->Object_GetField_Long(obj, stsContentSessionField, reinterpret_cast<ani_long*>(&stsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Object_GetField_Long status : %{public}d", status);
        return ret;
    }
    if (stsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "stsContentSession is null");
        return ret;
    }
    ret = stsContentSession->TerminateSelfWithResult();
    OHOS::AAFwk::Want want;
    int resultCode = 0;
    OHOS::AppExecFwk::UnWrapAbilityResult(env, abilityResult, resultCode, want);
    OHOS::AbilityRuntime::StsUIExtensionContentSession::AsyncCallback(env, callback,
        OHOS::AbilityRuntime::StsUIExtensionContentSession::WrapBusinessError(env, static_cast<int32_t>(ret)), nullptr);
    TAG_LOGD(AAFwkTag::UI_EXT, "NativeTerminateSelfWithResult end");
    return ret;
}

void NativeSetWindowBackgroundColor(ani_env* env, ani_object obj, ani_string color)
{
    if (env == nullptr) {
        TAG_LOGW(AAFwkTag::UI_EXT, "NativeSetWindowBackgroundColor null env");
        return;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("L@ohos/app/ability/UIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "FindClass status : %{public}d", status);
        return;
    }
    OHOS::AbilityRuntime::StsUIExtensionContentSession *stsContentSession = nullptr;
    ani_field stsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &stsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_FindFieldstatus : %{public}d", status);
        return;
    }
    status = env->Object_GetField_Long(obj, stsContentSessionField, reinterpret_cast<ani_long*>(&stsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Object_GetField_Long status : %{public}d", status);
        return;
    }
    if (stsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "stsContentSession is null");
        return;
    }
    return stsContentSession->SetWindowBackgroundColor(env, color);
}

ani_object NativeGetUIExtensionHostWindowProxy(ani_env* env, ani_object obj)
{
    ani_object object = nullptr;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeGetUIExtensionHostWindowProxy null env");
        return object;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("L@ohos/app/ability/UIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "FindClass status : %{public}d", status);
    }
    OHOS::AbilityRuntime::StsUIExtensionContentSession *stsContentSession = nullptr;
    ani_field stsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &stsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_FindFieldstatus : %{public}d", status);
        return object;
    }
    status = env->Object_GetField_Long(obj, stsContentSessionField, reinterpret_cast<ani_long*>(&stsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Object_GetField_Long status : %{public}d", status);
        return object;
    }
    if (stsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "stsContentSession is null");
        return object;
    }
    return stsContentSession->GetUIExtensionHostWindowProxy(env, obj);
}

namespace OHOS {
namespace AbilityRuntime {
StsUIExtensionContentSession::StsUIExtensionContentSession(
    sptr<AAFwk::SessionInfo> sessionInfo, sptr<Rosen::Window> uiWindow,
    std::weak_ptr<AbilityRuntime::Context> &context,
    std::shared_ptr<StsAbilityResultListeners>& abilityResultListeners)
    : sessionInfo_(sessionInfo), uiWindow_(uiWindow), context_(context)
{
    listener_ = std::make_shared<StsUISessionAbilityResultListener>();
    if (abilityResultListeners == nullptr || sessionInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null params");
    } else {
        abilityResultListeners->AddListener(sessionInfo->uiExtensionComponentId, listener_);
    }
}

StsUIExtensionContentSession::StsUIExtensionContentSession(sptr<AAFwk::SessionInfo> sessionInfo,
    sptr<Rosen::Window> uiWindow) : sessionInfo_(sessionInfo), uiWindow_(uiWindow)
{
}

ani_object StsUIExtensionContentSession::WrapBusinessError(ani_env *env, ani_int code)
{
    ani_class cls = nullptr;
    ani_field field = nullptr;
    ani_method method = nullptr;
    ani_object obj = nullptr;
    ani_status status = ANI_ERROR;

    if ((status = env->FindClass("L@ohos/base/BusinessError;", &cls)) != ANI_OK) {
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", nullptr, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &obj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "code", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetField_Double(obj, field, code)) != ANI_OK) {
        return nullptr;
    }
    return obj;
}

bool StsUIExtensionContentSession::AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result)
{
    ani_status status = ANI_ERROR;
    ani_class clsCall = nullptr;

    if ((status = env->FindClass("L@ohos/app/ability/UIExtensionContentSession/AsyncCallbackSessionWrapper;",
        &clsCall)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        return false;
    }
    ani_method method = nullptr;
    const char *INVOKE_METHOD_NAME = "invoke";
    if ((status = env->Class_FindMethod(
        clsCall, INVOKE_METHOD_NAME, "L@ohos/base/BusinessError;Lstd/core/Object;:V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        return false;
    }
    if (result == nullptr) {
        ani_ref nullRef = nullptr;
        env->GetNull(&nullRef);
        result = reinterpret_cast<ani_object>(nullRef);
    }
    if ((status = env->Object_CallMethod_Void(call, method, error, result)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        return false;
    }
    return true;
}

ani_object StsUIExtensionContentSession::CreateStsUIExtensionContentSession(ani_env* env,
    sptr<AAFwk::SessionInfo> sessionInfo, sptr<Rosen::Window> uiWindow,
    std::weak_ptr<AbilityRuntime::Context> context,
    std::shared_ptr<StsAbilityResultListeners>& abilityResultListeners,
    std::shared_ptr<StsUIExtensionContentSession> contentSessionPtr)
{
    ani_object object = nullptr;
    ani_method method = nullptr;
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("L@ohos/app/ability/UIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "FindClass status : %{public}d", status);
        return nullptr;
    }
    status = env->Class_FindMethod(cls, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        return nullptr;
    }
    status = env->Object_New(cls, method, &object);
    if ((status != ANI_OK) || (object == nullptr)) {
        return nullptr;
    }

    std::array methods = {
        ani_native_function {"terminateSelfSync", nullptr, reinterpret_cast<void *>(NativeTerminateSelf)},
        ani_native_function {"nativeSendData", nullptr, reinterpret_cast<void *>(NativeSendData)},
        //ani_native_function {"loadContent", nullptr, reinterpret_cast<void *>(NativeLoadContent)},
        ani_native_function {"terminateSelfWithResultSync", nullptr,
            reinterpret_cast<void *>(NativeTerminateSelfWithResult)},
        ani_native_function {"setWindowBackgroundColor", nullptr,
            reinterpret_cast<void *>(NativeSetWindowBackgroundColor)},
        // ani_native_function {"getUIExtensionHostWindowProxy", nullptr,
        //     reinterpret_cast<void *>(NativeGetUIExtensionHostWindowProxy)},
        ani_native_function {"setReceiveDataCallbackASync", nullptr,
            reinterpret_cast<void *>(NativeSetReceiveDataCallback)}
    };
    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        return nullptr;
    }
    ani_field nativeField = nullptr;
    status = env->Class_FindField(cls, "nativeContextSession", &nativeField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_FindFieldstatus : %{public}d", status);
        return nullptr;
    }
    status = env->Object_SetField_Long(object, nativeField, reinterpret_cast<ani_long>(contentSessionPtr.get()));
    if (status != ANI_OK) {
        return nullptr;
    }
    return object;
}

void StsUIExtensionContentSession::SendData(ani_env* env, ani_object object, ani_string data)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "call");
    AAFwk::WantParams params;
    std::string wantParamsString;
    if (!AppExecFwk::GetStdString(env, data, wantParamsString)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetStdString failed");
        return;
    }
    nlohmann::json wantParamsJson = nlohmann::json::parse(wantParamsString);
    from_json(wantParamsJson, params);

    if (uiWindow_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null uiWindow_");
        return;
    }

    Rosen::WMError ret = uiWindow_->TransferExtensionData(params);
    if (ret == Rosen::WMError::WM_OK) {
        TAG_LOGD(AAFwkTag::UI_EXT, "TransferExtensionData success");
    } else {
        TAG_LOGE(AAFwkTag::UI_EXT, "TransferExtensionData failed, ret=%{public}d", ret);
        return;
    }
}

void StsUIExtensionContentSession::LoadContent(ani_env* env, ani_object object, ani_string path, ani_object storage)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "call");
    std::string contextPath;
    ani_size sz {};
    env->String_GetUTF8Size(path, &sz);
    contextPath.resize(sz + 1);
    env->String_GetUTF8SubString(path, 0, sz, contextPath.data(), contextPath.size(), &sz);

    if (uiWindow_ == nullptr || sessionInfo_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "uiWindow_ or sessionInfo_ is nullptr");
        return;
    }

    if (sessionInfo_->isAsyncModalBinding && isFirstTriggerBindModal_) {
        TAG_LOGD(AAFwkTag::UI_EXT, "Trigger binding UIExtension modal window");
        uiWindow_->TriggerBindModalUIExtension();
        isFirstTriggerBindModal_ = false;
    }
    sptr<IRemoteObject> parentToken = sessionInfo_->parentToken;
    Rosen::WMError ret = uiWindow_->NapiSetUIContent(contextPath, env, storage,
        Rosen::BackupAndRestoreType::NONE, parentToken);
    if (ret == Rosen::WMError::WM_OK) {
        TAG_LOGD(AAFwkTag::UI_EXT, "AniSetUIContent success");
    } else {
        TAG_LOGE(AAFwkTag::UI_EXT, "AniSetUIContent failed, ret=%{public}d", ret);
    }
    return;
}

void StsUIExtensionContentSession::TerminateSelf()
{
    TAG_LOGD(AAFwkTag::UI_EXT, "call");
    AAFwk::AbilityManagerClient::GetInstance()->TerminateUIExtensionAbility(sessionInfo_);
}

int StsUIExtensionContentSession::TerminateSelfWithResult()
{
    TAG_LOGD(AAFwkTag::UI_EXT, "call");
    return AAFwk::AbilityManagerClient::GetInstance()->TerminateUIExtensionAbility(sessionInfo_);
}

void StsUIExtensionContentSession::SetWindowBackgroundColor(ani_env* env, ani_string color)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "call");
    std::string strColor;
    ani_status status = ANI_ERROR;
    ani_size bufferSize = 0U;
    status = env->String_GetUTF8Size(color, &bufferSize);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "String_GetUTF8Size, ret=%{public}d", status);
        return;
    }

    char* utfBuffer = (char*)malloc(bufferSize * sizeof(char));
    if (utfBuffer == nullptr) {
        return;
    }
    ani_size substrOffset = 0U;
    ani_size substrSize = bufferSize;
    ani_size result = 0U;
    status = env->String_GetUTF8SubString(color, substrOffset, substrSize, utfBuffer, bufferSize, &result);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "String_GetUTF8, ret=%{public}d", status);
        return;
    }
    strColor = utfBuffer;
    free(utfBuffer);
    if (uiWindow_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "uiWindow_ is nullptr");
         return;
    }
    Rosen::WMError ret = uiWindow_->SetBackgroundColor(strColor);
    if (ret == Rosen::WMError::WM_OK) {
        TAG_LOGD(AAFwkTag::UI_EXT, "SetBackgroundColor success");
    } else {
        TAG_LOGE(AAFwkTag::UI_EXT, "SetBackgroundColor failed, ret=%{public}d", ret);
    }
}

ani_object StsUIExtensionContentSession::GetUIExtensionHostWindowProxy(ani_env* env, ani_object object)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "call");
    // if (sessionInfo_ == nullptr) {
    //     TAG_LOGE(AAFwkTag::UI_EXT, "Invalid session info");
    //     ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
    //     return nullptr;
    // }

    // ani_value stsExtensionWindow = nullptr;
    // Rosen::JsExtensionWindow::CreateJsExtensionWindow(env, uiWindow_, sessionInfo_->hostWindowId);
    // if (jsExtensionWindow == nullptr) {
    //     TAG_LOGE(AAFwkTag::UI_EXT, "Failed to create jsExtensionWindow object");
    //     ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
    //     return nullptr;
    // }
    // auto value = StsRuntime::LoadSystemModuleByEngine(env, "application.extensionWindow", &stsExtensionWindow, 1);
    // if (value == nullptr) {
    //     ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
    //     return nullptr;
    // }
    return nullptr;
}

ani_object StsUIExtensionContentSession::SetReceiveDataCallback(ani_env* env, ani_object object)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "call");
    // if (sessionInfo_ == nullptr) {
    //     TAG_LOGE(AAFwkTag::UI_EXT, "Invalid session info");
    //     ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
    //     return nullptr;
    // }

    // ani_value stsExtensionWindow = nullptr;
    // Rosen::JsExtensionWindow::CreateJsExtensionWindow(env, uiWindow_, sessionInfo_->hostWindowId);
    // if (jsExtensionWindow == nullptr) {
    //     TAG_LOGE(AAFwkTag::UI_EXT, "Failed to create jsExtensionWindow object");
    //     ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
    //     return nullptr;
    // }
    // auto value = StsRuntime::LoadSystemModuleByEngine(env, "application.extensionWindow", &stsExtensionWindow, 1);
    // if (value == nullptr) {
    //     ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
    //     return nullptr;
    // }
    return nullptr;
}
}
}