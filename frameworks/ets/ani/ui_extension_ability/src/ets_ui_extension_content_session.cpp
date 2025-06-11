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
#include "ets_ui_extension_content_session.h"
#include "ets_ui_extension_context.h"
#include "hilog_tag_wrapper.h"
#ifdef SUPPORT_SCREEN
#include "ui_content.h"
#endif // SUPPORT_SCREEN
#include "want.h"
#include "window.h"
#include "ability_manager_client.h"

#include "ani_common_want.h"
#include "ani_common_util.h"
#include "ani_extension_window.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"
#include "remote_object_wrapper.h"
#include "tokenid_kit.h"
#include "want_params_wrapper.h"
#include "ets_error_utils.h"
namespace OHOS {
namespace AbilityRuntime {

const char* UI_EXTENSION_CONTENT_SESSION_CLASS_NAME =
    "L@ohos/app/ability/UIExtensionContentSession/UIExtensionContentSession;";

EtsUIExtensionContentSession* EtsUIExtensionContentSession::GetEtsContentSession(ani_env* env, ani_object obj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        ThrowEtsInvalidParamError(env, "context null");
        return nullptr;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass(UI_EXTENSION_CONTENT_SESSION_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        ThrowEtsInvalidParamError(env, "findClass fail");
        return nullptr;
    }
    EtsUIExtensionContentSession *etsContentSession = nullptr;
    ani_field etsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &etsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        ThrowEtsInvalidParamError(env, "class find field fail");
        return nullptr;
    }
    status = env->Object_GetField_Long(obj, etsContentSessionField, reinterpret_cast<ani_long*>(&etsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        ThrowEtsInvalidParamError(env, "object get field Long fail");
        return nullptr;
    }
    if (etsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "etsContentSession null");
        ThrowEtsInvalidParamError(env, "etsContentSession null");
        return nullptr;
    }
    return etsContentSession;
}

ani_object EtsUIExtensionContentSession::NativeSetReceiveDataCallback(ani_env* env, ani_object obj)
{
    auto etsContentSession = EtsUIExtensionContentSession::GetEtsContentSession(env, obj);
    ani_object object = nullptr;
    if (etsContentSession != nullptr) {
        object = etsContentSession->SetReceiveDataCallback(env, obj);
    }
    return object;
}

void EtsUIExtensionContentSession::NativeSendData(ani_env* env, ani_object obj, ani_object data)
{
    auto etsContentSession =EtsUIExtensionContentSession::GetEtsContentSession(env, obj);
    if (etsContentSession != nullptr) {
        etsContentSession->SendData(env, obj, data);
    }
}

void EtsUIExtensionContentSession::NativeLoadContent(ani_env* env, ani_object obj, ani_string path, ani_object storage)
{
    auto etsContentSession = EtsUIExtensionContentSession::GetEtsContentSession(env, obj);
    if (etsContentSession != nullptr) {
        etsContentSession->LoadContent(env, obj, path, storage);
    }
}

void EtsUIExtensionContentSession::NativeTerminateSelf(ani_env* env, ani_object obj, ani_object callback)
{
    auto etsContentSession = EtsUIExtensionContentSession::GetEtsContentSession(env, obj);
    if (etsContentSession != nullptr) {
        int32_t resultCode = etsContentSession->TerminateSelfWithResult();
        OHOS::AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateEtsErrorByNativeErr(env, static_cast<int32_t>(resultCode)), nullptr);
    }
}

int EtsUIExtensionContentSession::NativeTerminateSelfWithResult(ani_env* env, ani_object obj,
    ani_object abilityResult, ani_object callback)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "NativeTerminateSelfWithResult called");
    int ret = 0;
    auto etsContentSession = EtsUIExtensionContentSession::GetEtsContentSession(env, obj);
    if (etsContentSession != nullptr) {
        ret = etsContentSession->TerminateSelfWithResult();
        OHOS::AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateEtsErrorByNativeErr(env, static_cast<int32_t>(ret)), nullptr);
    }
    return ret;
}

void EtsUIExtensionContentSession::NativeSetWindowBackgroundColor(ani_env* env, ani_object obj, ani_string color)
{
    auto etsContentSession = EtsUIExtensionContentSession::GetEtsContentSession(env, obj);
    if (etsContentSession != nullptr) {
        etsContentSession->SetWindowBackgroundColor(env, color);
    }
}

ani_object EtsUIExtensionContentSession::NativeGetUIExtensionHostWindowProxy(ani_env* env, ani_object obj)
{
    auto etsContentSession = EtsUIExtensionContentSession::GetEtsContentSession(env, obj);
    ani_object object = nullptr;
    if (etsContentSession != nullptr) {
        object = etsContentSession->GetUIExtensionHostWindowProxy(env, obj);
    }
    return object;
}

EtsUIExtensionContentSession::EtsUIExtensionContentSession(
    sptr<AAFwk::SessionInfo> sessionInfo, sptr<Rosen::Window> uiWindow,
    std::weak_ptr<AbilityRuntime::Context> &context,
    std::shared_ptr<EtsAbilityResultListeners>& abilityResultListeners)
    : sessionInfo_(sessionInfo), uiWindow_(uiWindow), context_(context)
{
    listener_ = std::make_shared<EtsUISessionAbilityResultListener>();
    if (abilityResultListeners == nullptr || sessionInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null params");
    } else {
        abilityResultListeners->AddListener(sessionInfo->uiExtensionComponentId, listener_);
    }
}

EtsUIExtensionContentSession::EtsUIExtensionContentSession(sptr<AAFwk::SessionInfo> sessionInfo,
    sptr<Rosen::Window> uiWindow) : sessionInfo_(sessionInfo), uiWindow_(uiWindow)
{
}

ani_object EtsUIExtensionContentSession::CreateEtsUIExtensionContentSession(ani_env* env,
    sptr<AAFwk::SessionInfo> sessionInfo, sptr<Rosen::Window> uiWindow,
    std::weak_ptr<AbilityRuntime::Context> context,
    std::shared_ptr<EtsAbilityResultListeners>& abilityResultListeners,
    std::shared_ptr<EtsUIExtensionContentSession> contentSessionPtr)
{
    ani_object object = nullptr;
    ani_method method = nullptr;
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass(UI_EXTENSION_CONTENT_SESSION_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
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
        ani_native_function {"terminateSelfSync", nullptr,
            reinterpret_cast<void *>(EtsUIExtensionContentSession::NativeTerminateSelf)},
        ani_native_function {"nativeSendData", nullptr,
            reinterpret_cast<void *>(EtsUIExtensionContentSession::NativeSendData)},
        ani_native_function {"loadContent", nullptr,
            reinterpret_cast<void *>(EtsUIExtensionContentSession::NativeLoadContent)},
        ani_native_function {"terminateSelfWithResultSync", nullptr,
            reinterpret_cast<void *>(EtsUIExtensionContentSession::NativeTerminateSelfWithResult)},
        ani_native_function {"setWindowBackgroundColor", nullptr,
            reinterpret_cast<void *>(EtsUIExtensionContentSession::NativeSetWindowBackgroundColor)},
        ani_native_function {"getUIExtensionHostWindowProxy", nullptr,
            reinterpret_cast<void *>(EtsUIExtensionContentSession::NativeGetUIExtensionHostWindowProxy)},
        ani_native_function {"setReceiveDataCallbackASync", nullptr,
            reinterpret_cast<void *>(EtsUIExtensionContentSession::NativeSetReceiveDataCallback)}
    };
    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    ani_field nativeField = nullptr;
    status = env->Class_FindField(cls, "nativeContextSession", &nativeField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    status = env->Object_SetField_Long(object, nativeField, reinterpret_cast<ani_long>(contentSessionPtr.get()));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    return object;
}

void EtsUIExtensionContentSession::SendData(ani_env* env, ani_object object, ani_object data)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    AAFwk::WantParams params;
    AppExecFwk::UnwrapWantParams(env, reinterpret_cast<ani_ref>(data), params);
    if (uiWindow_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null uiWindow_");
        ThrowEtsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }

    Rosen::WMError ret = uiWindow_->TransferExtensionData(params);
    if (ret == Rosen::WMError::WM_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "TransferExtensionData success");
    } else {
        TAG_LOGE(AAFwkTag::UI_EXT, "TransferExtensionData failed, ret=%{public}d", ret);
        ThrowEtsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
}

void EtsUIExtensionContentSession::LoadContent(ani_env* env, ani_object object, ani_string path, ani_object storage)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    std::string contextPath;
    ani_size sz {};
    env->String_GetUTF8Size(path, &sz);
    contextPath.resize(sz + 1);
    env->String_GetUTF8SubString(path, 0, sz, contextPath.data(), contextPath.size(), &sz);

    if (uiWindow_ == nullptr || sessionInfo_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "uiWindow_ or sessionInfo_ is nullptr");
        ThrowEtsErrorByNativeErr(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER));
        return;
    }

    if (sessionInfo_->isAsyncModalBinding && isFirstTriggerBindModal_) {
        uiWindow_->TriggerBindModalUIExtension();
        isFirstTriggerBindModal_ = false;
    }
    sptr<IRemoteObject> parentToken = sessionInfo_->parentToken;
    Rosen::WMError ret = uiWindow_->NapiSetUIContent(contextPath, env, storage,
        Rosen::BackupAndRestoreType::NONE, parentToken);
    if (ret != Rosen::WMError::WM_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "AniSetUIContent failed, ret=%{public}d", ret);
        ThrowEtsErrorByNativeErr(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER));
    }
    return;
}

void EtsUIExtensionContentSession::TerminateSelf()
{
    TAG_LOGD(AAFwkTag::UI_EXT, "TerminateSelf call");
    AAFwk::AbilityManagerClient::GetInstance()->TerminateUIExtensionAbility(sessionInfo_);
}

int32_t EtsUIExtensionContentSession::TerminateSelfWithResult()
{
    TAG_LOGD(AAFwkTag::UI_EXT, "TerminateSelfWithResult call");
    return AAFwk::AbilityManagerClient::GetInstance()->TerminateUIExtensionAbility(sessionInfo_);
}

void EtsUIExtensionContentSession::SetWindowBackgroundColor(ani_env* env, ani_string color)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "SetWindowBackgroundColor call");
    std::string strColor;
    ani_size sz {};
    env->String_GetUTF8Size(color, &sz);
    strColor.resize(sz + 1);
    env->String_GetUTF8SubString(color, 0, sz, strColor.data(), strColor.size(), &sz);
    if (uiWindow_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "uiWindow_ is nullptr");
        ThrowEtsError(env, AbilityErrorCode::ERROR_CODE_INNER);
         return;
    }
    Rosen::WMError ret = uiWindow_->SetBackgroundColor(strColor);
    if (ret != Rosen::WMError::WM_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "SetBackgroundColor failed, ret=%{public}d", ret);
        ThrowEtsError(env, AbilityErrorCode::ERROR_CODE_INNER);
    }
}

ani_object EtsUIExtensionContentSession::GetUIExtensionHostWindowProxy(ani_env* env, ani_object object)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    if (sessionInfo_ == nullptr) {
        ThrowEtsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return nullptr;
    }
    ani_object etsExtensionWindow = nullptr;
    etsExtensionWindow =
        Rosen::AniExtensionWindow::CreateAniExtensionWindow(env, uiWindow_, sessionInfo_->hostWindowId);
    if (etsExtensionWindow == nullptr) {
        ThrowEtsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return nullptr;
    }
    ani_ref resultRef = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GlobalReference_Create(etsExtensionWindow, &resultRef)) != ANI_OK) {
        ThrowEtsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return nullptr;
    }
    return reinterpret_cast<ani_object>(resultRef);
}

ani_object EtsUIExtensionContentSession::SetReceiveDataCallback(ani_env* env, ani_object object)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    return nullptr;
}
} // namespace AbilityRuntime
} // namespace OHOS