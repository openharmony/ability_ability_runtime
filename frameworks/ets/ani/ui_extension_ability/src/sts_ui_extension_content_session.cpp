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
#include "ani_extension_window.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"
#include "remote_object_wrapper.h"
#include "tokenid_kit.h"
#include "want_params_wrapper.h"
#include "sts_error_utils.h"
namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* UI_SESSION_CLASS_NAME =
    "L@ohos/app/ability/UIExtensionContentSession/UIExtensionContentSession;";
}

StsUIExtensionContentSession* GetStsContentSession(ani_env* env, ani_object obj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        ThrowStsInvalidParamError(env, "context null");
        return nullptr;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass(UI_SESSION_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        ThrowStsInvalidParamError(env, "findClass fail");
        return nullptr;
    }
    StsUIExtensionContentSession *stsContentSession = nullptr;
    ani_field stsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &stsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        ThrowStsInvalidParamError(env, "class find field fail");
        return nullptr;
    }
    status = env->Object_GetField_Long(obj, stsContentSessionField, reinterpret_cast<ani_long*>(&stsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        ThrowStsInvalidParamError(env, "object get field Long fail");
        return nullptr;
    }
    if (stsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "stsContentSession null");
        ThrowStsInvalidParamError(env, "stsContentSession null");
        return nullptr;
    }
    return stsContentSession;
}
ani_object NativeSetReceiveDataCallback(ani_env* env, ani_object obj)
{
    auto stsContentSession = GetStsContentSession(env, obj);
    ani_object object = nullptr;
    if (stsContentSession != nullptr) {
        object = stsContentSession->SetReceiveDataCallback(env, obj);
    }
    return object;
}

void NativeSendData(ani_env* env, ani_object obj, ani_object data)
{
    auto stsContentSession = GetStsContentSession(env, obj);
    if (stsContentSession != nullptr) {
        stsContentSession->SendData(env, obj, data);
    }
}

void NativeLoadContent(ani_env* env, ani_object obj, ani_string path, ani_object storage)
{
    auto stsContentSession = GetStsContentSession(env, obj);
    if (stsContentSession != nullptr) {
        stsContentSession->LoadContent(env, obj, path, storage);
    }
}

void NativeTerminateSelf(ani_env* env, ani_object obj, [[maybe_unused]] ani_object callback)
{
    auto stsContentSession = GetStsContentSession(env, obj);
    if (stsContentSession != nullptr) {
        int32_t resultCode = stsContentSession->TerminateSelfWithResult();
        OHOS::AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, static_cast<int32_t>(resultCode)), nullptr);
    }
}

int NativeTerminateSelfWithResult(ani_env* env, ani_object obj, [[maybe_unused]] ani_object abilityResult,
    [[maybe_unused]] ani_object callback)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "NativeTerminateSelfWithResult called");
    int ret = 0;
    auto stsContentSession = GetStsContentSession(env, obj);
    if (stsContentSession != nullptr) {
        ret = stsContentSession->TerminateSelfWithResult();
        OHOS::AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret)), nullptr);
    }
    return ret;
}

void NativeSetWindowBackgroundColor(ani_env* env, ani_object obj, ani_string color)
{
    auto stsContentSession = GetStsContentSession(env, obj);
    if (stsContentSession != nullptr) {
        stsContentSession->SetWindowBackgroundColor(env, color);
    }
}

ani_object NativeGetUIExtensionHostWindowProxy(ani_env* env, ani_object obj)
{
    auto stsContentSession = GetStsContentSession(env, obj);
    ani_object object = nullptr;
    if (stsContentSession != nullptr) {
        object = stsContentSession->GetUIExtensionHostWindowProxy(env, obj);
    }
    return object;
}

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
    status = env->FindClass(UI_SESSION_CLASS_NAME, &cls);
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
            reinterpret_cast<void *>(OHOS::AbilityRuntime::NativeTerminateSelf)},
        ani_native_function {"nativeSendData", nullptr, reinterpret_cast<void *>(OHOS::AbilityRuntime::NativeSendData)},
        ani_native_function {"loadContent", nullptr, reinterpret_cast<void *>(OHOS::AbilityRuntime::NativeLoadContent)},
        ani_native_function {"terminateSelfWithResultSync", nullptr,
            reinterpret_cast<void *>(OHOS::AbilityRuntime::NativeTerminateSelfWithResult)},
        ani_native_function {"setWindowBackgroundColor", nullptr,
            reinterpret_cast<void *>(OHOS::AbilityRuntime::NativeSetWindowBackgroundColor)},
        ani_native_function {"getUIExtensionHostWindowProxy", nullptr,
            reinterpret_cast<void *>(OHOS::AbilityRuntime::NativeGetUIExtensionHostWindowProxy)},
        ani_native_function {"setReceiveDataCallbackASync", nullptr,
            reinterpret_cast<void *>(OHOS::AbilityRuntime::NativeSetReceiveDataCallback)}
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

void StsUIExtensionContentSession::SendData(ani_env* env, ani_object object, ani_object data)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    AAFwk::WantParams params;
    AppExecFwk::UnwrapWantParams(env, reinterpret_cast<ani_ref>(data), params);
    if (uiWindow_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null uiWindow_");
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }

    Rosen::WMError ret = uiWindow_->TransferExtensionData(params);
    if (ret == Rosen::WMError::WM_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "TransferExtensionData success");
    } else {
        TAG_LOGE(AAFwkTag::UI_EXT, "TransferExtensionData failed, ret=%{public}d", ret);
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
}

void StsUIExtensionContentSession::LoadContent(ani_env* env, ani_object object, ani_string path, ani_object storage)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    std::string contextPath;
    ani_size sz {};
    env->String_GetUTF8Size(path, &sz);
    contextPath.resize(sz + 1);
    env->String_GetUTF8SubString(path, 0, sz, contextPath.data(), contextPath.size(), &sz);

    if (uiWindow_ == nullptr || sessionInfo_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "uiWindow_ or sessionInfo_ is nullptr");
        ThrowStsErrorByNativeErr(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER));
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
        ThrowStsErrorByNativeErr(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER));
    }
    return;
}

void StsUIExtensionContentSession::TerminateSelf()
{
    TAG_LOGD(AAFwkTag::UI_EXT, "TerminateSelf call");
    AAFwk::AbilityManagerClient::GetInstance()->TerminateUIExtensionAbility(sessionInfo_);
}

int32_t StsUIExtensionContentSession::TerminateSelfWithResult()
{
    TAG_LOGD(AAFwkTag::UI_EXT, "TerminateSelfWithResult call");
    return AAFwk::AbilityManagerClient::GetInstance()->TerminateUIExtensionAbility(sessionInfo_);
}

void StsUIExtensionContentSession::SetWindowBackgroundColor(ani_env* env, ani_string color)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "SetWindowBackgroundColor call");
    std::string strColor;
    ani_size sz {};
    env->String_GetUTF8Size(color, &sz);
    strColor.resize(sz + 1);
    env->String_GetUTF8SubString(color, 0, sz, strColor.data(), strColor.size(), &sz);
    if (uiWindow_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "uiWindow_ is nullptr");
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
         return;
    }
    Rosen::WMError ret = uiWindow_->SetBackgroundColor(strColor);
    if (ret != Rosen::WMError::WM_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "SetBackgroundColor failed, ret=%{public}d", ret);
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
    }
}

ani_object StsUIExtensionContentSession::GetUIExtensionHostWindowProxy(ani_env* env, ani_object object)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    if (sessionInfo_ == nullptr) {
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return nullptr;
    }
    ani_object stsExtensionWindow = nullptr;
    stsExtensionWindow =
        Rosen::AniExtensionWindow::CreateAniExtensionWindow(env, uiWindow_, sessionInfo_->hostWindowId);
    if (stsExtensionWindow == nullptr) {
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return nullptr;
    }
    ani_ref resultRef = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GlobalReference_Create(stsExtensionWindow, &resultRef)) != ANI_OK) {
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return nullptr;
    }
    return reinterpret_cast<ani_object>(resultRef);
}

ani_object StsUIExtensionContentSession::SetReceiveDataCallback(ani_env* env, ani_object object)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    return nullptr;
}
}
}