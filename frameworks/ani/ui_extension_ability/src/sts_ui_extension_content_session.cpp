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
#include "hilog_tag_wrapper.h"
#include "ui_extension_context.h"
#ifdef SUPPORT_SCREEN
#include "ui_content.h"
#endif // SUPPORT_SCREEN
#include "want.h"
#include "window.h"

static ani_object NativeSetReceiveDataCallback(ani_env* env, ani_object obj)
{
    if (env == nullptr) {
        TAG_LOGW(AAFwkTag::UI_EXT, "NativeGetUIExtensionHostWindowProxy null env");
        ani_object object = nullptr;
        return object;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("LUIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeGetUIExtensionHostWindowProxy FindClass status : %{public}d", status);
    }
    OHOS::AbilityRuntime::StsUIExtensionContentSession *stsContentSession;
    ani_field stsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &stsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeGetUIExtensionHostWindowProxy Class_FindFieldstatus : %{public}d", status);
    }
    status = env->Object_GetField_Long(obj, stsContentSessionField, reinterpret_cast<ani_long*>(&stsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeGetUIExtensionHostWindowProxy Object_GetField_Long status : %{public}d",
            status);
    }
    if (stsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeGetUIExtensionHostWindowProxy stsContentSession is null");
        ani_object object = nullptr;
        return object;
    }
    return stsContentSession->SetReceiveDataCallback(env, obj);
}
static void NativeSendData(ani_env* env, ani_object obj)
{
    if (env == nullptr) {
        TAG_LOGW(AAFwkTag::UI_EXT, "NativeSendData null env");
        return;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("LUIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeSendData FindClass status : %{public}d", status);
    }
    OHOS::AbilityRuntime::StsUIExtensionContentSession *stsContentSession;
    ani_field stsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &stsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeSendData Class_FindFieldstatus : %{public}d", status);
    }
    status = env->Object_GetField_Long(obj, stsContentSessionField, reinterpret_cast<ani_long*>(&stsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeSendData Object_GetField_Long status : %{public}d", status);
    }
    if (stsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeSendData stsContentSession is null");
        return;
    }
    return stsContentSession->SendData(env, obj);
}

static void NativeLoadContent(ani_env* env, ani_object obj, ani_string path, ani_object storage)
{
    if (env == nullptr) {
        TAG_LOGW(AAFwkTag::UI_EXT, "NativeLoadContent null env");
        return;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("LUIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeLoadContent FindClass status : %{public}d", status);
    }
    OHOS::AbilityRuntime::StsUIExtensionContentSession *stsContentSession;
    ani_field stsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &stsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeLoadContent Class_FindFieldstatus : %{public}d", status);
    }
    status = env->Object_GetField_Long(obj, stsContentSessionField, reinterpret_cast<ani_long*>(&stsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeLoadContent Object_GetField_Long status : %{public}d", status);
    }
    if (stsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeLoadContent stsContentSession is null");
        return;
    }
    return stsContentSession->LoadContent(env, obj, path, storage);
}

static void NativeTerminateSelf(ani_env* env, ani_object obj)
{
    if (env == nullptr) {
        TAG_LOGW(AAFwkTag::UI_EXT, "NativeTerminateSelf null env");
        return;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("LUIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeTerminateSelf FindClass status : %{public}d", status);
    }
    OHOS::AbilityRuntime::StsUIExtensionContentSession *stsContentSession;
    ani_field stsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &stsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeTerminateSelf Class_FindFieldstatus : %{public}d", status);
    }
    status = env->Object_GetField_Long(obj, stsContentSessionField, reinterpret_cast<ani_long*>(&stsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeTerminateSelf Object_GetField_Long status : %{public}d", status);
    }
    if (stsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeTerminateSelf stsContentSession is null");
        return;
    }
    return stsContentSession->TerminateSelf();
}

static void NativeSetWindowBackgroundColor(ani_env* env, ani_object obj)
{
    if (env == nullptr) {
        TAG_LOGW(AAFwkTag::UI_EXT, "NativeTerminateSelfWithResult null env");
        return;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("LUIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeSetWindowBackgroundColor FindClass status : %{public}d", status);
    }
    OHOS::AbilityRuntime::StsUIExtensionContentSession *stsContentSession;
    ani_field stsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &stsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeSetWindowBackgroundColor Class_FindFieldstatus : %{public}d", status);
    }
    status = env->Object_GetField_Long(obj, stsContentSessionField, reinterpret_cast<ani_long*>(&stsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeSetWindowBackgroundColor Object_GetField_Long status : %{public}d", status);
    }
    if (stsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeSetWindowBackgroundColor stsContentSession is null");
        return;
    }
    return stsContentSession->SetWindowBackgroundColor("red");
}

static ani_object NativeGetUIExtensionHostWindowProxy(ani_env* env, ani_object obj)
{
    if (env == nullptr) {
        TAG_LOGW(AAFwkTag::UI_EXT, "NativeGetUIExtensionHostWindowProxy null env");
        ani_object object = nullptr;
        return object;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("LUIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeGetUIExtensionHostWindowProxy FindClass status : %{public}d", status);
    }
    OHOS::AbilityRuntime::StsUIExtensionContentSession *stsContentSession;
    ani_field stsContentSessionField;
    status = env->Class_FindField(cls, "nativeContextSession", &stsContentSessionField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeGetUIExtensionHostWindowProxy Class_FindFieldstatus : %{public}d", status);
    }
    status = env->Object_GetField_Long(obj, stsContentSessionField, reinterpret_cast<ani_long*>(&stsContentSession));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeGetUIExtensionHostWindowProxy Object_GetField_Long status : %{public}d",
            status);
    }
    if (stsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NativeGetUIExtensionHostWindowProxy stsContentSession is null");
        ani_object object = nullptr;
        return object;
    }
    return stsContentSession->GetUIExtensionHostWindowProxy(env, obj);
}

namespace OHOS {
namespace AbilityRuntime {
StsUIExtensionContentSession::StsUIExtensionContentSession(
    sptr<AAFwk::SessionInfo> sessionInfo, sptr<Rosen::Window> uiWindow,
    std::weak_ptr<AbilityRuntime::Context> &context,
    std::shared_ptr<AbilityResultListeners>& abilityResultListeners)
    : sessionInfo_(sessionInfo), uiWindow_(uiWindow), context_(context)
{
    listener_ = std::make_shared<UISessionAbilityResultListener>();
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
    std::shared_ptr<AbilityResultListeners>& abilityResultListeners)
{
    TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUIExtensionContentSession call");
    ani_object object = nullptr;
    ani_method method = nullptr;
    ani_class cls;
    ani_status status = ANI_ERROR;
    status = env->FindClass("LUIExtensionContentSession/UIExtensionContentSession;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUIExtensionContentSession FindClass status : %{public}d", status);
    }
    status = env->Class_FindMethod(cls, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUIExtensionContentSession Class_FindMethod status : %{public}d", status);
    }
    status = env->Object_New(cls, method, &object);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUIExtensionContentSession Object_New status : %{public}d", status);
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUIExtensionContentSession null object");
        return nullptr;
    }

    auto stsContentSession =
        std::make_unique<StsUIExtensionContentSession>(sessionInfo, uiWindow, context, abilityResultListeners);
    std::array methods = {
        ani_native_function {"terminateSelfSync", ":V", reinterpret_cast<void *>(NativeTerminateSelf)},
        ani_native_function {"sendData", nullptr, reinterpret_cast<void *>(NativeSendData)},
        ani_native_function {"loadContent", nullptr, reinterpret_cast<void *>(NativeLoadContent)},
        ani_native_function {"setWindowBackgroundColor", nullptr,
            reinterpret_cast<void *>(NativeSetWindowBackgroundColor)},
        ani_native_function {"getUIExtensionHostWindowProxy", nullptr,
            reinterpret_cast<void *>(NativeGetUIExtensionHostWindowProxy)},
        ani_native_function {"setReceiveDataCallback", nullptr, reinterpret_cast<void *>(NativeSetReceiveDataCallback)}
    };
    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUIExtensionContentSession status : %{public}d", status);
    }
    ani_field nativeField = nullptr;
    status = env->Class_FindField(cls, "nativeContextSession", &nativeField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUIExtensionContentSession Class_FindFieldstatus : %{public}d", status);
    }
    status = env->Object_SetField_Long(object, nativeField, reinterpret_cast<ani_long>(stsContentSession.release()));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUIExtensionContentSession status : %{public}d", status);
    }
    TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUIExtensionContentSession call end");
    return object;
}

void StsUIExtensionContentSession::SendData(ani_env* env, ani_object object)
{
    TAG_LOGE(AAFwkTag::UI_EXT, "StsUIExtensionContentSession SendData call");
    AAFwk::WantParams params;
    // if (!AppExecFwk::UnwrapWantParams(env, info.argv[INDEX_ZERO], params)) {
    //     TAG_LOGE(AAFwkTag::UI_EXT, "parse param failed");
    //     ThrowInvalidParamError(env, "OnSendData Failed to parse param! Data must be a Record<string, Object>.");
    //     return CreateJsUndefined(env);
    // }

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
    TAG_LOGD(AAFwkTag::UI_EXT, "StsUIExtensionContentSession::LoadContent called");
    std::string contextPath;
    ani_status status = ANI_ERROR;
    ani_size bufferSize = 0U;
    status = env->String_GetUTF8Size(path, &bufferSize);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "LoadContent String_GetUTF8Size, ret=%{public}d", status);
        return;
    }

    char* utfBuffer = (char*)malloc(bufferSize * sizeof(char));
    if (utfBuffer == nullptr) {
        return;
    }
    ani_size substrOffset = 0U;
    ani_size substrSize = bufferSize;
    ani_size result = 0U;
    status = env->String_GetUTF8SubString(path, substrOffset, substrSize, utfBuffer, bufferSize, &result);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "LoadContent String_GetUTF8, ret=%{public}d", status);
        return;
    }
    contextPath = utfBuffer;
    free(utfBuffer);
    TAG_LOGD(AAFwkTag::UI_EXT, "contextPath: %{public}s", contextPath.c_str());

    if (uiWindow_ == nullptr || sessionInfo_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "uiWindow_ or sessionInfo_ is nullptr");
        return;
    }

    if (sessionInfo_->isAsyncModalBinding && isFirstTriggerBindModal_) {
        TAG_LOGD(AAFwkTag::UI_EXT, "Trigger binding UIExtension modal window");
        uiWindow_->TriggerBindModalUIExtension();
        isFirstTriggerBindModal_ = false;
    }
    // sptr<IRemoteObject> parentToken = sessionInfo_->parentToken;
    // Rosen::WMError ret = uiWindow_->NapiSetUIContent(contextPath, env, storage,
    //     Rosen::BackupAndRestoreType::NONE, parentToken);
    // if (ret == Rosen::WMError::WM_OK) {
    //     TAG_LOGD(AAFwkTag::UI_EXT, "AniSetUIContent success");
    // } else {
    //     TAG_LOGE(AAFwkTag::UI_EXT, "AniSetUIContent failed, ret=%{public}d", ret);
    // }
    return;
}

void StsUIExtensionContentSession::TerminateSelf()
{
    TAG_LOGE(AAFwkTag::UI_EXT, "StsUIExtensionContentSession TerminateSelf call");
    //AAFwk::AbilityManagerClient::GetInstance()->TerminateUIExtensionAbility(sessionInfo_);
}

void StsUIExtensionContentSession::SetWindowBackgroundColor(std::string color)
{
    TAG_LOGE(AAFwkTag::UI_EXT, "StsUIExtensionContentSession SetWindowBackgroundColor call");
    //Todo
    // if (uiWindow_ == nullptr) {
    //     TAG_LOGE(AAFwkTag::UI_EXT, "uiWindow_ is nullptr");
    // }
    // Rosen::WMError ret = uiWindow_->SetBackgroundColor(color);
    // if (ret == Rosen::WMError::WM_OK) {
    //     TAG_LOGD(AAFwkTag::UI_EXT, "SetBackgroundColor success");
    // } else {
    //     TAG_LOGE(AAFwkTag::UI_EXT, "SetBackgroundColor failed, ret=%{public}d", ret);
    // }
}

ani_object StsUIExtensionContentSession::GetUIExtensionHostWindowProxy(ani_env* env, ani_object object)
{
    TAG_LOGE(AAFwkTag::UI_EXT, "StsUIExtensionContentSession GetUIExtensionHostWindowProxy call");
    //Todo 
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
    TAG_LOGE(AAFwkTag::UI_EXT, "StsUIExtensionContentSession GetUIExtensionHostWindowProxy call");
    //Todo
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
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetEnv is fail %{public}d", status);
        return ANI_ERROR;
    }

    static const char *className = "LUIExtensionContentSession/UIExtensionContentSession;";
    ani_class cls;
    status = env->FindClass(className, &cls);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::UI_EXT, "FindClass is fail %{public}d", status);
        return ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"terminateSelfSync", ":V", reinterpret_cast<void *>(NativeTerminateSelf)},
        ani_native_function {"sendData", nullptr, reinterpret_cast<void *>(NativeSendData)},
        ani_native_function {"loadContent", nullptr, reinterpret_cast<void *>(NativeLoadContent)},
        ani_native_function {"setWindowBackgroundColor", nullptr,
            reinterpret_cast<void *>(NativeSetWindowBackgroundColor)},
        ani_native_function {"getUIExtensionHostWindowProxy", nullptr,
            reinterpret_cast<void *>(NativeGetUIExtensionHostWindowProxy)},
        ani_native_function {"setReceiveDataCallback", nullptr, reinterpret_cast<void *>(NativeSetReceiveDataCallback)}
    };

    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_BindNativeMethods is fail %{public}d", status);
        return ANI_ERROR;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}