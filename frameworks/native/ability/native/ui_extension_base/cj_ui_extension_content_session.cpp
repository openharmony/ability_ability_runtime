/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cj_ui_extension_content_session.h"

#include "cj_common_ffi.h"
#include "cj_ui_extension_object.h"
#include "cj_ui_extension_context.h"
#include "cj_lambda.h"
#include "ability_business_error.h"
#include "ability_manager_client.h"
#include "accesstoken_kit.h"
#include "event_handler.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "string_wrapper.h"
#include "tokenid_kit.h"
#ifdef SUPPORT_SCREEN
#include "ui_content.h"
#endif // SUPPORT_SCREEN
#include "want.h"
#include "window.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* PERMISSION_PRIVACY_WINDOW = "ohos.permission.PRIVACY_WINDOW";
const std::string UIEXTENSION_TARGET_TYPE_KEY = "ability.want.params.uiExtensionTargetType";
const std::string FLAG_AUTH_READ_URI_PERMISSION = "ability.want.params.uriPermissionFlag";
} // namespace

CJUIExtensionContentSession::CJUIExtensionContentSession(
    sptr<AAFwk::SessionInfo> sessionInfo, sptr<Rosen::Window> uiWindow,
    std::weak_ptr<AbilityRuntime::Context> context)
    : sessionInfo_(sessionInfo), uiWindow_(uiWindow), context_(context)
{
}

sptr<CJUIExtensionContentSession> CJUIExtensionContentSession::Create(sptr<AAFwk::SessionInfo> sessionInfo,
    sptr<Rosen::Window> uiWindow, std::weak_ptr<AbilityRuntime::Context> context)
{
    return FFI::FFIData::Create<CJUIExtensionContentSession>(sessionInfo, uiWindow, context);
}

int32_t CJUIExtensionContentSession::LoadContent(const std::string& path)
{
    if (sessionInfo_->isAsyncModalBinding && isFirstTriggerBindModal_) {
        TAG_LOGD(AAFwkTag::UI_EXT, "Trigger binding UIExtension modal window");
        uiWindow_->TriggerBindModalUIExtension();
        isFirstTriggerBindModal_ = false;
    }
    Rosen::WMError ret = uiWindow_->NapiSetUIContent(path, nullptr, nullptr,
        Rosen::BackupAndRestoreType::NONE, sessionInfo_->parentToken);
    if (ret != Rosen::WMError::WM_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "NapiSetUIContent failed, ret=%{public}d", ret);
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "NapiSetUIContent success");
    return SUCCESS_CODE;
}

int32_t CJUIExtensionContentSession::TerminateSelf()
{
    return AAFwk::AbilityManagerClient::GetInstance()->TerminateUIExtensionAbility(sessionInfo_);
}

int32_t CJUIExtensionContentSession::TerminateSelfWithResult(AAFwk::Want* want, int32_t resultCode)
{
    auto extensionContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(context_.lock());
    if (!extensionContext) {
        TAG_LOGE(AAFwkTag::UI_EXT, "extensionContext is nullptr");
    } else {
        auto token = extensionContext->GetToken();
        AAFwk::AbilityManagerClient::GetInstance()->TransferAbilityResultForExtension(token, resultCode, *want);
    }

    if (uiWindow_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "uiWindow_ is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto ret = uiWindow_->TransferAbilityResult(resultCode, *want);
    if (ret != Rosen::WMError::WM_OK) {
        return ERR_INVALID_INSTANCE_CODE;
    }

    return AAFwk::AbilityManagerClient::GetInstance()->TerminateUIExtensionAbility(sessionInfo_);
}

int32_t CJUIExtensionContentSession::SetWindowPrivacyMode(bool isPrivacyMode)
{
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    int ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(selfToken, PERMISSION_PRIVACY_WINDOW);
    if (ret != Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_PERMISSION_DENIED);
    }

    if (uiWindow_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null uiWindow");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto retCode = uiWindow_->SetPrivacyMode(isPrivacyMode);
    if (retCode == Rosen::WMError::WM_OK) {
        return SUCCESS_CODE;
    }
    return ERR_INVALID_INSTANCE_CODE;
}

int32_t CJUIExtensionContentSession::StartAbilityByType(const std::string &type, AAFwk::WantParams &wantParam,
    const std::shared_ptr<CjUIExtensionCallback> &uiExtensionCallbacks)
{
    if (uiWindow_ == nullptr || uiWindow_->GetUIContent() == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null uiContent");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }

    wantParam.SetParam(UIEXTENSION_TARGET_TYPE_KEY, AAFwk::String::Box(type));
    AAFwk::Want want;
    want.SetParams(wantParam);
    if (wantParam.HasParam(FLAG_AUTH_READ_URI_PERMISSION)) {
        want.SetFlags(wantParam.GetIntParam(FLAG_AUTH_READ_URI_PERMISSION, 0));
        wantParam.Remove(FLAG_AUTH_READ_URI_PERMISSION);
    }

#ifdef SUPPORT_SCREEN
    InitDisplayId(want);
#endif

    auto uiContent = uiWindow_->GetUIContent();
    Ace::ModalUIExtensionCallbacks callback;
    callback.onError = [uiExtensionCallbacks](int arg, const std::string &str1, const std::string &str2) {
        uiExtensionCallbacks->OnError(arg);
    };
    callback.onRelease = [uiExtensionCallbacks](const auto &arg) {
        uiExtensionCallbacks->OnRelease(arg);
    };
    Ace::ModalUIExtensionConfig config;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, callback, config);
    if (sessionId == 0) {
        TAG_LOGE(AAFwkTag::UI_EXT, "createModalUIExtension failed");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }
    uiExtensionCallbacks->SetUIContent(uiContent);
    uiExtensionCallbacks->SetSessionId(sessionId);
    return static_cast<int32_t>(AbilityErrorCode::ERROR_OK);
}

#ifdef SUPPORT_SCREEN
void CJUIExtensionContentSession::InitDisplayId(AAFwk::Want &want)
{
    auto context = AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(context_.lock());
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return;
    }

    auto window = context->GetWindow();
    if (window == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null window");
        return;
    }

    TAG_LOGI(AAFwkTag::UI_EXT, "window displayId %{public}" PRIu64, window->GetDisplayId());
    want.SetParam(AAFwk::Want::PARAM_RESV_DISPLAY_ID, static_cast<int32_t>(window->GetDisplayId()));
}
#endif // SUPPORT_SCREEN

extern "C" {
CJ_EXPORT int32_t FFICJExtSessionLoadContent(int64_t sessionId, const char* path)
{
    if (path == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param path is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto session = FFI::FFIData::GetData<CJUIExtensionContentSession>(sessionId);
    if (session == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null CJUIExtensionContentSession");
        return ERR_INVALID_INSTANCE_CODE;
    }

    return session->LoadContent(std::string(path));
}

CJ_EXPORT int32_t FFICJExtSessionTerminateSelf(int64_t sessionId)
{
    auto session = FFI::FFIData::GetData<CJUIExtensionContentSession>(sessionId);
    if (session == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null CJUIExtensionContentSession");
        return ERR_INVALID_INSTANCE_CODE;
    }

    return session->TerminateSelf();
}

CJ_EXPORT int32_t FFICJExtSessionTerminateSelfWithResult(int64_t sessionId, WantHandle want, int32_t resultCode)
{
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param want is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto session = FFI::FFIData::GetData<CJUIExtensionContentSession>(sessionId);
    if (session == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null CJUIExtensionContentSession");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);

    return session->TerminateSelfWithResult(actualWant, resultCode);
}

CJ_EXPORT int32_t FFICJExtSessionSetWindowPrivacyMode(int64_t sessionId, bool isPrivacyMode)
{
    auto session = FFI::FFIData::GetData<CJUIExtensionContentSession>(sessionId);
    if (session == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null CJUIExtensionContentSession");
        return ERR_INVALID_INSTANCE_CODE;
    }

    return session->SetWindowPrivacyMode(isPrivacyMode);
}

CJ_EXPORT int32_t FFICJExtSessionStartAbilityByType(int64_t sessionId, char* cType, char* cWantParams,
    void (*onError)(int32_t, char*, char*), void (*onResult)(CJAbilityResult))
{
    if (cType == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param cType is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    if (cWantParams == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param cWantParams is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    if (onError == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param onError is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    if (onResult == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param onResult is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto session = FFI::FFIData::GetData<CJUIExtensionContentSession>(sessionId);
    if (session == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null CJUIExtensionContentSession");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto wantParam = AAFwk::WantParamWrapper::ParseWantParamsWithBrackets(cWantParams);
    auto callback = std::make_shared<CjUIExtensionCallback>();
    callback->SetCjCallbackOnResult(CJLambda::Create(onResult));
    callback->SetCjCallbackOnError(CJLambda::Create(onError));
    return session->StartAbilityByType(std::string(cType), wantParam, callback);
}
} // extern "C"
} // namespace AbilityRuntime
} // namespace OHOS
