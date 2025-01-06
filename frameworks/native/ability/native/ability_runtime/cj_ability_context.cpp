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

#include "ability_runtime/cj_ability_context.h"

#include "ability_business_error.h"
#include "cj_ability_connect_callback_object.h"
#include "cj_common_ffi.h"
#include "cj_common_ffi.h"
#include "cj_utils_ffi.h"
#include "hilog_tag_wrapper.h"
#include "string_wrapper.h"
#ifdef SUPPORT_SCREEN
#include "ui_content.h"
#endif // SUPPORT_SCREEN
#include "want_params_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {

#ifdef SUPPORT_SCREEN
constexpr const char* ERROR_MSG_INNER = "Inner error.";
#endif // SUPPORT_SCREEN
constexpr const char* UIEXTENSION_TARGET_TYPE_KEY = "ability.want.params.uiExtensionTargetType";
constexpr const char* FLAG_AUTH_READ_URI_PERMISSION = "ability.want.params.uriPermissionFlag";
std::shared_ptr<AbilityRuntime::AbilityContext> CJAbilityContext::GetAbilityContext()
{
    return context_;
}

sptr<IRemoteObject> CJAbilityContext::GetToken()
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    return context_->GetToken();
}

std::string CJAbilityContext::GetPreferencesDir()
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return "";
    }
    return context_->GetPreferencesDir();
}

std::string CJAbilityContext::GetDatabaseDir()
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return "";
    }
    return context_->GetDatabaseDir();
}

std::string CJAbilityContext::GetBundleName()
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return "";
    }
    return context_->GetBundleName();
}

int32_t CJAbilityContext::GetArea()
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->GetArea();
}

std::shared_ptr<AppExecFwk::AbilityInfo> CJAbilityContext::GetAbilityInfo()
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    return context_->GetAbilityInfo();
}

std::shared_ptr<AppExecFwk::HapModuleInfo> CJAbilityContext::GetHapModuleInfo()
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    return context_->GetHapModuleInfo();
}

std::shared_ptr<AppExecFwk::Configuration> CJAbilityContext::GetConfiguration()
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    return context_->GetConfiguration();
}

int32_t CJAbilityContext::StartAbility(const AAFwk::Want& want)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    // -1 is default accountId which is the same as js.
    return context_->StartAbility(want, -1);
}

int32_t CJAbilityContext::StartAbility(const AAFwk::Want& want, const AAFwk::StartOptions& startOptions)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->StartAbility(want, startOptions, -1);
}

int32_t CJAbilityContext::StartAbilityWithAccount(const AAFwk::Want& want, int32_t accountId)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->StartAbilityWithAccount(want, accountId, -1);
}

int32_t CJAbilityContext::StartAbilityWithAccount(
    const AAFwk::Want& want, int32_t accountId, const AAFwk::StartOptions& startOptions)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->StartAbilityWithAccount(want, accountId, startOptions, -1);
}

int32_t CJAbilityContext::StartServiceExtensionAbility(const Want& want)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->StartServiceExtensionAbility(want);
}

int32_t CJAbilityContext::StartServiceExtensionAbilityWithAccount(const Want& want, int32_t accountId)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->StartServiceExtensionAbility(want, accountId);
}

int32_t CJAbilityContext::StopServiceExtensionAbility(const Want& want)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->StopServiceExtensionAbility(want);
}

int32_t CJAbilityContext::StopServiceExtensionAbilityWithAccount(const Want& want, int32_t accountId)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->StopServiceExtensionAbility(want, accountId);
}

int32_t CJAbilityContext::TerminateSelf()
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->TerminateSelf();
}

int32_t CJAbilityContext::TerminateSelfWithResult(const AAFwk::Want& want, int32_t resultCode)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->TerminateAbilityWithResult(want, resultCode);
}

std::tuple<int32_t, bool> CJAbilityContext::IsTerminating()
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return std::make_tuple(ERR_INVALID_INSTANCE_CODE, false);
    }
    return std::make_tuple(SUCCESS_CODE, context_->IsTerminating());
}

bool CJAbilityContext::ConnectAbility(const AAFwk::Want& want, int64_t connectionId)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto connection = new CJAbilityConnectCallback(connectionId);
    return context_->ConnectAbility(want, connection);
}

int32_t CJAbilityContext::ConnectAbilityWithAccount(
    const AAFwk::Want& want, int32_t accountId, int64_t connectionId)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto connection = new CJAbilityConnectCallback(connectionId);
    return context_->ConnectAbilityWithAccount(want, accountId, connection);
}

void CJAbilityContext::DisconnectAbility(const AAFwk::Want& want, int64_t connectionId)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return;
    }
    auto connection = new CJAbilityConnectCallback(connectionId);
    context_->ConnectAbility(want, connection);
}

int32_t CJAbilityContext::StartAbilityForResult(const AAFwk::Want& want, int32_t requestCode, RuntimeTask&& task)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->StartAbilityForResult(want, requestCode, std::move(task));
}

int32_t CJAbilityContext::StartAbilityForResult(
    const AAFwk::Want& want, const AAFwk::StartOptions& startOptions, int32_t requestCode, RuntimeTask&& task)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->StartAbilityForResult(want, startOptions, requestCode, std::move(task));
}

int32_t CJAbilityContext::StartAbilityForResultWithAccount(
    const AAFwk::Want& want, int32_t accountId, int32_t requestCode, RuntimeTask&& task)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->StartAbilityForResultWithAccount(want, accountId, requestCode, std::move(task));
}

int32_t CJAbilityContext::StartAbilityForResultWithAccount(const AAFwk::Want& want, int32_t accountId,
    const AAFwk::StartOptions& startOptions, int32_t requestCode, RuntimeTask&& task)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->StartAbilityForResultWithAccount(want, accountId, startOptions, requestCode, std::move(task));
}

int32_t CJAbilityContext::RequestPermissionsFromUser(
    AppExecFwk::Ability* ability, std::vector<std::string>& permissions, PermissionRequestTask&& task)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return SUCCESS_CODE;
}

#ifdef SUPPORT_GRAPHICS
int32_t CJAbilityContext::SetMissionLabel(const std::string& label)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->SetMissionLabel(label);
}

int32_t CJAbilityContext::SetMissionIcon(const std::shared_ptr<OHOS::Media::PixelMap>& icon)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->SetMissionIcon(icon);
}
#endif

void CJAbilityContext::InheritWindowMode(AAFwk::Want& want)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
#ifdef SUPPORT_GRAPHICS
    // Only split mode need inherit.
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return;
    }
    auto windowMode = context_->GetCurrentWindowMode();
    if (windowMode == AAFwk::AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_PRIMARY ||
        windowMode == AAFwk::AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_SECONDARY) {
        want.SetParam(Want::PARAM_RESV_WINDOW_MODE, windowMode);
    }
    TAG_LOGD(AAFwkTag::CONTEXT, "end, window mode is %{public}d", windowMode);
#endif
}

int32_t CJAbilityContext::RequestDialogService(AAFwk::Want& want, RequestDialogResultTask&& task)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context_->RequestDialogService(want, std::move(task));
}

int32_t CJAbilityContext::SetRestoreEnabled(bool enabled)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    context_->SetRestoreEnabled(enabled);
    return SUCCESS_CODE;
}

int32_t CJAbilityContext::BackToCallerAbilityWithResult(const AAFwk::Want &want, int resultCode, int64_t requestCode)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    return context_->BackToCallerAbilityWithResult(want, resultCode, requestCode);
}

int32_t CJAbilityContext::SetMissionContinueState(const AAFwk::ContinueState &state)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    return context_->SetMissionContinueState(state);
}

int32_t CJAbilityContext::StartAbilityByType(const std::string &type, AAFwk::WantParams &wantParams,
    const std::shared_ptr<CjUIExtensionCallback> &uiExtensionCallbacks)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    TAG_LOGD(AAFwkTag::CONTEXT, "call");
    auto uiContent = context_->GetUIContent();
    if (uiContent == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null uiContent");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    wantParams.SetParam(UIEXTENSION_TARGET_TYPE_KEY, AAFwk::String::Box(type));
    AAFwk::Want want;
    want.SetParams(wantParams);
    if (wantParams.HasParam(FLAG_AUTH_READ_URI_PERMISSION)) {
        int32_t flag = wantParams.GetIntParam(FLAG_AUTH_READ_URI_PERMISSION, 0);
        want.SetFlags(flag);
        wantParams.Remove(FLAG_AUTH_READ_URI_PERMISSION);
    }
    Ace::ModalUIExtensionCallbacks callback;
    callback.onError = [uiExtensionCallbacks](int32_t arg, const std::string &str1, const std::string &str2) {
        uiExtensionCallbacks->OnError(arg);
    };
    callback.onRelease = [uiExtensionCallbacks](int32_t arg) {
        uiExtensionCallbacks->OnRelease(arg);
    };
    callback.onResult = [uiExtensionCallbacks](int32_t arg1, const OHOS::AAFwk::Want arg2) {
        uiExtensionCallbacks->OnResult(arg1, arg2);
    };

    Ace::ModalUIExtensionConfig config;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, callback, config);
    if (sessionId == 0) {
        TAG_LOGE(AAFwkTag::CONTEXT, "createModalUIExtension failed");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    uiExtensionCallbacks->SetUIContent(uiContent);
    uiExtensionCallbacks->SetSessionId(sessionId);
    return ERR_OK;
}

int32_t CJAbilityContext::MoveUIAbilityToBackground()
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    return context_->MoveUIAbilityToBackground();
}

int32_t CJAbilityContext::ReportDrawnCompleted()
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    return context_->ReportDrawnCompleted();
}

int32_t CJAbilityContext::OpenAtomicService(AAFwk::Want& want, const AAFwk::StartOptions &options,
    int requestCode, RuntimeTask &&task)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    return context_->OpenAtomicService(want, options, requestCode, std::move(task));
}

bool CJAbilityContext::CreateOpenLinkTask(RuntimeTask &&task, int32_t requestCode,
    AAFwk::Want &want, int &nativeRequestCode)
{
    want.SetParam(Want::PARAM_RESV_FOR_RESULT, true);
    nativeRequestCode = requestCode;
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return false;
    }
    context_->InsertResultCallbackTask(nativeRequestCode, std::move(task));
    return true;
}

int32_t CJAbilityContext::OpenLink(const AAFwk::Want& want, int requestCode)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    return context_->OpenLink(want, requestCode);
}

int32_t CJAbilityContext::ChangeAbilityVisibility(bool isShow)
{
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    return context_->ChangeAbilityVisibility(isShow);
}

void CjUIExtensionCallback::SetSessionId(int32_t sessionId)
{
    sessionId_ = sessionId;
}
#ifdef SUPPORT_SCREEN
void CjUIExtensionCallback::SetUIContent(Ace::UIContent* uiContent)
{
    uiContent_ = uiContent;
}

void CjUIExtensionCallback::SetCjCallbackOnResult(std::function<void(CJAbilityResult)> onResultCallback)
{
    onResultCallback_ = onResultCallback;
}

void CjUIExtensionCallback::SetCjCallbackOnError(std::function<void(int32_t, char*, char*)> onErrorCallback)
{
    onErrorCallback_ = onErrorCallback;
}

void CjUIExtensionCallback::OnError(int32_t number)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "call");
    CallCjError(number);
    if (uiContent_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "uiContent_ null");
        return;
    }
    uiContent_->CloseModalUIExtension(sessionId_);
}

void CjUIExtensionCallback::OnResult(int32_t resultCode, const AAFwk::Want &want)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "call");
    CallCjResult(resultCode, want);
    if (uiContent_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "uiContent_ null");
        return;
    }
    uiContent_->CloseModalUIExtension(sessionId_);
}

void CjUIExtensionCallback::CallCjResult(int32_t resultCode, const AAFwk::Want &want)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "call");
    CJAbilityResult abilityResult = { .resultCode = resultCode, .wantHandle = const_cast<AAFwk::Want*>(&want) };
    if (onResultCallback_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "onResultCallback_ is nullptr");
        return;
    }
    onResultCallback_(abilityResult);
}

void CjUIExtensionCallback::OnRelease(int32_t code)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "call, code:%{public}d", code);
    if (uiContent_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "uiContent_ null");
        return;
    }
    uiContent_->CloseModalUIExtension(sessionId_);
}
#endif // SUPPORT_SCREEN
void CjUIExtensionCallback::CallCjError(int32_t number)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "call");
    std::string name;
    std::string message;
#ifdef SUPPORT_SCREEN
    if (number != static_cast<int32_t>(AbilityErrorCode::ERROR_OK)) {
        number = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
        name = ERROR_MSG_INNER;
        message = "StartAbilityByType failed.";
    }
#endif // SUPPORT_SCREEN
    if (onErrorCallback_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "onErrorCallback_ is nullptr");
        return;
    }
    auto cName = CreateCStringFromString(name);
    auto cMessage = CreateCStringFromString(message);
    onErrorCallback_(number, cName, cMessage);
    TAG_LOGI(AAFwkTag::UI_EXT, "end");
}

} // namespace AbilityRuntime
} // namespace OHOS
