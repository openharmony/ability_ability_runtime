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

#include "ets_fill_request_callback.h"

#include "ability_manager_client.h"
#include "ani_common_util.h"
#include "ani_enum_convert.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *WANT_PARAMS_VIEW_DATA = "ohos.ability.params.viewData";
constexpr const char *WANT_PARAMS_AUTO_FILL_CMD = "ohos.ability.params.autoFillCmd";
constexpr const char *WANT_PARAMS_AUTO_FILL_CMD_AUTOFILL = "autofill";
constexpr const char *WANT_PARAMS_UPDATE_POPUP_WIDTH = "ohos.ability.params.popupWidth";
constexpr const char *WANT_PARAMS_UPDATE_POPUP_HEIGHT = "ohos.ability.params.popupHeight";
constexpr const char *WANT_PARAMS_UPDATE_POPUP_PLACEMENT = "ohos.ability.params.popupPlacement";
constexpr const char *CONFIG_POPUP_SIZE = "popupSize";
constexpr const char *CONFIG_POPUP_PLACEMENT = "placement";
constexpr const char *WANT_PARAMS_FILL_CONTENT = "ohos.ability.params.fillContent";
constexpr const char *ERROR_MSG_INVALID_EMPTY = "JsonString is empty.";
constexpr const char *ERROR_MSG_PARAMETER_INVALID =
    "The storeld can consist of only letters, digits, and underscores(_), and cannot exceed 128 characters.";
constexpr const char *FILL_REQUEST_CALL_BACK_CLASS_NAME = "Lapplication/AutoFillRequest/FillRequestCallbackInner;";
constexpr const char *CLEANER_CLASS = "Lapplication/AutoFillRequest/Cleaner;";
}

EtsFillRequestCallback::EtsFillRequestCallback(
    sptr<AAFwk::SessionInfo> sessionInfo, sptr<Rosen::Window> uiWindow)
    : sessionInfo_(sessionInfo), uiWindow_(uiWindow)
{}

ani_object EtsFillRequestCallback::SetEtsFillRequestCallback(ani_env *env, sptr<AAFwk::SessionInfo> sessionInfo,
    sptr<Rosen::Window> uiWindow)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return nullptr;
    }
    if (sessionInfo == nullptr || uiWindow == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null sessionInfo or uiWindow");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(FILL_REQUEST_CALL_BACK_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "find class status: %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "J:V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "find method status: %{public}d", status);
        return nullptr;
    }
    auto etsFillRequestCallback = new (std::nothrow) EtsFillRequestCallback(sessionInfo, uiWindow);
    if (etsFillRequestCallback == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "etsFillRequestCallback nullptr");
        return nullptr;
    }
    ani_object contextObj = nullptr;
    if ((status = env->Object_New(cls, method, &contextObj, reinterpret_cast<ani_long>(etsFillRequestCallback)))
        != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "new object status: %{public}d", status);
        delete etsFillRequestCallback;
        etsFillRequestCallback = nullptr;
        return nullptr;
    }
    return contextObj;
}

EtsFillRequestCallback *EtsFillRequestCallback::GetEtsFillRequestCallback(ani_env *env, ani_object object)
{
    if (env == nullptr || object == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env or object");
        return nullptr;
    }
    ani_long fillRequestCallbackInnerPtr = 0;
    ani_status status = env->Object_GetFieldByName_Long(object, "fillRequestCallbackInnerPtr",
        &fillRequestCallbackInnerPtr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "fillRequestCallbackInnerPtr GetField status: %{public}d", status);
        return nullptr;
    }
    auto etsFillRequestCallback = reinterpret_cast<EtsFillRequestCallback *>(fillRequestCallbackInnerPtr);
    if (etsFillRequestCallback == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "etsFillRequestCallback null");
        return nullptr;
    }
    return etsFillRequestCallback;
}

void EtsFillRequestCallback::Clean(ani_env *env, ani_object object)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return;
    }
    ani_long ptr = 0;
    ani_status status = env->Object_GetFieldByName_Long(object, "ptr", &ptr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "ptr GetField status: %{public}d", status);
        return;
    }
    if (ptr != 0) {
        delete reinterpret_cast<EtsFillRequestCallback *>(ptr);
    }
}

void EtsFillRequestCallback::FillRequestSuccess(ani_env *env, ani_object object, ani_object responseObj)
{
    auto etsFillRequestCallback = GetEtsFillRequestCallback(env, object);
    if (etsFillRequestCallback == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null etsFillRequestCallback");
        return;
    }
    etsFillRequestCallback->OnFillRequestSuccess(env, object, responseObj);
}

void EtsFillRequestCallback::FillRequestFailed(ani_env *env, ani_object object)
{
    auto etsFillRequestCallback = GetEtsFillRequestCallback(env, object);
    if (etsFillRequestCallback == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null etsFillRequestCallback");
        return;
    }
    etsFillRequestCallback->OnFillRequestFailed(env, object);
}

void EtsFillRequestCallback::FillRequestCanceled(ani_env *env, ani_object object, ani_object fillContentObj)
{
    auto etsFillRequestCallback = GetEtsFillRequestCallback(env, object);
    if (etsFillRequestCallback == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null etsFillRequestCallback");
        return;
    }
    etsFillRequestCallback->OnFillRequestCanceled(env, object, fillContentObj);
}

void EtsFillRequestCallback::FillRequestAutoFillPopupConfig(ani_env *env, ani_object object,
    ani_object autoFillPopupConfigObj)
{
    auto etsFillRequestCallback = GetEtsFillRequestCallback(env, object);
    if (etsFillRequestCallback == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null etsFillRequestCallback");
        return;
    }
    etsFillRequestCallback->OnFillRequestAutoFillPopupConfig(env, object, autoFillPopupConfigObj);
}

void EtsFillRequestCallback::OnFillRequestSuccess(ani_env *env, ani_object object, ani_object responseObj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return;
    }
    FillResponse response;
    EtsAutoFillExtensionUtil::UnwrapFillResponse(env, responseObj, response);
    std::string jsonString = response.viewData.ToJsonString();
    if (jsonString.empty()) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "empty jsonString");
        EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        SendResultCodeAndViewData(EtsAutoFillExtensionUtil::AutoFillResultCode::CALLBACK_FAILED_INVALID_PARAM, "");
        return;
    }
    SendResultCodeAndViewData(EtsAutoFillExtensionUtil::AutoFillResultCode::CALLBACK_SUCESS, jsonString);
}

void EtsFillRequestCallback::OnFillRequestFailed(ani_env *env, ani_object object)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return;
    }
    SendResultCodeAndViewData(EtsAutoFillExtensionUtil::AutoFillResultCode::CALLBACK_FAILED, "");
}

void EtsFillRequestCallback::OnFillRequestCanceled(ani_env *env, ani_object object, ani_object fillContentObj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return;
    }
    ani_status status = ANI_OK;
    ani_boolean isFillContentUndefined;
    if ((status = env->Reference_IsUndefined(fillContentObj, &isFillContentUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "Falied to check undefinde status: %{public}d", status);
        SendResultCodeAndViewData(EtsAutoFillExtensionUtil::AutoFillResultCode::CALLBACK_FAILED_INVALID_PARAM, "");
        return;
    }
    if (isFillContentUndefined) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "parse fillContent failed");
        EtsErrorUtil::ThrowError(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            ERROR_MSG_PARAMETER_INVALID);
        SendResultCodeAndViewData(EtsAutoFillExtensionUtil::AutoFillResultCode::CALLBACK_FAILED_INVALID_PARAM, "");
        return;
    }
    std::string jsonString = "";
    if (!AppExecFwk::GetStdString(env, reinterpret_cast<ani_string>(fillContentObj), jsonString)) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "empty jsonString");
        EtsErrorUtil::ThrowError(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            ERROR_MSG_INVALID_EMPTY);
        SendResultCodeAndViewData(EtsAutoFillExtensionUtil::AutoFillResultCode::CALLBACK_FAILED_INVALID_PARAM, "");
        return;
    }
    SendResultCodeAndViewData(EtsAutoFillExtensionUtil::AutoFillResultCode::CALLBACK_CANCEL, jsonString);
}

void EtsFillRequestCallback::OnFillRequestAutoFillPopupConfig(ani_env *env, ani_object object,
    ani_object autoFillPopupConfigObj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return;
    }
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "Non-system app forbidden to call");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP);
        return;
    }
    if (uiWindow_ == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null uiWindow");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    AAFwk::WantParams wantParams;
    wantParams.SetParam(WANT_PARAMS_AUTO_FILL_CMD, AAFwk::Integer::Box(AutoFillCommand::RESIZE));
    auto isValueChanged = SetPopupConfigToWantParams(env, autoFillPopupConfigObj, wantParams);
    if (isValueChanged) {
        auto ret = uiWindow_->TransferExtensionData(wantParams);
        if (ret != Rosen::WMError::WM_OK) {
            TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "Transfer ability result failed");
            EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        }
    }
}

bool EtsFillRequestCallback::SetPopupConfigToWantParams(ani_env *env, ani_object autoFillPopupConfigObj,
    AAFwk::WantParams& wantParams)
{
    ani_ref etsValue = nullptr;
    bool isValueChanged = false;
    if (AppExecFwk::GetRefProperty(env, autoFillPopupConfigObj, CONFIG_POPUP_SIZE, etsValue) && etsValue) {
        PopupSize popupSize;
        EtsAutoFillExtensionUtil::UnwrapPopupSize(env, static_cast<ani_object>(etsValue), popupSize);
        wantParams.SetParam(WANT_PARAMS_UPDATE_POPUP_WIDTH, AAFwk::Integer::Box(popupSize.width));
        wantParams.SetParam(WANT_PARAMS_UPDATE_POPUP_HEIGHT, AAFwk::Integer::Box(popupSize.height));
        isValueChanged = true;
    }
    etsValue = nullptr;
    if (AppExecFwk::GetRefProperty(env, autoFillPopupConfigObj, CONFIG_POPUP_PLACEMENT, etsValue) && etsValue) {
        int32_t popupPlacement = 0;
        AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(env, static_cast<ani_enum_item>(etsValue), popupPlacement);
        wantParams.SetParam(WANT_PARAMS_UPDATE_POPUP_PLACEMENT, AAFwk::Integer::Box(popupPlacement));
        isValueChanged = true;
    }
    return isValueChanged;
}

void EtsFillRequestCallback::SendResultCodeAndViewData(const EtsAutoFillExtensionUtil::AutoFillResultCode &resultCode,
    const std::string &etsString)
{
    if (uiWindow_ == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null uiWindow");
        return;
    }

    AAFwk::Want want;
    if (resultCode == EtsAutoFillExtensionUtil::AutoFillResultCode::CALLBACK_SUCESS) {
        want.SetParam(WANT_PARAMS_VIEW_DATA, etsString);
        want.SetParam(WANT_PARAMS_AUTO_FILL_CMD, WANT_PARAMS_AUTO_FILL_CMD_AUTOFILL);
    }

    if (resultCode == EtsAutoFillExtensionUtil::AutoFillResultCode::CALLBACK_CANCEL) {
        want.SetParam(WANT_PARAMS_FILL_CONTENT, etsString);
    }

    auto ret = uiWindow_->TransferAbilityResult(resultCode, want);
    if (ret != Rosen::WMError::WM_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "TransferAbilityResult failed");
        return;
    }

    auto errorCode = AAFwk::AbilityManagerClient::GetInstance()->TerminateUIExtensionAbility(sessionInfo_);
    if (errorCode != ERR_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "TerminateUIExtensionAbility error: %{public}d", errorCode);
    }
}

ani_object EtsFillRequestCallback::CreateEtsFillRequestCallback(ani_env *env,
    sptr<AAFwk::SessionInfo> sessionInfo, sptr<Rosen::Window> uiWindow)
{
    if (env == nullptr || sessionInfo == nullptr || uiWindow == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env, sessionInfo or uiWindow");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(FILL_REQUEST_CALL_BACK_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "find class status: %{public}d", status);
        return nullptr;
    }
    std::array functions = {
        ani_native_function { "onSuccess", "Lapplication/AutoFillRequest/FillResponse;:V",
            reinterpret_cast<void*>(EtsFillRequestCallback::FillRequestSuccess) },
        ani_native_function { "onFailure", ":V",
            reinterpret_cast<void*>(EtsFillRequestCallback::FillRequestFailed) },
        ani_native_function { "onCancel", "Lstd/core/String;:V",
            reinterpret_cast<void*>(EtsFillRequestCallback::FillRequestCanceled) },
        ani_native_function { "setAutoFillPopupConfig", "Lapplication/AutoFillPopupConfig/AutoFillPopupConfig;:V",
            reinterpret_cast<void*>(EtsFillRequestCallback::FillRequestAutoFillPopupConfig) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK
        && status != ANI_ALREADY_BINDED) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "bind method status : %{public}d", status);
        return nullptr;
    }
    ani_class cleanerCls = nullptr;
    if ((status = env->FindClass(CLEANER_CLASS, &cleanerCls)) != ANI_OK || cleanerCls == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "Cleaner FindClass failed status: %{public}d, or null cleanerCls", status);
        return nullptr;
    }
    std::array cleanerMethods = {
        ani_native_function {"clean", nullptr, reinterpret_cast<void *>(EtsFillRequestCallback::Clean) },
    };
    if ((status = env->Class_BindNativeMethods(cleanerCls, cleanerMethods.data(), cleanerMethods.size())) !=
        ANI_OK && status != ANI_ALREADY_BINDED) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "cleanerCls Class_BindNativeMethods failed status: %{public}d", status);
        return nullptr;
    }
    ani_object contextObj = SetEtsFillRequestCallback(env, sessionInfo, uiWindow);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null contextObj");
        return nullptr;
    }
    return contextObj;
}
} // namespace AbilityRuntime
} // namespace OHOS