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

#include "ets_save_request_callback.h"

#include "ability_manager_client.h"
#include "ani_common_util.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *SAVE_REQUEST_CALL_BACK_CLASS_NAME = "Lapplication/AutoFillRequest/SaveRequestCallbackInner;";
constexpr const char *CLEANER_CLASS = "Lapplication/AutoFillRequest/Cleaner;";
}

EtsSaveRequestCallback::EtsSaveRequestCallback(
    sptr<AAFwk::SessionInfo> sessionInfo, sptr<Rosen::Window> uiWindow)
    : sessionInfo_(sessionInfo), uiWindow_(uiWindow)
{}

ani_object EtsSaveRequestCallback::SetEtsSaveRequestCallback(ani_env *env, sptr<AAFwk::SessionInfo> sessionInfo,
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
    if ((status = env->FindClass(SAVE_REQUEST_CALL_BACK_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "find class status: %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "J:V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "find method status: %{public}d", status);
        return nullptr;
    }
    auto etsSaveRequestCallback = new (std::nothrow) EtsSaveRequestCallback(sessionInfo, uiWindow);
    if (etsSaveRequestCallback == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "etsSaveRequestCallback nullptr");
        return nullptr;
    }
    ani_object contextObj = nullptr;
    if ((status = env->Object_New(cls, method, &contextObj, reinterpret_cast<ani_long>(etsSaveRequestCallback)))
        != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "new object status: %{public}d", status);
        delete etsSaveRequestCallback;
        etsSaveRequestCallback = nullptr;
        return nullptr;
    }
    return contextObj;
}

EtsSaveRequestCallback *EtsSaveRequestCallback::GetEtsSaveRequestCallback(ani_env *env, ani_object object)
{
    if (env == nullptr || object == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env or object");
        return nullptr;
    }
    ani_long saveRequestCallbackInnerPtr = 0;
    ani_status status = env->Object_GetFieldByName_Long(object, "saveRequestCallbackInnerPtr",
        &saveRequestCallbackInnerPtr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "saveRequestCallbackInnerPtr GetField status: %{public}d", status);
        return nullptr;
    }
    auto etsSaveRequestCallback = reinterpret_cast<EtsSaveRequestCallback *>(saveRequestCallbackInnerPtr);
    if (etsSaveRequestCallback == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "etsSaveRequestCallback null");
        return nullptr;
    }
    return etsSaveRequestCallback;
}

void EtsSaveRequestCallback::Clean(ani_env *env, ani_object object)
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
        delete reinterpret_cast<EtsSaveRequestCallback *>(ptr);
    }
}

void EtsSaveRequestCallback::SaveRequestSuccess(ani_env *env, ani_object object)
{
    auto etsSaveRequestCallback = GetEtsSaveRequestCallback(env, object);
    if (etsSaveRequestCallback == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null etsSaveRequestCallback");
        return;
    }
    etsSaveRequestCallback->OnSaveRequestSuccess(env, object);
}

void EtsSaveRequestCallback::SaveRequestFailed(ani_env *env, ani_object object)
{
    auto etsSaveRequestCallback = GetEtsSaveRequestCallback(env, object);
    if (etsSaveRequestCallback == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null etsSaveRequestCallback");
        return;
    }
    etsSaveRequestCallback->OnSaveRequestFailed(env, object);
}

void EtsSaveRequestCallback::OnSaveRequestSuccess(ani_env *env, ani_object object)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return;
    }
    SendResultCodeAndViewData(EtsAutoFillExtensionUtil::AutoFillResultCode::CALLBACK_SUCESS);
}

void EtsSaveRequestCallback::OnSaveRequestFailed(ani_env *env, ani_object object)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return;
    }
    SendResultCodeAndViewData(EtsAutoFillExtensionUtil::AutoFillResultCode::CALLBACK_FAILED);
}

void EtsSaveRequestCallback::SendResultCodeAndViewData(const EtsAutoFillExtensionUtil::AutoFillResultCode &resultCode)
{
    if (uiWindow_ == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null uiWindow_");
        return;
    }

    AAFwk::Want want;
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

ani_object EtsSaveRequestCallback::CreateEtsSaveRequestCallback(ani_env *env,
    sptr<AAFwk::SessionInfo> sessionInfo, sptr<Rosen::Window> uiWindow)
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
    if ((status = env->FindClass(SAVE_REQUEST_CALL_BACK_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "find class status: %{public}d", status);
        return nullptr;
    }
    std::array functions = {
        ani_native_function { "onSuccess", ":V",
            reinterpret_cast<void*>(EtsSaveRequestCallback::SaveRequestSuccess) },
        ani_native_function { "onFailure", ":V",
            reinterpret_cast<void*>(EtsSaveRequestCallback::SaveRequestFailed) },
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
        ani_native_function {"clean", nullptr, reinterpret_cast<void *>(EtsSaveRequestCallback::Clean) },
    };
    if ((status = env->Class_BindNativeMethods(cleanerCls, cleanerMethods.data(), cleanerMethods.size())) !=
        ANI_OK && status != ANI_ALREADY_BINDED) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "cleanerCls Class_BindNativeMethods failed status: %{public}d", status);
        return nullptr;
    }
    ani_object contextObj = SetEtsSaveRequestCallback(env, sessionInfo, uiWindow);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null contextObj");
        return nullptr;
    }
    return contextObj;
}
} // namespace AbilityRuntime
} // namespace OHOS