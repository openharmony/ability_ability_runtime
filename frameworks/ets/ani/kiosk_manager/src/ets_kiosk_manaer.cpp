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

#include "ets_kiosk_manager.h"

#include "ability_business_error.h"
#include "ability_context.h"
#include "ability_manager_client.h"
#include "ani_base_context.h"
#include "ani_common_util.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"
#include "kiosk_status.h"

namespace OHOS {
namespace AbilityRuntime {
using AbilityManagerClient = AAFwk::AbilityManagerClient;

constexpr const char* KIOSK_STATUS_CLASS_NAME = "application.KioskStatus.KioskStatusInner";
constexpr const char* KIOSK_MANAGER_CLASS_NAME = "@ohos.app.ability.kioskManager.kioskManager";
constexpr const char* KIOSK_MANAGER_KIOSK_BUNDLE_NAME = "kioskBundleName";
constexpr const char* KIOSK_MANAGER_IS_KIOSK_MODE = "isKioskMode";
constexpr const char* KIOSK_MANAGER_KIOSK_BUNDLE_UID = "kioskBundleUid";
constexpr const char* SIGNATURE_UIABILITY_CALLBACK =
    "C{application.UIAbilityContext.UIAbilityContext}C{utils.AbilityUtils.AsyncCallbackWrapper}:";
constexpr const char* SIGNATURE_UIABILITY = "C{application.UIAbilityContext.UIAbilityContext}:";
constexpr const char* SIGNATURE_CALLBACK = "C{utils.AbilityUtils.AsyncCallbackWrapper}:";

void EnterKioskModeSyncCheck(ani_env *env, ani_object contextObj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, contextObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        EtsErrorUtil::ThrowInvalidParamError(
            env, "Failed to get context, context must not be nullptr.");
        return;
    }
    auto uiAbilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
    if (uiAbilityContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null UIAbilityContext");
        EtsErrorUtil::ThrowInvalidParamError(
            env, "Failed to get uiAbilityContext, uiAbilityContext must not be nullptr.");
        return;
    }
    auto token = uiAbilityContext->GetToken();
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null token");
        EtsErrorUtil::ThrowInvalidParamError(env, "Failed to get token, token must not be nullptr.");
        return;
    }
}

void EnterKioskModeSync(ani_env *env, ani_object contextObj, ani_object callback)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, contextObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        EtsErrorUtil::ThrowInvalidParamError(
            env, "Failed to get context, context must not be nullptr.");
        return;
    }
    auto uiAbilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
    if (uiAbilityContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null UIAbilityContext");
        EtsErrorUtil::ThrowInvalidParamError(
            env, "Failed to get uiAbilityContext, uiAbilityContext must not be nullptr.");
        return;
    }
    auto token = uiAbilityContext->GetToken();
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null token");
        EtsErrorUtil::ThrowInvalidParamError(env, "Failed to get token, token must not be nullptr.");
        return;
    }
    auto errCode = AbilityManagerClient::GetInstance()->EnterKioskMode(token);
    if (errCode != ERR_OK) {
        AppExecFwk::AsyncCallback(
            env, callback, EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(errCode)), nullptr);
        return;
    }
    AppExecFwk::AsyncCallback(env, callback, nullptr, nullptr);
}

void ExitKioskModeSyncCheck(ani_env *env, ani_object contextObj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, contextObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        EtsErrorUtil::ThrowInvalidParamError(
            env, "Failed to get context, context must not be nullptr.");
        return;
    }
    auto uiAbilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
    if (uiAbilityContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null UIAbilityContext");
        EtsErrorUtil::ThrowInvalidParamError(
            env, "Failed to get uiAbilityContext, uiAbilityContext must not be nullptr.");
        return;
    }
    auto token = uiAbilityContext->GetToken();
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null token");
        EtsErrorUtil::ThrowInvalidParamError(
            env, "Failed to get token, token must not be nullptr.");
        return;
    }
}

void ExitKioskModeSync(ani_env *env, ani_object contextObj, ani_object callback)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, contextObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        EtsErrorUtil::ThrowInvalidParamError(
            env, "Failed to get context, context must not be nullptr.");
        return;
    }
    auto uiAbilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
    if (uiAbilityContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null UIAbilityContext");
        EtsErrorUtil::ThrowInvalidParamError(
            env, "Failed to get uiAbilityContext, uiAbilityContext must not be nullptr.");
        return;
    }
    auto token = uiAbilityContext->GetToken();
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null token");
        EtsErrorUtil::ThrowInvalidParamError(
            env, "Failed to get token, token must not be nullptr.");
        return;
    }
    auto errCode = AbilityManagerClient::GetInstance()->ExitKioskMode(token);
    if (errCode != ERR_OK) {
        AppExecFwk::AsyncCallback(
            env, callback, EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(errCode)), nullptr);
        return;
    }
    AppExecFwk::AsyncCallback(env, callback, nullptr, nullptr);
}

ani_object CreateEtsKioskStatus(ani_env *env, std::shared_ptr<AAFwk::KioskStatus> kioskStatus)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    if (kioskStatus == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null kioskStatus");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_method method = nullptr;
    ani_object contextObj = nullptr;
    ani_status status = env->FindClass(KIOSK_STATUS_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_New status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetPropertyByName_Ref(contextObj, KIOSK_MANAGER_KIOSK_BUNDLE_NAME,
        OHOS::AppExecFwk::GetAniString(env, kioskStatus->kioskBundleName_))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "set kioskBundleName failed, status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetPropertyByName_Boolean(
        contextObj, KIOSK_MANAGER_IS_KIOSK_MODE, kioskStatus->isKioskMode_)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "set isKioskMode failed, status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetPropertyByName_Int(
        contextObj, KIOSK_MANAGER_KIOSK_BUNDLE_UID, kioskStatus->kioskBundleUid_)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "set kioskBundleUid failed, status: %{public}d", status);
        return nullptr;
    }
    return contextObj;
}

void GetKioskStatusSync(ani_env *env, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "Get KioskStatus");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    std::shared_ptr<AAFwk::KioskStatus> kioskStatus = std::make_shared<AAFwk::KioskStatus>();
    auto errCode = AbilityManagerClient::GetInstance()->GetKioskStatus(*kioskStatus);
    if (errCode != ERR_OK) {
        AppExecFwk::AsyncCallback(
            env, callback, EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(errCode)), nullptr);
        return;
    }
    auto status = CreateEtsKioskStatus(env, kioskStatus);
    AppExecFwk::AsyncCallback(env, callback, nullptr, status);
}

void EtsKioskManagerInit(ani_env *env)
{
    TAG_LOGI(AAFwkTag::APPKIT, "EtsKioskManagerInit call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "Invalid param");
        return;
    }
    ani_namespace ns;
    if (env->FindNamespace(KIOSK_MANAGER_CLASS_NAME, &ns) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindNamespace failed");
        return;
    }
    if (ns == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "ns null");
        return;
    }
    std::array functions = {
        ani_native_function {
            "nativeEnterKioskMode", SIGNATURE_UIABILITY_CALLBACK,
            reinterpret_cast<void*>(EnterKioskModeSync)
        },
        ani_native_function {
            "nativeEnterKioskModeCheck", SIGNATURE_UIABILITY,
            reinterpret_cast<void*>(EnterKioskModeSyncCheck)
        },
        ani_native_function {
            "nativeExitKioskMode", SIGNATURE_UIABILITY_CALLBACK,
            reinterpret_cast<void*>(ExitKioskModeSync)
        },
        ani_native_function {
            "nativeExitKioskModeCheck", SIGNATURE_UIABILITY,
            reinterpret_cast<void*>(ExitKioskModeSyncCheck)
        },
        ani_native_function {
            "nativeGetKioskStatus", SIGNATURE_CALLBACK,
            reinterpret_cast<void*>(GetKioskStatusSync)
        },

    };
    if (env->Namespace_BindNativeFunctions(ns, functions.data(), functions.size()) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Namespace_BindNativeFunctions failed");
    };
}

extern "C"{
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGI(AAFwkTag::APPKIT, "ANI_Constructor");
    if (vm == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "vm null");
        return ANI_ERROR;
    }
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "result null");
        return ANI_ERROR;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    }
    EtsKioskManagerInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGI(AAFwkTag::APPKIT, "ANI_Constructor finish");
    return ANI_OK;
}
}
} // namespace Ability
} // namespace OHOS