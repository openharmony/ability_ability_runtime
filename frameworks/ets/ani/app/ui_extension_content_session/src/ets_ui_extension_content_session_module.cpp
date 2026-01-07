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

#include "ets_ui_extension_content_session_module.h"

#include <cstdio>
#include <sys/syscall.h>
#include <unistd.h>

#include "ani_base_context.h"
#include "ani_common_util.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "js_runtime_utils.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
const char *UI_EXTENSION_CONTENT_SESSION_CLASS_NAME =
    "@ohos.app.ability.UIExtensionContentSession.UIExtensionContentSession";
} // namespace

ani_object EtsUiExtensionContentSessionModule::NativeTransferStatic(ani_env *aniEnv, ani_object, ani_object input)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UI_EXT, "transfer static ServiceExtensionContext");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null aniEnv");
        return nullptr;
    }

    void *unwrapResult = nullptr;
    bool success = arkts_esvalue_unwrap(aniEnv, input, &unwrapResult);
    if (!success) {
        TAG_LOGE(AAFwkTag::UI_EXT, "failed to unwrap");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }
    if (unwrapResult == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null unwrapResult");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto jsSession = reinterpret_cast<JsUIExtensionContentSession *>(unwrapResult);
    if (jsSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null JsUIExtensionContentSession");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }
    std::weak_ptr<Context> weakContext = jsSession->GetContext();
    if (weakContext.lock() == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "context is null");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    auto abilityResultListeners = std::make_shared<EtsAbilityResultListeners>();
    EtsUIExtensionContentSession *etsSession = new (std::nothrow) EtsUIExtensionContentSession(
        jsSession->GetSessionInfo(), jsSession->GetUIWindow(), weakContext, abilityResultListeners);
    if (etsSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "create etsSession failed");
        return nullptr;
    }

    ani_object sessionObj = EtsUIExtensionContentSession::CreateEtsUIExtensionContentSession(aniEnv, etsSession);
    if (sessionObj == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateEtsUIExtensionContentSession failed");
        delete etsSession;
    }
    return sessionObj;
}

ani_object EtsUiExtensionContentSessionModule::NativeTransferDynamic(
    ani_env *aniEnv, ani_class aniCls, ani_object input)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UI_EXT, "transfer dynamic UiExtensionContentSession");
    if (!IsInstanceOf(aniEnv, input)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "not UiExtensionContentSession");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }
    auto etsContentSession = EtsUIExtensionContentSession::GetEtsContentSession(aniEnv, input);
    if (etsContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null etsContentSession");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    ani_object object = CreateDynamicObject(aniEnv, aniCls, etsContentSession);
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "invalid object");
        EtsErrorUtil::ThrowEtsTransferClassError(aniEnv);
        return nullptr;
    }

    return object;
}

ani_object EtsUiExtensionContentSessionModule::CreateDynamicObject(
    ani_env *aniEnv, ani_class aniCls, EtsUIExtensionContentSession *etsContentSession)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    // get napiEnv from aniEnv
    napi_env napiEnv = {};
    if (!arkts_napi_scope_open(aniEnv, &napiEnv)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "arkts_napi_scope_open failed");
        return nullptr;
    }
    auto abilityResultListeners = std::make_shared<AbilityResultListeners>();
    std::weak_ptr<Context> weakContext = etsContentSession->GetContext();
    if (weakContext.lock() == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "context is null");
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }
    napi_value nativeContentSession = JsUIExtensionContentSession::CreateJsUIExtensionContentSession(napiEnv,
        etsContentSession->GetSessionInfo(), etsContentSession->GetUIWindow(), weakContext, abilityResultListeners);
    if (nativeContentSession == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "create JsUIExtensionContentSession failed");
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    hybridgref ref = nullptr;
    bool success = hybridgref_create_from_napi(napiEnv, nativeContentSession, &ref);
    if (!success) {
        TAG_LOGE(AAFwkTag::UI_EXT, "hybridgref_create_from_napi failed");
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    ani_object result = nullptr;
    success = hybridgref_get_esvalue(aniEnv, ref, &result);
    if (!success) {
        TAG_LOGE(AAFwkTag::UI_EXT, "hybridgref_get_esvalue failed");
        hybridgref_delete_from_napi(napiEnv, ref);
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }

    hybridgref_delete_from_napi(napiEnv, ref);

    if (!arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "arkts_napi_scope_close_n failed");
        return nullptr;
    }

    return result;
}

bool EtsUiExtensionContentSessionModule::IsInstanceOf(ani_env *aniEnv, ani_object aniObj)
{
    ani_class cls {};
    ani_status status = ANI_ERROR;
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null aniEnv");
        return false;
    }
    if ((status = aniEnv->FindClass(UI_EXTENSION_CONTENT_SESSION_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "FindClass status: %{public}d", status);
        return false;
    }
    ani_boolean isInstanceOf = false;
    if ((status = aniEnv->Object_InstanceOf(aniObj, cls, &isInstanceOf)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Object_InstanceOf status: %{public}d", status);
        return false;
    }
    return isInstanceOf;
}

void EtsUiExtensionContentSessionModuleInit(ani_env *aniEnv)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "Init ServiceExtensionContext kit");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null ani env");
        return;
    }

    ani_class uiExtSessionCls = nullptr;
    auto status = aniEnv->FindClass(UI_EXTENSION_CONTENT_SESSION_CLASS_NAME, &uiExtSessionCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "FindClass ServiceExtensionContext failed status: %{public}d", status);
        return;
    }

    std::array nativeFuncs = {
        ani_native_function { "nativeTransferStatic", "C{std.interop.ESValue}:C{std.core.Object}",
            reinterpret_cast<void *>(EtsUiExtensionContentSessionModule::NativeTransferStatic) },
        ani_native_function { "nativeTransferDynamic", "C{std.core.Object}:C{std.interop.ESValue}",
            reinterpret_cast<void *>(EtsUiExtensionContentSessionModule::NativeTransferDynamic) },
    };
    status = aniEnv->Class_BindStaticNativeMethods(uiExtSessionCls, nativeFuncs.data(), nativeFuncs.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_BindStaticNativeMethods failed status: %{public}d", status);
        return;
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "Init ServiceExtensionContext kit end");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "ANI_Constructor");
    if (vm == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null vm");
        return ANI_ERROR;
    }

    ani_env *aniEnv = nullptr;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &aniEnv);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    }

    EtsUiExtensionContentSessionModuleInit(aniEnv);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::UI_EXT, "ANI_Constructor finish");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS
