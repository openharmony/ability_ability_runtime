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

#include "ets_panel_start_callback.h"

#include "ability_business_error.h"
#include "ani_common_ability_result.h"
#include "ani_common_util.h"
#include "hilog_tag_wrapper.h"
#ifdef SUPPORT_SCREEN
#include "ui_content.h"
#include "ws_common.h"
#endif  // SUPPORT_SCREEN

namespace OHOS {
namespace AbilityRuntime {
#ifdef SUPPORT_SCREEN
constexpr const char *ERROR_MSG_INNER = "Inner error.";
#endif  // SUPPORT_SCREEN

namespace {
constexpr const char *ABILITY_START_CLASS_NAME =
    "L@ohos/app/ability/verticalPanelManager/verticalPanelManager/PanelStartCallback;";
}

EtsPanelStartCallback::~EtsPanelStartCallback()
{
    ani_env *env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null env");
        return;
    }
    if (callback_ != nullptr) {
        env->GlobalReference_Delete(callback_);
        callback_ = nullptr;
    }
}

#ifdef SUPPORT_SCREEN
void EtsPanelStartCallback::OnError(int32_t number)
{
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "OnError call");
    std::string name;
    std::string message;
    if (number != static_cast<int32_t>(Rosen::WSError::WS_OK)) {
        number = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
        name = ERROR_MSG_INNER;
        message = "StartAbilityByType failed.";
    }
    auto env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null env");
        return;
    }
    ani_string aniName = nullptr;
    ani_status status = env->String_NewUTF8(name.c_str(), name.length(), &aniName);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "aniName String_NewUTF8 failed, status: %{public}d", status);
        return;
    }
    ani_string aniMsg = nullptr;
    if ((status = env->String_NewUTF8(message.c_str(), message.length(), &aniMsg)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "aniMsg String_NewUTF8 failed, status: %{public}d", status);
        return;
    }
    CallObjectMethod("onError", nullptr, (ani_double)number, aniName, aniMsg);
    CloseModalUIExtension();
}

void EtsPanelStartCallback::OnResult(int32_t resultCode, const AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "OnResult call");
    auto env = GetAniEnv();
    if (env == nullptr || callback_ == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null env or callback_");
        return;
    }
    ani_object startCallback = reinterpret_cast<ani_object>(callback_);
    ani_ref onResultRef = nullptr;
    ani_status status = env->Object_GetPropertyByName_Ref(startCallback, "onResult", &onResultRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "Failed to get property: onResult, status: %{public}d", status);
        return;
    }
    ani_boolean isUndefined = true;
    status = env->Reference_IsUndefined(onResultRef, &isUndefined);
    if (status != ANI_OK || isUndefined || onResultRef == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "Failed to check undefined for onResult, status: %{public}d", status);
        return;
    }

    ani_fn_object onResultFn = reinterpret_cast<ani_fn_object>(onResultRef);
    ani_object abilityResultObj = AppExecFwk::WrapAbilityResult(env, resultCode, want);
    if (abilityResultObj == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "create abilityResultObj failed");
        return;
    }
    ani_ref argv[] = {abilityResultObj};
    ani_ref result = nullptr;
    status = env->FunctionalObject_Call(onResultFn, 1, argv, &result);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "call onResult fn failed, status: %{public}d", status);
        return;
    }
    CloseModalUIExtension();
}
#endif  // SUPPORT_SCREEN

void EtsPanelStartCallback::CallObjectMethod(const char *name, const char *signature, ...)
{
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "CallObjectMethod name: %{public}s", name);
    auto env = GetAniEnv();
    if (env == nullptr || callback_ == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null env or callback_");
        return;
    }
    ani_class clsCall = nullptr;
    ani_status status = env->FindClass(ABILITY_START_CLASS_NAME, &clsCall);
    if (status != ANI_OK || clsCall == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL,
            "find AbilityStartCallback class failed, status: %{public}d, or null cls", status);
        return;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(clsCall, name, signature, &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "find onError method failed, status: %{public}d, or null method", status);
        env->ResetError();
        return;
    }
    va_list args;
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(reinterpret_cast<ani_object>(callback_), method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "Object_CallMethod name: %{public}s, status: %{public}d", name, status);
        return;
    }
    va_end(args);
    TAG_LOGI(AAFwkTag::VERTICAL_PANEL, "CallObjectMethod end, name: %{public}s", name);
}

void EtsPanelStartCallback::SetEtsCallbackObject(ani_object aniObject)
{
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "SetEtsCallbackObject call");
    ani_env *env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null env");
        return;
    }
    ani_ref callback = nullptr;
    ani_status status = env->GlobalReference_Create(aniObject, &callback);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "GlobalReference_Create failed, status: %{public}d", status);
        return;
    }
    callback_ = callback;
}

ani_env* EtsPanelStartCallback::GetAniEnv()
{
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "GetAniEnv call");
    if (vm_ == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null vm_");
        return nullptr;
    }
    ani_env *env = nullptr;
    ani_status status = vm_->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "get env failed, status: %{public}d", status);
        return nullptr;
    }
    return env;
}
}  // namespace AbilityRuntime
}  // namespace OHOS