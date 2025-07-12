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

#include "ets_ui_extension_callback.h"

#include "ability_business_error.h"
#include "ani_common_ability_result.h"
#include "hilog_tag_wrapper.h"
#ifdef SUPPORT_SCREEN
#include "ui_content.h"
#include "ws_common.h"
#endif // SUPPORT_SCREEN

namespace OHOS {
namespace AbilityRuntime {
#ifdef SUPPORT_SCREEN
constexpr const char* ERROR_MSG_INNER = "Inner error.";
#endif // SUPPORT_SCREEN

namespace {
constexpr const char *ABILITY_START_CLASS_NAME = "Lapplication/AbilityStartCallback/AbilityStartCallback;";
}

EtsUIExtensionCallback::~EtsUIExtensionCallback()
{
    ani_env *env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    if (callback_ != nullptr) {
        env->GlobalReference_Delete(callback_);
        callback_ = nullptr;
    }
}

void EtsUIExtensionCallback::OnError(int32_t number)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "call");
    auto env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_class clsCall = nullptr;
    if ((status = env->FindClass(ABILITY_START_CLASS_NAME, &clsCall)) != ANI_OK || clsCall == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "find AbilityStartCallback class failed, status: %{public}d, or null cls", status);
        return;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(clsCall, "onError", nullptr, &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "find onError method failed, status: %{public}d, or null method", status);
        return;
    }
    std::string name;
    std::string message;
#ifdef SUPPORT_SCREEN
    if (number != static_cast<int32_t>(Rosen::WSError::WS_OK)) {
        number = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
        name = ERROR_MSG_INNER;
        message = "StartAbilityByType failed.";
    }
#endif // SUPPORT_SCREEN
    ani_string aniName;
    if ((status = env->String_NewUTF8(name.c_str(), name.length(), &aniName)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "String_NewUTF8 failed, status: %{public}d", status);
        return;
    }
    ani_string aniMsg;
    if ((status = env->String_NewUTF8(message.c_str(), message.length(), &aniMsg)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "String_NewUTF8 failed, status: %{public}d", status);
        return;
    }
    if ((status = env->Object_CallMethod_Void(reinterpret_cast<ani_object>(callback_),
        method, (ani_double)number, aniName, aniMsg)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "call onError method failed, status: %{public}d", status);
        return;
    }
    CloseModalUIExtension();
}

void EtsUIExtensionCallback::OnResult(int32_t resultCode, const AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "call");
    auto env = GetAniEnv();
    if (env == nullptr || callback_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_object startCallback = reinterpret_cast<ani_object>(callback_);
    ani_ref onResultRef {};
    if ((status = env->Object_GetPropertyByName_Ref(startCallback, "onResult", &onResultRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "get onResult failed, status: %{public}d", status);
        return;
    }
    ani_fn_object onResultFn = reinterpret_cast<ani_fn_object>(onResultRef);
    ani_object abilityResultObj = AppExecFwk::WrapAbilityResult(env, resultCode, want);
    if (abilityResultObj == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "create abilityResultObj failed");
        return;
    }
    ani_ref argv[] = { abilityResultObj };
    ani_ref result;
    if ((status = env->FunctionalObject_Call(onResultFn, 1, argv, &result)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "call onResult fn failed, status: %{public}d", status);
        return;
    }
    CloseModalUIExtension();
}

void EtsUIExtensionCallback::SetEtsCallbackObject(ani_object aniObject)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "SetEtsCallbackObject call");
    ani_env *env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    ani_ref callback = nullptr;
    ani_status status = env->GlobalReference_Create(aniObject, &callback);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GlobalReference_Create failed, status: %{public}d", status);
        return;
    }
    callback_ = callback;
}

ani_env* EtsUIExtensionCallback::GetAniEnv()
{
    TAG_LOGD(AAFwkTag::UI_EXT, "GetAniEnv call");
    if (vm_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null vm_");
        return nullptr;
    }
    ani_env *env = nullptr;
    ani_status status = vm_->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "get env failed, status: %{public}d", status);
        return nullptr;
    }
    return env;
}
}  // namespace AbilityRuntime
}  // namespace OHOS