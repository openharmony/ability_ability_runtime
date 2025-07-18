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

#include "ets_ability_lifecycle_callback.h"

#include "hilog_tag_wrapper.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "native_engine/native_engine.h"
#include "sts_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *SIGNATURE_UIABILITY = "L@ohos/app/ability/UIAbility/UIAbility;:V";
constexpr const char *SIGNATURE_UIABILITY_WINDOW_STAGE =
    "L@ohos/app/ability/UIAbility/UIAbility;L@ohos/window/window/WindowStage;:V";
constexpr const char *SIGNATURE_ABILITY_LIFECYCLE_CALLBACK =
    "L@ohos/app/ability/AbilityLifecycleCallback/AbilityLifecycleCallback;";
constexpr const int32_t ERROR_CODE_NULL_ENV = -1;
constexpr const int32_t ERROR_CODE_NULL_CALLBACK = -2;
constexpr const int32_t ERROR_CODE_NULL_REF = -3;
}
EtsAbilityLifecycleCallback::EtsAbilityLifecycleCallback(ani_env *env)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    ani_vm *aniVM = nullptr;
    if (env->GetVM(&aniVM) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetVM failed");
        return;
    }
    vm_ = aniVM;
}

ani_env *EtsAbilityLifecycleCallback::GetAniEnv()
{
    if (vm_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null vm_");
        return nullptr;
    }
    ani_env* env = nullptr;
    if (vm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed");
        return nullptr;
    }
    return env;
}

int32_t EtsAbilityLifecycleCallback::serialNumber_ = 0;

void EtsAbilityLifecycleCallback::CallObjectMethod(const char *methodName,
    const char *signature, std::shared_ptr<STSNativeReference> ability)
{
    ani_env *aniEnv = GetAniEnv();
    if (aniEnv == nullptr || ability == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv or ability");
        return;
    }
    ani_ref aniAbilityRef = ability->aniRef;
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = aniEnv->FindClass(SIGNATURE_ABILITY_LIFECYCLE_CALLBACK, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed to find class, status=%{public}d", status);
        return;
    }

    ani_method method = nullptr;
    if ((status = aniEnv->Class_FindMethod(cls, methodName, signature, &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed to find method, status=%{public}d", status);
        return;
    }

    ani_value aniAbility {};
    aniAbility.r = aniAbilityRef;
    for (const auto &callback : callbacks_) {
        if (callback.second == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null callback");
            return;
        }
        if ((status = aniEnv->Object_CallMethod_Void(
            reinterpret_cast<ani_object>(callback.second), method, aniAbility)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "failed to call method %{public}s, status=%{public}d", methodName, status);
            return;
        }
    }
}

void EtsAbilityLifecycleCallback::CallObjectMethod(const char *methodName, const char *signature,
    std::shared_ptr<STSNativeReference> ability, std::shared_ptr<STSNativeReference> windowStage)
{
    ani_env *aniEnv = GetAniEnv();
    if (aniEnv == nullptr || ability == nullptr || windowStage == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv or ability or windowStage");
        return;
    }
    ani_ref aniAbilityRef = ability->aniRef;
    ani_ref aniWindowStageRef = windowStage->aniRef;
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = aniEnv->FindClass(SIGNATURE_ABILITY_LIFECYCLE_CALLBACK, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed to find class, status=%{public}d", status);
        return;
    }

    ani_method method = nullptr;
    if ((status = aniEnv->Class_FindMethod(cls, methodName, signature, &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed to find method, status=%{public}d", status);
        return;
    }

    ani_value aniAbility {};
    aniAbility.r = aniAbilityRef;
    ani_value aniWindowStage {};
    aniWindowStage.r = aniWindowStageRef;
    for (const auto &callback : callbacks_) {
        if (callback.second == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null callback");
            return;
        }
        if ((status = aniEnv->Object_CallMethod_Void(reinterpret_cast<ani_object>(callback.second),
            method, aniAbility, aniWindowStage)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "failed to call method %{public}s, status=%{public}d", methodName, status);
            return;
        }
    }
}

int32_t EtsAbilityLifecycleCallback::Register(ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "enter EtsAbilityLifecycleCallback::Register");
    ani_env *aniEnv = GetAniEnv();
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv");
        return ERROR_CODE_NULL_ENV;
    }
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv");
        return ERROR_CODE_NULL_CALLBACK;
    }
    int32_t callbackId = serialNumber_;
    if (serialNumber_ < INT32_MAX) {
        serialNumber_++;
    } else {
        serialNumber_ = 0;
    }
    ani_ref ref = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = aniEnv->GlobalReference_Create(callback, &ref)) != ANI_OK || ref == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed to create reference, status=%{public}d", status);
        return ERROR_CODE_NULL_REF;
    }
    callbacks_.emplace(callbackId, ref);
    return callbackId;
}

bool EtsAbilityLifecycleCallback::Unregister(int32_t callbackId)
{
    TAG_LOGI(AAFwkTag::APPKIT, "Unregister callbackId : %{public}d", callbackId);
    return callbacks_.erase(callbackId);
}

void EtsAbilityLifecycleCallback::OnAbilityCreate(std::shared_ptr<STSNativeReference> ability)
{
    CallObjectMethod("onAbilityCreate", SIGNATURE_UIABILITY, ability);
}

void EtsAbilityLifecycleCallback::OnWindowStageCreate(std::shared_ptr<STSNativeReference> ability,
    std::shared_ptr<STSNativeReference> windowStage)
{
    CallObjectMethod("onWindowStageCreate", SIGNATURE_UIABILITY_WINDOW_STAGE, ability, windowStage);
}

void EtsAbilityLifecycleCallback::OnWindowStageDestroy(std::shared_ptr<STSNativeReference> ability,
    std::shared_ptr<STSNativeReference> windowStage)
{
    CallObjectMethod("onWindowStageDestroy", SIGNATURE_UIABILITY_WINDOW_STAGE, ability, windowStage);
}

void EtsAbilityLifecycleCallback::OnAbilityDestroy(std::shared_ptr<STSNativeReference> ability)
{
    CallObjectMethod("onAbilityDestroy", SIGNATURE_UIABILITY, ability);
}

void EtsAbilityLifecycleCallback::OnAbilityForeground(std::shared_ptr<STSNativeReference> ability)
{
    CallObjectMethod("onAbilityForeground", SIGNATURE_UIABILITY, ability);
}

void EtsAbilityLifecycleCallback::OnAbilityBackground(std::shared_ptr<STSNativeReference> ability)
{
    CallObjectMethod("onAbilityBackground", SIGNATURE_UIABILITY, ability);
}

}  // namespace AbilityRuntime
}  // namespace OHOS