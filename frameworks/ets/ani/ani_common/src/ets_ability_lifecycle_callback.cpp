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

#include "ani_common_util.h"
#include "hilog_tag_wrapper.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "native_engine/native_engine.h"
#include "ets_runtime.h"
#include "ets_native_reference.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *SIGNATURE_UIABILITY = "C{@ohos.app.ability.UIAbility.UIAbility}:";
constexpr const char *SIGNATURE_UIABILITY_WINDOW_STAGE =
    "C{@ohos.app.ability.UIAbility.UIAbility}C{@ohos.window.window.WindowStage}:";
constexpr const int32_t ERROR_CODE_NULL_ENV = -1;
constexpr const int32_t ERROR_CODE_NULL_CALLBACK = -2;
constexpr const int32_t ERROR_CODE_NULL_REF = -3;
constexpr int32_t ARGC_ONE = 1;
constexpr int32_t ARGC_TWO = 2;
}

int32_t EtsAbilityLifecycleCallback::serialNumber_ = 0;

EtsAbilityLifecycleCallback::EtsAbilityLifecycleCallback(ani_env *env)
{
    type_ = AbilityLifecycleCallbackType::ETS;
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

void EtsAbilityLifecycleCallback::CallObjectMethod(const char *methodName,
    const char *signature, std::shared_ptr<AppExecFwk::ETSNativeReference> ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "CallObjectMethod called");
    ani_env *aniEnv = GetAniEnv();
    if (aniEnv == nullptr || ability == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv or ability");
        return;
    }
    ani_status status = ANI_ERROR;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &callback : callbacks_) {
        if (callback.second == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null callback");
            return;
        }
        if ((status = aniEnv->Object_CallMethodByName_Void(
            reinterpret_cast<ani_object>(callback.second), methodName, signature, ability->aniRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "failed to call method %{public}s, status=%{public}d", methodName, status);
            return;
        }
    }
}

void EtsAbilityLifecycleCallback::CallObjectMethod(const char *methodName, const char *signature,
    std::shared_ptr<AppExecFwk::ETSNativeReference> ability,
    std::shared_ptr<AppExecFwk::ETSNativeReference> windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "CallObjectMethod called");
    ani_env *aniEnv = GetAniEnv();
    if (aniEnv == nullptr || ability == nullptr || windowStage == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv or ability or windowStage");
        return;
    }
    ani_status status = ANI_ERROR;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &callback : callbacks_) {
        if (callback.second == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null callback");
            return;
        }
        if ((status = aniEnv->Object_CallMethodByName_Void(
            reinterpret_cast<ani_object>(callback.second), methodName, signature, ability->aniRef,
            windowStage->aniRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "failed to call method %{public}s, status=%{public}d", methodName, status);
            return;
        }
    }
}

void EtsAbilityLifecycleCallback::CallObjectProperty(const char *name,
    std::shared_ptr<AppExecFwk::ETSNativeReference> ability)
{
    ani_env *aniEnv = GetAniEnv();
    if (aniEnv == nullptr || ability == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv or ability");
        return;
    }
    CallObjectPropertyCommon(aniEnv, name, ability->aniRef, nullptr);
}

void EtsAbilityLifecycleCallback::CallObjectProperty(const char *name,
    std::shared_ptr<AppExecFwk::ETSNativeReference> ability,
    std::shared_ptr<AppExecFwk::ETSNativeReference> windowStage)
{
    ani_env *aniEnv = GetAniEnv();
    if (aniEnv == nullptr || ability == nullptr || windowStage == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv or ability or windowStage");
        return;
    }
    CallObjectPropertyCommon(aniEnv, name, ability->aniRef, windowStage->aniRef);
}

void EtsAbilityLifecycleCallback::CallObjectPropertyCommon(ani_env *env, const char *name,
    ani_ref ability, ani_ref windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "CallObjectPropertyCommon called");
    ani_status status = ANI_ERROR;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &callback : callbacks_) {
        if (callback.second == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null callback");
            return;
        }
        ani_ref funRef = nullptr;
        if ((status = env->Object_GetPropertyByName_Ref(reinterpret_cast<ani_object>(callback.second),
            name, &funRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "failed to get property, status : %{public}d", status);
            return;
        }
        if (!AppExecFwk::IsValidProperty(env, funRef)) {
            continue;
        }

        ani_ref result = nullptr;
        if (windowStage != nullptr) {
            std::vector<ani_ref> argv = { ability, windowStage };
            if ((status = env->FunctionalObject_Call(reinterpret_cast<ani_fn_object>(funRef), ARGC_TWO, argv.data(),
                &result)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::APPKIT, "failed to call property, status: %{public}d", status);
            }
        } else {
            std::vector<ani_ref> argv = { ability };
            if ((status = env->FunctionalObject_Call(reinterpret_cast<ani_fn_object>(funRef), ARGC_ONE, argv.data(),
                &result)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::APPKIT, "failed to call property, status: %{public}d", status);
            }
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
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_.emplace(callbackId, ref);
    return callbackId;
}

bool EtsAbilityLifecycleCallback::Unregister(int32_t callbackId)
{
    TAG_LOGI(AAFwkTag::APPKIT, "Unregister callbackId : %{public}d", callbackId);
    std::lock_guard<std::mutex> lock(mutex_);
    auto itr = callbacks_.find(callbackId);
    if (itr != callbacks_.end() && itr->second != nullptr) {
        ani_env *aniEnv = GetAniEnv();
        if (aniEnv != nullptr) {
            aniEnv->GlobalReference_Delete(itr->second);
        }
    }
    return callbacks_.erase(callbackId) == 1;
}

void EtsAbilityLifecycleCallback::OnAbilityCreate(const AbilityLifecycleCallbackArgs &ability)
{
    CallObjectMethod("onAbilityCreate", SIGNATURE_UIABILITY,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_);
}

void EtsAbilityLifecycleCallback::OnWindowStageCreate(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallObjectMethod("onWindowStageCreate", SIGNATURE_UIABILITY_WINDOW_STAGE,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(windowStage).ref_);
}

void EtsAbilityLifecycleCallback::OnWindowStageDestroy(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallObjectMethod("onWindowStageDestroy", SIGNATURE_UIABILITY_WINDOW_STAGE,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(windowStage).ref_);
}

void EtsAbilityLifecycleCallback::OnAbilityDestroy(const AbilityLifecycleCallbackArgs &ability)
{
    CallObjectMethod("onAbilityDestroy", SIGNATURE_UIABILITY,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_);
}

void EtsAbilityLifecycleCallback::OnAbilityForeground(const AbilityLifecycleCallbackArgs &ability)
{
    CallObjectMethod("onAbilityForeground", SIGNATURE_UIABILITY,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_);
}

void EtsAbilityLifecycleCallback::OnAbilityBackground(const AbilityLifecycleCallbackArgs &ability)
{
    CallObjectMethod("onAbilityBackground", SIGNATURE_UIABILITY,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_);
}

void EtsAbilityLifecycleCallback::OnAbilitySaveState(const AbilityLifecycleCallbackArgs &ability)
{
    CallObjectProperty("onAbilitySaveState",
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_);
}

void EtsAbilityLifecycleCallback::OnWindowStageRestore(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallObjectProperty("onWindowStageRestore",
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(windowStage).ref_);
}

void EtsAbilityLifecycleCallback::OnAbilityWillDestroy(const AbilityLifecycleCallbackArgs &ability)
{
    CallObjectProperty("onAbilityWillDestroy",
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_);
}

void EtsAbilityLifecycleCallback::OnWindowStageWillDestroy(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallObjectProperty("onWindowStageWillDestroy",
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(windowStage).ref_);
}

void EtsAbilityLifecycleCallback::OnWindowStageWillCreate(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallObjectProperty("onWindowStageWillCreate",
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(windowStage).ref_);
}

void EtsAbilityLifecycleCallback::OnAbilityWillBackground(const AbilityLifecycleCallbackArgs &ability)
{
    CallObjectProperty("onAbilityWillBackground",
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_);
}

void EtsAbilityLifecycleCallback::OnWindowStageWillRestore(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallObjectProperty("onWindowStageWillRestore",
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(windowStage).ref_);
}

void EtsAbilityLifecycleCallback::OnAbilityWillCreate(const AbilityLifecycleCallbackArgs &ability)
{
    CallObjectProperty("onAbilityWillCreate",
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_);
}

void EtsAbilityLifecycleCallback::OnAbilityWillForeground(const AbilityLifecycleCallbackArgs &ability)
{
    CallObjectProperty("onAbilityWillForeground",
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_);
}

void EtsAbilityLifecycleCallback::OnNewWant(const AbilityLifecycleCallbackArgs &ability)
{
    CallObjectProperty("onNewWant",
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_);
}

void EtsAbilityLifecycleCallback::OnAbilityWillContinue(const AbilityLifecycleCallbackArgs &ability)
{
    CallObjectProperty("onAbilityWillContinue",
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_);
}

void EtsAbilityLifecycleCallback::OnWillNewWant(const AbilityLifecycleCallbackArgs &ability)
{
    CallObjectProperty("onWillNewWant",
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_);
}

void EtsAbilityLifecycleCallback::OnAbilityWillSaveState(const AbilityLifecycleCallbackArgs &ability)
{
    CallObjectProperty("onAbilityWillSaveState",
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_);
}

void EtsAbilityLifecycleCallback::OnAbilityContinue(const AbilityLifecycleCallbackArgs &ability)
{
    CallObjectMethod("onAbilityContinue", SIGNATURE_UIABILITY,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_);
}

void EtsAbilityLifecycleCallback::OnWindowStageInactive(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallObjectMethod("onWindowStageInactive", SIGNATURE_UIABILITY_WINDOW_STAGE,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(windowStage).ref_);
}

void EtsAbilityLifecycleCallback::OnWindowStageActive(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallObjectMethod("onWindowStageActive", SIGNATURE_UIABILITY_WINDOW_STAGE,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(ability).ref_,
        static_cast<const EtsAbilityLifecycleCallbackArgs &>(windowStage).ref_);
}
}  // namespace AbilityRuntime
}  // namespace OHOS