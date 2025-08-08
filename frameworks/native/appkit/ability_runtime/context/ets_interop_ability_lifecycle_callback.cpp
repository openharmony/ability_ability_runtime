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

#include "ets_interop_ability_lifecycle_callback.h"

#include <sstream>

#include "ani.h"
#include "ets_exception_callback.h"
#include "ets_runtime.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *SIGNATURE_NAMESPACE_INTEROP_ABILITY_LIFECYCLE =
    "L@ohos/app/ability/InteropAbilityLifecycleCallback/InteropAbilityLifecycle;";
constexpr const char *SIGNATURE_UIABILITY =
    "Lstd/interop/ESValue;L@ohos/app/ability/InteropAbilityLifecycleCallback/InteropAbilityLifecycleCallback;:V";
constexpr const char *SIGNATURE_UIABILITY_WINDOW_STAGE =
    "Lstd/interop/ESValue;Lstd/interop/ESValue;"
    "L@ohos/app/ability/InteropAbilityLifecycleCallback/InteropAbilityLifecycleCallback;:V";
constexpr const int32_t ERROR_CODE_NULL_ENV = -1;
constexpr const int32_t ERROR_CODE_NULL_CALLBACK = -2;
constexpr const int32_t ERROR_CODE_NULL_REF = -3;
}
EtsInteropAbilityLifecycleCallback::EtsInteropAbilityLifecycleCallback(ani_env *env)
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

ani_env *EtsInteropAbilityLifecycleCallback::GetAniEnv()
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

bool EtsInteropAbilityLifecycleCallback::Empty()
{
    std::lock_guard<std::mutex> lock(callbacksLock_);
    return callbacks_.empty();
}

void EtsInteropAbilityLifecycleCallback::CallObjectMethod(const char *methodName,
    const char *signature, std::shared_ptr<InteropObject> ability)
{
    ani_env *aniEnv = GetAniEnv();
    if (aniEnv == nullptr || ability == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv or ability");
        return;
    }
    if (!ability->IsFromNapi()) {
        TAG_LOGI(AAFwkTag::APPKIT, "not from js");
        return;
    }
    ani_ref abilityEsValue = ability->GetAniValue(aniEnv);
    if (abilityEsValue == nullptr) {
        TAG_LOGI(AAFwkTag::APPKIT, "null esvalue");
        return;
    }

    ani_status status = ANI_ERROR;
    ani_namespace ns;
    if ((status = aniEnv->FindNamespace(SIGNATURE_NAMESPACE_INTEROP_ABILITY_LIFECYCLE, &ns)) != ANI_OK ||
        ns == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed to find namespace, status=%{public}d", status);
        return;
    }

    ani_function callbackInnerFn = nullptr;
    if ((status = aniEnv->Namespace_FindFunction(ns, methodName, signature, &callbackInnerFn)) != ANI_OK ||
        callbackInnerFn == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed to find function %{public}s, status=%{public}d", methodName, status);
        return;
    }

    ani_value aniAbility {};
    aniAbility.r = reinterpret_cast<ani_ref>(abilityEsValue);
    std::lock_guard<std::mutex> lock(callbacksLock_);
    for (const auto &callback : callbacks_) {
        if (callback == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null callback");
            return;
        }
        if ((status = aniEnv->Function_Call_Void(callbackInnerFn,
            aniAbility, reinterpret_cast<ani_object>(callback))) != ANI_OK) {
            const EtsEnv::ETSErrorObject errorObj = GetETSErrorObject();
            TAG_LOGE(AAFwkTag::APPKIT, "failed to call function %{public}s,status=%{public}d\nname=%{public}s\n"
                "message=%{public}s\nstack=%{public}s", methodName, status, errorObj.name.c_str(),
                errorObj.message.c_str(), errorObj.stack.c_str());
            return;
        }
    }
}

void EtsInteropAbilityLifecycleCallback::CallObjectMethod(const char *methodName, const char *signature,
    std::shared_ptr<InteropObject> ability, std::shared_ptr<InteropObject> windowStage)
{
    ani_env *aniEnv = GetAniEnv();
    if (aniEnv == nullptr || ability == nullptr || windowStage == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv or ability or windowStage");
        return;
    }
    if (!ability->IsFromNapi()) {
        TAG_LOGI(AAFwkTag::APPKIT, "not from js");
        return;
    }
    ani_ref abilityEsValue = ability->GetAniValue(aniEnv);
    ani_ref windowStageEsValue = windowStage->GetAniValue(aniEnv);
    if (abilityEsValue == nullptr || windowStageEsValue == nullptr) {
        TAG_LOGI(AAFwkTag::APPKIT, "null esvalue");
        return;
    }

    ani_status status = ANI_ERROR;
    ani_namespace ns = nullptr;
    if ((status = aniEnv->FindNamespace(SIGNATURE_NAMESPACE_INTEROP_ABILITY_LIFECYCLE, &ns)) != ANI_OK ||
        ns == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed to find namespace, status=%{public}d", status);
        return;
    }

    ani_function callbackInnerFn = nullptr;
    if ((status = aniEnv->Namespace_FindFunction(ns, methodName, signature, &callbackInnerFn)) != ANI_OK ||
        callbackInnerFn == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed to find function %{public}s, status=%{public}d", methodName, status);
        return;
    }

    ani_value aniAbility {};
    aniAbility.r = reinterpret_cast<ani_ref>(abilityEsValue);
    ani_value aniWindowStage {};
    aniWindowStage.r = reinterpret_cast<ani_ref>(windowStageEsValue);
    std::lock_guard<std::mutex> lock(callbacksLock_);
    for (const auto &callback : callbacks_) {
        if (callback == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null callback");
            return;
        }
        if ((status = aniEnv->Function_Call_Void(callbackInnerFn,
            aniAbility, aniWindowStage, reinterpret_cast<ani_object>(callback))) != ANI_OK) {
            const EtsEnv::ETSErrorObject errorObj = GetETSErrorObject();
            TAG_LOGE(AAFwkTag::APPKIT, "failed to call function %{public}s,status=%{public}d\nname=%{public}s\n"
                "message=%{public}s\nstack=%{public}s", methodName, status, errorObj.name.c_str(),
                errorObj.message.c_str(), errorObj.stack.c_str());
            return;
        }
    }
}

int32_t EtsInteropAbilityLifecycleCallback::Register(ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "enter EtsInteropAbilityLifecycleCallback::Register");
    ani_env *aniEnv = GetAniEnv();
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv");
        return ERROR_CODE_NULL_ENV;
    }
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv");
        return ERROR_CODE_NULL_CALLBACK;
    }
    ani_ref ref = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = aniEnv->GlobalReference_Create(callback, &ref)) != ANI_OK || ref == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed to create reference, status=%{public}d", status);
        return ERROR_CODE_NULL_REF;
    }
    std::lock_guard<std::mutex> lock(callbacksLock_);
    callbacks_.push_back(ref);
    return 0;
}

EtsEnv::ETSErrorObject EtsInteropAbilityLifecycleCallback::GetETSErrorObject()
{
    TAG_LOGD(AAFwkTag::APPKIT, "GetETSErrorObject called");
    ani_boolean errorExists = ANI_FALSE;
    ani_status status = ANI_ERROR;
    auto aniEnv = GetAniEnv();
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return EtsEnv::ETSErrorObject();
    }
    if ((status = aniEnv->ExistUnhandledError(&errorExists)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "ExistUnhandledError failed, status : %{public}d", status);
        return EtsEnv::ETSErrorObject();
    }
    if (errorExists == ANI_FALSE) {
        TAG_LOGE(AAFwkTag::APPKIT, "not exist error");
        return EtsEnv::ETSErrorObject();
    }
    ani_error aniError = nullptr;
    if ((status = aniEnv->GetUnhandledError(&aniError)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetUnhandledError failed, status : %{public}d", status);
        return EtsEnv::ETSErrorObject();
    }
    if ((status = aniEnv->ResetError()) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "ResetError failed, status : %{public}d", status);
        return EtsEnv::ETSErrorObject();
    }
    std::string errorMsg = GetErrorProperty(aniError, "message");
    std::string errorName = GetErrorProperty(aniError, "name");
    std::string errorStack = GetErrorProperty(aniError, "stack");
    const EtsEnv::ETSErrorObject errorObj = {
        .name = errorName,
        .message = errorMsg,
        .stack = errorStack
    };
    return errorObj;
}

std::string EtsInteropAbilityLifecycleCallback::GetErrorProperty(ani_error aniError, const char *property)
{
    TAG_LOGD(AAFwkTag::APPKIT, "GetErrorProperty called");
    auto aniEnv = GetAniEnv();
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return "";
    }
    std::string propertyValue;
    ani_status status = ANI_ERROR;
    ani_type errorType = nullptr;
    if ((status = aniEnv->Object_GetType(aniError, &errorType)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_GetType failed, status : %{public}d", status);
        return propertyValue;
    }
    ani_method getterMethod = nullptr;
    if ((status = aniEnv->Class_FindGetter(static_cast<ani_class>(errorType), property, &getterMethod)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindGetter failed, status : %{public}d", status);
        return propertyValue;
    }
    ani_ref aniRef = nullptr;
    if ((status = aniEnv->Object_CallMethod_Ref(aniError, getterMethod, &aniRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_CallMethod_Ref failed, status : %{public}d", status);
        return propertyValue;
    }
    ani_string aniString = reinterpret_cast<ani_string>(aniRef);
    ani_size sz {};
    if ((status = aniEnv->String_GetUTF8Size(aniString, &sz)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "String_GetUTF8Size failed, status : %{public}d", status);
        return propertyValue;
    }
    propertyValue.resize(sz + 1);
    if ((status = aniEnv->String_GetUTF8SubString(
        aniString, 0, sz, propertyValue.data(), propertyValue.size(), &sz))!= ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "String_GetUTF8SubString failed, status : %{public}d", status);
        return propertyValue;
    }
    propertyValue.resize(sz);
    return propertyValue;
}

bool EtsInteropAbilityLifecycleCallback::Unregister(ani_object aniCallback)
{
    ani_status status = ANI_ERROR;
    ani_env *env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed");
        return false;
    }
    if (aniCallback == nullptr) {
        TAG_LOGI(AAFwkTag::APPKIT, "null aniCallback");
        std::lock_guard<std::mutex> lock(callbacksLock_);
        for (auto &callback : callbacks_) {
            if (!callback) {
                TAG_LOGE(AAFwkTag::APPKIT, "Invalid aniCallback");
                continue;
            }
            if ((status = env->GlobalReference_Delete(callback)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Delete status: %{public}d", status);
            }
        }
        callbacks_.clear();
        return true;
    }
    std::lock_guard<std::mutex> lock(callbacksLock_);
    for (auto iter = callbacks_.begin(); iter != callbacks_.end(); ++iter) {
        if (*iter == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid callback");
            continue;
        }
        ani_boolean isEqual = false;
        env->Reference_StrictEquals(aniCallback, *iter, &isEqual);
        if (isEqual) {
            if ((status = env->GlobalReference_Delete(*iter)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Delete status: %{public}d", status);
                return false;
            }
            callbacks_.erase(iter);
            return true;
        }
    }
    return false;
}

void EtsInteropAbilityLifecycleCallback::OnAbilityCreate(std::shared_ptr<InteropObject> ability)
{
    CallObjectMethod("onAbilityCreateInner", SIGNATURE_UIABILITY, ability);
}

void EtsInteropAbilityLifecycleCallback::OnWindowStageCreate(std::shared_ptr<InteropObject> ability,
    std::shared_ptr<InteropObject> windowStage)
{
    CallObjectMethod("onWindowStageCreateInner", SIGNATURE_UIABILITY_WINDOW_STAGE, ability, windowStage);
}

void EtsInteropAbilityLifecycleCallback::OnWindowStageDestroy(std::shared_ptr<InteropObject> ability,
    std::shared_ptr<InteropObject> windowStage)
{
    CallObjectMethod("onWindowStageDestroyInner", SIGNATURE_UIABILITY_WINDOW_STAGE, ability, windowStage);
}

void EtsInteropAbilityLifecycleCallback::OnAbilityDestroy(std::shared_ptr<InteropObject> ability)
{
    CallObjectMethod("onAbilityDestroyInner", SIGNATURE_UIABILITY, ability);
}

void EtsInteropAbilityLifecycleCallback::OnAbilityForeground(std::shared_ptr<InteropObject> ability)
{
    CallObjectMethod("onAbilityForegroundInner", SIGNATURE_UIABILITY, ability);
}

void EtsInteropAbilityLifecycleCallback::OnAbilityBackground(std::shared_ptr<InteropObject> ability)
{
    CallObjectMethod("onAbilityBackgroundInner", SIGNATURE_UIABILITY, ability);
}
}  // namespace AbilityRuntime
}  // namespace OHOS