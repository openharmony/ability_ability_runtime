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

#ifdef SUPPORT_GRAPHICS
#include "ets_ability_first_frame_state_observer.h"

#include "ani_task.h"
#include "ets_app_manager_utils.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* ABILITY_FIRST_FRAME_STATE_OBSERVER_CLASS_NAME =
    "application.AbilityFirstFrameStateObserver.AbilityFirstFrameStateObserver";
}
ETSAbilityFirstFrameStateObserver::ETSAbilityFirstFrameStateObserver(ani_vm *vm) : etsVm_(vm) {}

void ETSAbilityFirstFrameStateObserver::OnAbilityFirstFrameState(
    const AbilityFirstFrameStateData &abilityFirstFrameStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "OnAbilityFirstFrameState called");
    wptr<ETSAbilityFirstFrameStateObserver> weakPtr = this;
    auto task = [abilityFirstFrameStateData, weakPtr] () {
        auto abilityFirstFrameStateObserver = weakPtr.promote();
        if (abilityFirstFrameStateObserver == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null observerPtr");
            return;
        }
        abilityFirstFrameStateObserver->HandleOnAbilityFirstFrameState(abilityFirstFrameStateData);
    };
    if (AniTask::AniSendEvent(task) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to aniSendEvent");
    }
    TAG_LOGD(AAFwkTag::APPMGR, "OnAbilityFirstFrameState end");
}

void ETSAbilityFirstFrameStateObserver::HandleOnAbilityFirstFrameState(
    const AbilityFirstFrameStateData &abilityFirstFrameStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "HandleOnAbilityFirstFrameState called");
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "etsVm_ nullptr");
        return;
    }
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed");
        return;
    }
    auto paramObj = AppManagerEts::WrapAbilityFirstFrameStateData(env, abilityFirstFrameStateData);
    if (paramObj != nullptr && etsObserverObject_ != nullptr) {
        CallEtsFunction(env, reinterpret_cast<ani_object>(etsObserverObject_), "onAbilityFirstFrameDrawn",
            nullptr, paramObj);
    }
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

void ETSAbilityFirstFrameStateObserver::CallEtsFunction(ani_env* env, ani_object etsObserverObject,
    const char *methodName, const char *signature, ...)
{
    TAG_LOGD(AAFwkTag::APPMGR, "call method:%{public}s", methodName);
    ani_class cls;
    ani_method method = nullptr;
    ani_status status = ANI_OK;
    if ((status = env->FindClass(ABILITY_FIRST_FRAME_STATE_OBSERVER_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "find observer failed status : %{public}d", status);
        return;
    }
    if ((status = env->Class_FindMethod(cls, methodName, signature, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "status: %{public}d", status);
        return;
    }
    env->ResetError();
    va_list args;
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(etsObserverObject, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "status: %{public}d", status);
        va_end(args);
        return;
    }
    va_end(args);
    TAG_LOGD(AAFwkTag::APPMGR, "end");
    return;
}

void ETSAbilityFirstFrameStateObserver::SetEtsObserverObject(const ani_object &etsObserverObject)
{
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null etsVm_");
        return;
    }
    if (etsObserverObject == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) != ANI_OK || env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed status: %{public}d", status);
        return;
    }
    ani_ref observerRef = nullptr;
    if ((status = env->GlobalReference_Create(etsObserverObject, &observerRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        return;
    }
    etsObserverObject_ = observerRef;
}

void ETSAbilityFirstFrameStateObserver::ResetEtsObserverObject()
{
    if (etsObserverObject_) {
        AppManagerEts::ReleaseObjectReference(etsVm_, etsObserverObject_);
    }
}

void ETSAbilityFirstFrameStateObserverManager::AddEtsAbilityFirstFrameStateObserver(
    const sptr<ETSAbilityFirstFrameStateObserver> observer)
{
    if (observer == nullptr || observer->GetAniObserver() == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return;
    }
    std::lock_guard<std::mutex> lock(observerListLock_);
    etsAbilityFirstFrameStateObserverList_.emplace_back(observer);
}

bool ETSAbilityFirstFrameStateObserverManager::IsObserverObjectExist(const ani_object &esObserverObject)
{
    if (GetObserverObject(esObserverObject) == nullptr) {
        TAG_LOGD(AAFwkTag::APPMGR, "observer not exist");
        return false;
    }
    TAG_LOGD(AAFwkTag::APPMGR, "observer exist");
    return true;
}

void ETSAbilityFirstFrameStateObserverManager::RemoveAllEtsObserverObjects(
    sptr<OHOS::AAFwk::IAbilityManager> &abilityManager)
{
    TAG_LOGD(AAFwkTag::APPMGR, "RemoveAllEtsObserverObject called");
    if (abilityManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null abilityMgr");
        return;
    }
    std::lock_guard<std::mutex> lock(observerListLock_);
    for (auto &observer : etsAbilityFirstFrameStateObserverList_) {
        if (observer == nullptr) {
            continue;
        }
        abilityManager->UnregisterAbilityFirstFrameStateObserver(observer);
        observer->ResetEtsObserverObject();
    }
    etsAbilityFirstFrameStateObserverList_.clear();
}

bool ETSAbilityFirstFrameStateObserver::IsStrictEquals(const ani_object &etsObserverObject)
{
    if (etsObserverObject == nullptr) {
        return false;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) != ANI_OK || env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed status: %{public}d", status);
        return false;
    }
    ani_boolean isEquals = ANI_FALSE;
    if ((status = env->Reference_StrictEquals(etsObserverObject_, etsObserverObject, &isEquals)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Reference_StrictEquals failed status: %{public}d", status);
        return false;
    }
    return isEquals == ANI_TRUE;
}

void ETSAbilityFirstFrameStateObserverManager::RemoveEtsObserverObject(
    sptr<OHOS::AAFwk::IAbilityManager> &abilityManager, const ani_object &etsObserverObject)
{
    TAG_LOGD(AAFwkTag::APPMGR, "RemoveEtsObserverObject called");
    if (abilityManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null abilityMgr");
        return;
    }
    if (etsObserverObject == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return;
    }
    std::lock_guard<std::mutex> lock(observerListLock_);
    auto it = etsAbilityFirstFrameStateObserverList_.begin();
    for (; it != etsAbilityFirstFrameStateObserverList_.end(); ++it) {
        if (*it == nullptr) {
            continue;
        }
        if ((*it)->GetAniObserver() == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null value");
            continue;
        }
        if ((*it)->IsStrictEquals(etsObserverObject)) {
            abilityManager->UnregisterAbilityFirstFrameStateObserver(*it);
            (*it)->ResetEtsObserverObject();
            etsAbilityFirstFrameStateObserverList_.erase(it);
            return;
        }
    }
}

ani_ref ETSAbilityFirstFrameStateObserverManager::GetObserverObject(const ani_object &etsObserverObject)
{
    if (etsObserverObject == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(observerListLock_);
    auto it = find_if(etsAbilityFirstFrameStateObserverList_.begin(),
        etsAbilityFirstFrameStateObserverList_.end(),
        [&etsObserverObject](const sptr<ETSAbilityFirstFrameStateObserver> &observer) {
            if (observer == nullptr || observer->GetAniObserver() == nullptr) {
                return false;
            }
            return observer->IsStrictEquals(etsObserverObject);
        });
    if (it != etsAbilityFirstFrameStateObserverList_.end() && *it != nullptr) {
        return (*it)->GetAniObserver();
    }
    return nullptr;
}
} // namespace AbilityRuntime
} // namespace OHOS
#endif // SUPPORT_GRAPHICS