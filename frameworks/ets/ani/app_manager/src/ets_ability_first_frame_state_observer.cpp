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

#include "ets_app_manager_utils.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* ABILITY_FIRST_FRAME_STATE_OBSERVER_CLASS_NAME =
    "Lapplication/AbilityFirstFrameStateObserver/AbilityFirstFrameStateObserver;";
}
ETSAbilityFirstFrameStateObserver::ETSAbilityFirstFrameStateObserver(ani_vm *vm) : etsVm_(vm) {}

ani_status ETSAbilityFirstFrameStateObserver::AniSendEvent(const std::function<void()> task)
{
    TAG_LOGD(AAFwkTag::APPMGR, "AniSendEvent");
    if (task == nullptr) {
        TAG_LOGD(AAFwkTag::APPMGR, "null task");
        return ani_status::ANI_INVALID_ARGS;
    }
    if (!mainHandler_) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        if (!runner) {
            TAG_LOGD(AAFwkTag::APPMGR, "null EventRunner");
            return ani_status::ANI_NOT_FOUND;
        }
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    if (mainHandler_ == nullptr) {
        TAG_LOGD(AAFwkTag::APPMGR, "null mainHandler");
        return ani_status::ANI_NOT_FOUND;
    }
    mainHandler_->PostTask(std::move(task));
    return ani_status::ANI_OK;
}

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
    if (AniSendEvent(task) != ANI_OK) {
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
    ani_env *env = nullptr;
    if (!AppManagerEts::AttachAniEnv(etsVm_, env)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to AttachAniEnv");
        AppManagerEts::DetachAniEnv(etsVm_);
        return;
    }
    auto paramObj = AppManagerEts::WrapAbilityFirstFrameStateData(env, abilityFirstFrameStateData);
    if (paramObj != nullptr && etsObserverObject_ != nullptr) {
        CallEtsFunction(env, reinterpret_cast<ani_object>(etsObserverObject_->aniRef), "onAbilityFirstFrameDrawn",
            nullptr, paramObj);
    }
    AppManagerEts::DetachAniEnv(etsVm_);
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
    AppExecFwk::ETSNativeReference stRef;
    stRef.aniObj = etsObserverObject;
    stRef.aniRef = observerRef;
    etsObserverObject_ = std::make_shared<AppExecFwk::ETSNativeReference>(stRef);
}

void ETSAbilityFirstFrameStateObserver::ResetEtsObserverObject()
{
    if (etsObserverObject_) {
        AppManagerEts::ReleaseObjectReference(etsVm_, etsObserverObject_->aniRef);
        etsObserverObject_.reset();
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
        auto tmpObject = (*it)->GetAniObserver();
        if (tmpObject == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null value");
            continue;
        }
        if (tmpObject->aniObj == etsObserverObject) {
            abilityManager->UnregisterAbilityFirstFrameStateObserver(*it);
            (*it)->ResetEtsObserverObject();
            etsAbilityFirstFrameStateObserverList_.erase(it);
            return;
        }
    }
}

std::shared_ptr<AppExecFwk::ETSNativeReference> ETSAbilityFirstFrameStateObserverManager::GetObserverObject(
    const ani_object &etsObserverObject)
{
    if (etsObserverObject == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(observerListLock_);
    auto it = find_if(etsAbilityFirstFrameStateObserverList_.begin(),
        etsAbilityFirstFrameStateObserverList_.end(),
        [&etsObserverObject](const sptr<ETSAbilityFirstFrameStateObserver> &observer) {
            return observer != nullptr && observer->GetAniObserver() &&
                   observer->GetAniObserver()->aniObj == etsObserverObject;
        });
    if (it != etsAbilityFirstFrameStateObserverList_.end() && *it != nullptr) {
        return (*it)->GetAniObserver();
    }
    return nullptr;
}
} // namespace AbilityRuntime
} // namespace OHOS
#endif // SUPPORT_GRAPHICS