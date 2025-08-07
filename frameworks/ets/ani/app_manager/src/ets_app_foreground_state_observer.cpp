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
#include "ets_app_foreground_state_observer.h"

#include "ets_app_manager_utils.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* APP_FOREGROUND_STATE_OBSERVER_CLASS_NAME =
    "Lapplication/AppForegroundStateObserver/AppForegroundStateObserver;";
}
ETSAppForegroundStateObserver::ETSAppForegroundStateObserver(ani_vm *etsVm) : etsVm_(etsVm) {}

ETSAppForegroundStateObserver::~ETSAppForegroundStateObserver()
{
    RemoveAllEtsObserverObjects();
}

ani_status ETSAppForegroundStateObserver::AniSendEvent(const std::function<void()> task)
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

void ETSAppForegroundStateObserver::OnAppStateChanged(const AppStateData &appStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "OnAppStateChanged called");
    if (!valid_) {
        TAG_LOGE(AAFwkTag::APPMGR, "invalid appMgr");
        return;
    }
    wptr<ETSAppForegroundStateObserver> weakPtr = this;
    auto task = [appStateData, weakPtr] () {
        auto appForegroundStateObserver = weakPtr.promote();
        if (appForegroundStateObserver == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null observerPtr");
            return;
        }
        appForegroundStateObserver->HandleOnAppStateChanged(appStateData);
    };
    if (AniSendEvent(task) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to aniSendEvent");
    }
    TAG_LOGD(AAFwkTag::APPMGR, "OnAppStateChanged end");
}

void ETSAppForegroundStateObserver::HandleOnAppStateChanged(const AppStateData &appStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "HandleOnAppStateChanged called");
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "etsVm_ nullptr");
        return;
    }
    ani_env *env = nullptr;
    if (!AppManagerEts::AttachAniEnv(etsVm_, env)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to AttachAniEnv");
        return;
    }
    auto appStateDataObj = AppManagerEts::WrapAppStateData(env, appStateData);
    if (appStateDataObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "WrapAppStateData failed");
        AppManagerEts::DetachAniEnv(etsVm_);
        return;
    }
    std::lock_guard<std::mutex> lock(etsObserverObjectSetLock_);
    for (auto &item : etsObserverObjects_) {
        if (item != nullptr) {
            CallEtsFunction(env, reinterpret_cast<ani_object>(item), "onAppStateChanged", nullptr, appStateDataObj);
        }
    }
    AppManagerEts::DetachAniEnv(etsVm_);
}

void ETSAppForegroundStateObserver::CallEtsFunction(ani_env* env, ani_object etsObserverObject,
    const char *methodName, const char *signature, ...)
{
    TAG_LOGD(AAFwkTag::APPMGR, "call method:%{public}s", methodName);
    ani_class cls;
    ani_method method = nullptr;
    ani_status status = ANI_OK;
    if ((status = env->FindClass(APP_FOREGROUND_STATE_OBSERVER_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "find observer failed status : %{public}d", status);
        return;
    }
    if ((status = env->Class_FindMethod(cls, methodName, signature, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "status: %{public}d", status);
        return;
    }
    env->ResetError();
    va_list args;
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(etsObserverObject, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "status: %{public}d", status);
        return;
    }
    va_end(args);
    TAG_LOGD(AAFwkTag::APPMGR, "end");
    return;
}

void ETSAppForegroundStateObserver::AddEtsObserverObject(const ani_object &observerObj)
{
    if (observerObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return;
    }
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null etsVm_");
        return;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) != ANI_OK || env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed status: %{public}d", status);
        return;
    }
    if (GetObserverObject(observerObj) == nullptr) {
        std::lock_guard<std::mutex> lock(etsObserverObjectSetLock_);
        ani_ref global = nullptr;
        if ((status = env->GlobalReference_Create(observerObj, &global)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
            return;
        }
        etsObserverObjects_.emplace_back(global);
    } else {
        TAG_LOGD(AAFwkTag::APPMGR, "observer exist");
    }
}

void ETSAppForegroundStateObserver::RemoveAllEtsObserverObjects()
{
    std::lock_guard<std::mutex> lock(etsObserverObjectSetLock_);
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null etsVm_");
        return;
    }
    for (const auto &item : etsObserverObjects_) {
        if (item == nullptr) {
            continue;
        }
        AppManagerEts::ReleaseObjectReference(etsVm_, item);
    }
    etsObserverObjects_.clear();
}

void ETSAppForegroundStateObserver::RemoveEtsObserverObject(const ani_object &observerObj)
{
    if (observerObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return;
    }
    wptr<ETSAppForegroundStateObserver> weakPtr = this;
    auto it = find_if(etsObserverObjects_.begin(),
        etsObserverObjects_.end(),
        [weakPtr, &observerObj](ani_ref item) {
            auto appForegroundStateObserver = weakPtr.promote();
            if (appForegroundStateObserver == nullptr) {
                TAG_LOGE(AAFwkTag::APPMGR, "null appForegroundStateObserver");
                return false;
            }
            return appForegroundStateObserver->IsStrictEquals(item, observerObj);
        });
    if (it != etsObserverObjects_.end()) {
        std::lock_guard<std::mutex> lock(etsObserverObjectSetLock_);
        AppManagerEts::ReleaseObjectReference(etsVm_, *it);
        etsObserverObjects_.erase(it);
    }
}

ani_ref ETSAppForegroundStateObserver::GetObserverObject(const ani_object &observerObject)
{
    if (observerObject == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return nullptr;
    }
    for (auto& item : etsObserverObjects_) {
        if (IsStrictEquals(item, observerObject)) {
            return item;
        }
    }
    return nullptr;
}

void ETSAppForegroundStateObserver::SetValid(bool valid)
{
    valid_ = valid;
}

bool ETSAppForegroundStateObserver::IsEmpty()
{
    std::lock_guard<std::mutex> lock(etsObserverObjectSetLock_);
    return etsObserverObjects_.empty();
}

bool ETSAppForegroundStateObserver::IsStrictEquals(ani_ref observerRef, const ani_object &etsObserverObject)
{
    if (etsVm_ == nullptr || observerRef == nullptr || etsObserverObject == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "etsVm_ or etsObserverObject or observerRef null");
        return false;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) != ANI_OK || env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed status: %{public}d", status);
        return false;
    }
    ani_boolean isEquals = ANI_FALSE;
    if ((status = env->Reference_StrictEquals(observerRef, etsObserverObject, &isEquals)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Reference_StrictEquals failed status: %{public}d", status);
        return false;
    }
    return isEquals == ANI_TRUE;
}
} // namespace AbilityRuntime
} // namespace OHOS
