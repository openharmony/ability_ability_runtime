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

#include "ets_app_state_observer.h"

#include "ani_common_ability_state_data.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ani_task.h"
#include "hilog_tag_wrapper.h"
#include "ets_app_manager_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *SIGNATURE_APP_STATE_DATA = "C{application.AppStateData.AppStateData}:";
constexpr const char *SIGNATURE_ABILITY_STATE_DATA = "C{application.AbilityStateData.AbilityStateData}:";
constexpr const char *SIGNATURE_PROCESS_DATA = "C{application.ProcessData.ProcessData}:";
constexpr const char *CLASS_NAME_APPLIACTION_STATE_OBSERVER =
    "application.ApplicationStateObserver.ApplicationStateObserverImpl";
}

EtsAppStateObserver::EtsAppStateObserver(ani_vm *etsVm) : etsVm_(etsVm) {}

EtsAppStateObserver::~EtsAppStateObserver()
{
    ani_env *env = AttachCurrentThread();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed");
        return;
    }
    std::lock_guard<std::mutex> lock(etsObserverObjectMapLock_);
    for (auto it = etsObserverObjectMap_.begin(); it != etsObserverObjectMap_.end();) {
        env->GlobalReference_Delete(it->second);
        it++;
    }
    DetachCurrentThread();
};

void EtsAppStateObserver::OnForegroundApplicationChanged(const AppStateData &appStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "OnForegroundApplicationChanged bundleName:%{public}s,uid:%{public}d, state:%{public}d",
        appStateData.bundleName.c_str(), appStateData.uid, appStateData.state);
    if (!valid_) {
        TAG_LOGE(AAFwkTag::APPMGR, "invalid appmgr");
        return;
    }
    wptr<EtsAppStateObserver> etsObserver = this;
    auto task = [appStateData, etsObserver]() {
        sptr<EtsAppStateObserver> etsObserverSptr = etsObserver.promote();
        if (!etsObserverSptr) {
            TAG_LOGW(AAFwkTag::APPMGR, "null stsObserver");
            return;
        }
        etsObserverSptr->HandleOnForegroundApplicationChanged(appStateData);
    };
    if (AniTask::AniSendEvent(task) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to aniSendEvent");
    }
}

void EtsAppStateObserver::HandleOnForegroundApplicationChanged(const AppStateData &appStateData)
{
    ani_env *env = AttachCurrentThread();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed");
        return;
    }
    auto tmpMap = GetEtsObserverObjectMap();
    for (auto &item : tmpMap) {
        auto appStateDataObj = AppManagerEts::WrapAppStateData(env, appStateData);
        if (appStateDataObj == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null appStateDataObj");
            DetachCurrentThread();
            return;
        }
        CallEtsFunction(env, item.second, "onForegroundApplicationChanged", SIGNATURE_APP_STATE_DATA, appStateDataObj);
    }
    DetachCurrentThread();
}

void EtsAppStateObserver::OnAbilityStateChanged(const AbilityStateData &abilityStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "OnAbilityStateChanged");
    if (!valid_) {
        TAG_LOGE(AAFwkTag::APPMGR, "appMgr may has cancelled storage");
        return;
    }
    wptr<EtsAppStateObserver> etsObserver = this;
    auto task = [abilityStateData, etsObserver] () {
        sptr<EtsAppStateObserver> etsObserverSptr = etsObserver.promote();
        if (!etsObserverSptr) {
            TAG_LOGW(AAFwkTag::APPMGR, "null stsObserver");
            return;
        }
        etsObserverSptr->HandleOnAbilityStateChanged(abilityStateData);
    };
    if (AniTask::AniSendEvent(task) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to aniSendEvent");
    }
}

void EtsAppStateObserver::HandleOnAbilityStateChanged(const AbilityStateData &abilityStateData)
{
    ani_env *env = AttachCurrentThread();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed");
        return;
    }
    auto tmpMap = GetEtsObserverObjectMap();
    for (auto &item : tmpMap) {
        auto abilityStateDataObj = OHOS::AppExecFwk::WrapAbilityStateData(env, abilityStateData);
        if (abilityStateDataObj == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null abilityStateDataObj");
            DetachCurrentThread();
        }
        CallEtsFunction(env, item.second, "onAbilityStateChanged", SIGNATURE_ABILITY_STATE_DATA, abilityStateDataObj);
    }
    DetachCurrentThread();
}

void EtsAppStateObserver::OnExtensionStateChanged(const AbilityStateData &abilityStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "called");
    if (!valid_) {
        TAG_LOGE(AAFwkTag::APPMGR, "appMgr may destroyed");
        return;
    }

    wptr<EtsAppStateObserver> etsObserver = this;
    auto task = [abilityStateData, etsObserver]() {
        sptr<EtsAppStateObserver> etsObserverSptr = etsObserver.promote();
        if (!etsObserverSptr) {
            TAG_LOGW(AAFwkTag::APPMGR, "null stsObserver");
            return;
        }
        etsObserverSptr->HandleOnExtensionStateChanged(abilityStateData);
    };
    if (AniTask::AniSendEvent(task) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to aniSendEvent");
    }
}

void EtsAppStateObserver::HandleOnExtensionStateChanged(const AbilityStateData &abilityStateData)
{
    ani_env *env = AttachCurrentThread();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed");
        return;
    }
    auto tmpMap = GetEtsObserverObjectMap();
    for (auto &item : tmpMap) {
        auto abilityStateDataObj = OHOS::AppExecFwk::WrapAbilityStateData(env, abilityStateData);
        if (abilityStateDataObj == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null abilityStateDataObj");
            DetachCurrentThread();
        }
        CallEtsFunction(env, item.second, "onAbilityStateChanged", SIGNATURE_ABILITY_STATE_DATA, abilityStateDataObj);
    }
    DetachCurrentThread();
}

void EtsAppStateObserver::OnProcessCreated(const ProcessData &processData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "OnProcessCreated");
    if (!valid_) {
        TAG_LOGE(AAFwkTag::APPMGR, "appmgr may has cancelled storage");
        return;
    }

    wptr<EtsAppStateObserver> etsObserver = this;
    auto task = [processData, etsObserver]() {
        sptr<EtsAppStateObserver> etsObserverSptr = etsObserver.promote();
        if (!etsObserverSptr) {
            TAG_LOGW(AAFwkTag::APPMGR, "null stsObserver");
            return;
        }
        etsObserverSptr->HandleOnProcessCreated(processData);
    };
    if (AniTask::AniSendEvent(task) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to aniSendEvent");
    }
}

void EtsAppStateObserver::HandleOnProcessCreated(const ProcessData &processData)
{
    ani_env *env = AttachCurrentThread();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed");
        return;
    }
    auto tmpMap = GetEtsObserverObjectMap();
    for (auto &item : tmpMap) {
        auto processDataObj = AppManagerEts::WrapProcessData(env, processData);
        if (processDataObj == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null processDataObj");
            DetachCurrentThread();
            return;
        }
        CallEtsFunction(env, item.second, "onProcessCreated", SIGNATURE_PROCESS_DATA, processDataObj);
    }
    DetachCurrentThread();
}

void EtsAppStateObserver::OnProcessStateChanged(const ProcessData &processData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "called");
    if (!valid_) {
        TAG_LOGE(AAFwkTag::APPMGR, "appMgr may destroyed");
        return;
    }

    wptr<EtsAppStateObserver> etsObserver = this;
    auto task = [processData, etsObserver]() {
        sptr<EtsAppStateObserver> etsObserverSptr = etsObserver.promote();
        if (!etsObserverSptr) {
            TAG_LOGW(AAFwkTag::APPMGR, "null stsObserver");
            return;
        }
        etsObserverSptr->HandleOnProcessStateChanged(processData);
    };
    if (AniTask::AniSendEvent(task) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to aniSendEvent");
    }
}

void EtsAppStateObserver::HandleOnProcessStateChanged(const ProcessData &processData)
{
    ani_env *env = AttachCurrentThread();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed");
        return;
    }
    auto tmpMap = GetEtsObserverObjectMap();
    for (auto &item : tmpMap) {
        auto processDataObj = AppManagerEts::WrapProcessData(env, processData);
        if (processDataObj == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null processDataObj");
            DetachCurrentThread();
            return;
        }
        CallEtsFunction(env, item.second, "onProcessStateChanged", SIGNATURE_PROCESS_DATA, processDataObj);
    }
    DetachCurrentThread();
}

void EtsAppStateObserver::OnProcessDied(const ProcessData &processData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "called");
    if (!valid_) {
        TAG_LOGE(AAFwkTag::APPMGR, "appmgr may destroyed");
        return;
    }

    wptr<EtsAppStateObserver> etsObserver = this;
    auto task = [processData, etsObserver]() {
        sptr<EtsAppStateObserver> etsObserverSptr = etsObserver.promote();
        if (!etsObserverSptr) {
            TAG_LOGW(AAFwkTag::APPMGR, "null stsObserver");
            return;
        }
        etsObserverSptr->HandleOnProcessDied(processData);
    };
    if (AniTask::AniSendEvent(task) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to aniSendEvent");
    }
}

void EtsAppStateObserver::HandleOnProcessDied(const ProcessData &processData)
{
    ani_env *env = AttachCurrentThread();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed");
        return;
    }
    auto tmpMap = GetEtsObserverObjectMap();
    for (auto &item : tmpMap) {
        auto processDataObj = AppManagerEts::WrapProcessData(env, processData);
        if (processDataObj == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null processDataObj");
            DetachCurrentThread();
            return;
        }
        CallEtsFunction(env, item.second, "onProcessDied", SIGNATURE_PROCESS_DATA, processDataObj);
    }
    DetachCurrentThread();
}

void EtsAppStateObserver::OnAppStarted(const AppStateData &appStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "bundleName:%{public}s, uid:%{public}d, state:%{public}d",
        appStateData.bundleName.c_str(), appStateData.uid, appStateData.state);
    if (!valid_) {
        TAG_LOGE(AAFwkTag::APPMGR, "appMgr may destroyed");
        return;
    }

    wptr<EtsAppStateObserver> etsObserver = this;
    auto task = [appStateData, etsObserver]() {
        sptr<EtsAppStateObserver> etsObserverSptr = etsObserver.promote();
        if (!etsObserverSptr) {
            TAG_LOGW(AAFwkTag::APPMGR, "null stsObserver");
            return;
        }
        etsObserverSptr->HandleOnAppStarted(appStateData);
    };
    if (AniTask::AniSendEvent(task) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to aniSendEvent");
    }
}

void EtsAppStateObserver::HandleOnAppStarted(const AppStateData &appStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "bundleName:%{public}s, uid:%{public}d, state:%{public}d",
        appStateData.bundleName.c_str(), appStateData.uid, appStateData.state);
    ani_env *env = AttachCurrentThread();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed");
        return;
    }
    auto tmpMap = GetEtsObserverObjectMap();
    for (auto &item : tmpMap) {
        auto appStateDataObj = AppManagerEts::WrapAppStateData(env, appStateData);
        if (appStateDataObj == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null appStateDataObj");
            DetachCurrentThread();
            return;
        }
        CallEtsFunction(env, item.second, "onAppStarted", SIGNATURE_APP_STATE_DATA, appStateDataObj);
    }
    DetachCurrentThread();
}

void EtsAppStateObserver::OnAppStopped(const AppStateData &appStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "bundleName:%{public}s, uid:%{public}d, state:%{public}d",
        appStateData.bundleName.c_str(), appStateData.uid, appStateData.state);
    if (!valid_) {
        TAG_LOGE(AAFwkTag::APPMGR, "appMgr may destroyed");
        return;
    }

    wptr<EtsAppStateObserver> etsObserver = this;
    auto task = [appStateData, etsObserver]() {
        sptr<EtsAppStateObserver> etsObserverSptr = etsObserver.promote();
        if (!etsObserverSptr) {
            TAG_LOGW(AAFwkTag::APPMGR, "null stsObserver");
            return;
        }
        etsObserverSptr->HandleOnAppStopped(appStateData);
    };
    if (AniTask::AniSendEvent(task) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to aniSendEvent");
    }
}

void EtsAppStateObserver::HandleOnAppStopped(const AppStateData &appStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "bundleName:%{public}s, uid:%{public}d, state:%{public}d",
        appStateData.bundleName.c_str(), appStateData.uid, appStateData.state);
    ani_env *env = AttachCurrentThread();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed");
        return;
    }
    auto tmpMap = GetEtsObserverObjectMap();
    for (auto &item : tmpMap) {
        auto appStateDataObj = AppManagerEts::WrapAppStateData(env, appStateData);
        if (appStateDataObj == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null appStateDataObj");
            DetachCurrentThread();
            return;
        }
        CallEtsFunction(env, item.second, "onAppStopped", SIGNATURE_APP_STATE_DATA, appStateDataObj);
    }
    DetachCurrentThread();
}

void EtsAppStateObserver::CallEtsFunction(
    ani_env *env, ani_object EtsObserverObject, const char *methodName, const char *signature, ...)
{
    TAG_LOGD(AAFwkTag::APPMGR, "call method:%{public}s", methodName);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null env");
        return;
    }
    ani_class cls = nullptr;
    ani_method method = nullptr;
    ani_status status = ANI_OK;
    status = env->FindClass(CLASS_NAME_APPLIACTION_STATE_OBSERVER, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to find ApplicationStateObserver, status: %{public}d", status);
        return;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null cls");
        return;
    }
    if ((status = env->Class_FindMethod(cls, methodName, signature, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to find method, status: %{public}d", status);
        return;
    }
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null method");
        return;
    }
    env->ResetError();
    va_list args;
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(EtsObserverObject, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to call %{public}s method,status: %{public}d", methodName, status);
        return;
    }
    va_end(args);
    return;
}

void EtsAppStateObserver::AddEtsObserverObject(ani_env *env, const int32_t observerId, ani_object EtsObserverObject)
{
    TAG_LOGD(AAFwkTag::APPMGR, "AddEtsObserverObject");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null env");
        return;
    }
    ani_ref global = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GlobalReference_Create(EtsObserverObject, &global)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "status: %{public}d", status);
        return;
    }
    if (global == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null EtsObserverObject ref");
        return;
    }
    std::lock_guard<std::mutex> lock(etsObserverObjectMapLock_);
    etsObserverObjectMap_.emplace(observerId, reinterpret_cast<ani_object>(global));
}

bool EtsAppStateObserver::RemoveEtsObserverObject(const int32_t observerId)
{
    TAG_LOGD(AAFwkTag::APPMGR, "RemoveEtsObserverObject");
    std::lock_guard<std::mutex> lock(etsObserverObjectMapLock_);
    return (etsObserverObjectMap_.erase(observerId) == 1);
}

bool EtsAppStateObserver::FindObserverByObserverId(const int32_t observerId)
{
    std::lock_guard<std::mutex> lock(etsObserverObjectMapLock_);
    return etsObserverObjectMap_.find(observerId) != etsObserverObjectMap_.end();
}

size_t EtsAppStateObserver::GetEtsObserverMapSize()
{
    std::lock_guard<std::mutex> lock(etsObserverObjectMapLock_);
    return etsObserverObjectMap_.size();
}

void EtsAppStateObserver::SetValid(const bool valid)
{
    valid_ = valid;
}

std::map<int32_t, ani_object> EtsAppStateObserver::GetEtsObserverObjectMap()
{
    std::lock_guard<std::mutex> lock(etsObserverObjectMapLock_);
    return etsObserverObjectMap_;
}

ani_env *EtsAppStateObserver::AttachCurrentThread()
{
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) == ANI_OK) {
        return env;
    }
    ani_option interopEnabled { "--interop=disable", nullptr };
    ani_options aniArgs { 1, &interopEnabled };
    if ((status = etsVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "status: %{public}d", status);
        return nullptr;
    }
    isAttachThread_ = true;
    return env;
}

void EtsAppStateObserver::DetachCurrentThread()
{
    if (isAttachThread_) {
        etsVm_->DetachCurrentThread();
        isAttachThread_ = false;
    }
}
} // namespace AbilityRuntime
} // namespace OHOS