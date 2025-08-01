/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "app_state_observer_manager.h"

#include "ability_foreground_state_observer_stub.h"
#include "app_foreground_state_observer_stub.h"
#include "application_state_observer_stub.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "in_process_call_wrapper.h"
#include "remote_client_manager.h"
#include "ui_extension_utils.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string XIAOYI_BUNDLE_NAME = "com.huawei.hmos.vassistant";
constexpr int BUNDLE_NAME_LIST_MAX_SIZE = 128;
constexpr int OBSERVER_SINGLE_COUNT_LOG = 40;
constexpr int OBSERVER_SINGLE_STEP_LOG = 10;
constexpr int OBSERVER_UID_COUNT_LOG = 3;
constexpr int OBSERVER_AMOUNT_COUNT_LOG = 70;
constexpr const char* DEVELOPER_MODE_STATE = "const.security.developermode.state";
} // namespace
AppStateObserverManager::AppStateObserverManager()
{
    TAG_LOGD(AAFwkTag::APPMGR, "AppStateObserverManager instance is created");
}

AppStateObserverManager::~AppStateObserverManager()
{
    TAG_LOGD(AAFwkTag::APPMGR, "AppStateObserverManager instance is destroyed");
}

void AppStateObserverManager::Init()
{
    if (!handler_) {
        handler_ = AAFwk::TaskHandlerWrap::CreateQueueHandler("app_state_task_queue");
    }
}

int32_t AppStateObserverManager::RegisterApplicationStateObserver(
    const sptr<IApplicationStateObserver> &observer, const std::vector<std::string> &bundleNameList)
{
    TAG_LOGD(AAFwkTag::APPMGR, "called");
    if (bundleNameList.size() > BUNDLE_NAME_LIST_MAX_SIZE) {
        TAG_LOGE(AAFwkTag::APPMGR, "bundleNameList passed in is too long");
        return ERR_INVALID_VALUE;
    }
    if (AAFwk::PermissionVerification::GetInstance()->VerifyAppStateObserverPermission() == ERR_PERMISSION_DENIED) {
        TAG_LOGE(AAFwkTag::APPMGR, "verification failed");
        return ERR_PERMISSION_DENIED;
    }
    if (observer == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return ERR_INVALID_VALUE;
    }
    if (ObserverExist(observer)) {
        TAG_LOGE(AAFwkTag::APPMGR, "observer exist");
        return ERR_INVALID_VALUE;
    }
    std::lock_guard lockRegister(observerLock_);
    appStateObserverMap_.emplace(observer, AppStateObserverInfo{IPCSkeleton::GetCallingUid(), bundleNameList});
    if (appStateObserverMap_.size() >= OBSERVER_SINGLE_COUNT_LOG &&
        appStateObserverMap_.size() % OBSERVER_SINGLE_STEP_LOG == 0) {
        TAG_LOGW(AAFwkTag::APPMGR, "appStateObserverMap_ size:%{public}zu", appStateObserverMap_.size());
    }
    AddObserverCount(IPCSkeleton::GetCallingUid());
    AddObserverDeathRecipient(observer, ObserverType::APPLICATION_STATE_OBSERVER);
    return ERR_OK;
}

int32_t AppStateObserverManager::UnregisterApplicationStateObserver(const sptr<IApplicationStateObserver> &observer)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APPMGR, "called");
    if (AAFwk::PermissionVerification::GetInstance()->VerifyAppStateObserverPermission() == ERR_PERMISSION_DENIED) {
        TAG_LOGE(AAFwkTag::APPMGR, "verification failed");
        return ERR_PERMISSION_DENIED;
    }
    std::lock_guard lockUnregister(observerLock_);
    if (observer == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return ERR_INVALID_VALUE;
    }

    for (auto it = appStateObserverMap_.begin(); it != appStateObserverMap_.end(); ++it) {
        if (it->first->AsObject() == observer->AsObject()) {
            DecreaseObserverCount(it->second.uid);
            appStateObserverMap_.erase(it);
            TAG_LOGD(AAFwkTag::APPMGR, "appStateObserverMap_ size:%{public}zu", appStateObserverMap_.size());
            RemoveObserverDeathRecipient(observer);
            return ERR_OK;
        }
    }
    TAG_LOGE(AAFwkTag::APPMGR, "observer not exist");
    return ERR_INVALID_VALUE;
}

int32_t AppStateObserverManager::RegisterAppForegroundStateObserver(const sptr<IAppForegroundStateObserver> &observer)
{
    TAG_LOGD(AAFwkTag::APPMGR, "called");
    if (observer == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return ERR_INVALID_VALUE;
    }
    if (AAFwk::PermissionVerification::GetInstance()->VerifyAppStateObserverPermission() == ERR_PERMISSION_DENIED) {
        TAG_LOGE(AAFwkTag::APPMGR, "verification failed");
        return ERR_PERMISSION_DENIED;
    }
    if (IsAppForegroundObserverExist(observer)) {
        TAG_LOGE(AAFwkTag::APPMGR, "observer exist");
        return ERR_INVALID_VALUE;
    }

    std::lock_guard lockRegister(appForegroundObserverLock_);
    appForegroundStateObserverMap_.emplace(observer, IPCSkeleton::GetCallingUid());
    AddObserverDeathRecipient(observer, ObserverType::APP_FOREGROUND_STATE_OBSERVER);
    AddObserverCount(IPCSkeleton::GetCallingUid());
    if (appForegroundStateObserverMap_.size() >= OBSERVER_SINGLE_COUNT_LOG &&
        appForegroundStateObserverMap_.size() % OBSERVER_SINGLE_STEP_LOG == 0) {
        TAG_LOGW(AAFwkTag::APPMGR, "appForegroundObserver size:%{public}zu", appForegroundStateObserverMap_.size());
    }
    return ERR_OK;
}

int32_t AppStateObserverManager::UnregisterAppForegroundStateObserver(const sptr<IAppForegroundStateObserver> &observer)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APPMGR, "called");
    if (observer == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return ERR_INVALID_VALUE;
    }
    if (AAFwk::PermissionVerification::GetInstance()->VerifyAppStateObserverPermission() == ERR_PERMISSION_DENIED) {
        TAG_LOGE(AAFwkTag::APPMGR, "verification failed");
        return ERR_PERMISSION_DENIED;
    }
    std::lock_guard lockUnregister(appForegroundObserverLock_);
    for (const auto &[it, uid] : appForegroundStateObserverMap_) {
        if (it != nullptr && it->AsObject() == observer->AsObject()) {
            DecreaseObserverCount(uid);
            appForegroundStateObserverMap_.erase(it);
            RemoveObserverDeathRecipient(observer);
            return ERR_OK;
        }
    }
    return ERR_INVALID_VALUE;
}

int32_t AppStateObserverManager::RegisterAbilityForegroundStateObserver(
    const sptr<IAbilityForegroundStateObserver> &observer)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APPMGR, "called");
    if (observer == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return ERR_INVALID_VALUE;
    }
    if (AAFwk::PermissionVerification::GetInstance()->VerifyAppStateObserverPermission() == ERR_PERMISSION_DENIED) {
        TAG_LOGE(AAFwkTag::APPMGR, "verification failed");
        return ERR_PERMISSION_DENIED;
    }
    if (IsAbilityForegroundObserverExist(observer)) {
        TAG_LOGW(AAFwkTag::APPMGR, "Observer exist.");
        return ERR_OK;
    }

    std::lock_guard lockRegister(abilityForegroundObserverLock_);
    abilityForegroundObserverMap_.emplace(observer, IPCSkeleton::GetCallingUid());
    AddObserverDeathRecipient(observer, ObserverType::ABILITY_FOREGROUND_STATE_OBSERVER);
    AddObserverCount(IPCSkeleton::GetCallingUid());
    if (abilityForegroundObserverMap_.size() >= OBSERVER_SINGLE_COUNT_LOG &&
        abilityForegroundObserverMap_.size() % OBSERVER_SINGLE_STEP_LOG == 0) {
        TAG_LOGW(AAFwkTag::APPMGR, "abilityForegroundObserver size:%{public}zu", abilityForegroundObserverMap_.size());
    }
    return ERR_OK;
}

int32_t AppStateObserverManager::UnregisterAbilityForegroundStateObserver(
    const sptr<IAbilityForegroundStateObserver> &observer)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APPMGR, "called");
    if (observer == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return ERR_INVALID_VALUE;
    }
    if (AAFwk::PermissionVerification::GetInstance()->VerifyAppStateObserverPermission() == ERR_PERMISSION_DENIED) {
        TAG_LOGE(AAFwkTag::APPMGR, "verification failed");
        return ERR_PERMISSION_DENIED;
    }
    std::lock_guard lockUnregister(abilityForegroundObserverLock_);
    for (const auto &[it, uid] : abilityForegroundObserverMap_) {
        if (it != nullptr && it->AsObject() == observer->AsObject()) {
            DecreaseObserverCount(uid);
            abilityForegroundObserverMap_.erase(it);
            RemoveObserverDeathRecipient(observer);
            return ERR_OK;
        }
    }
    return ERR_INVALID_VALUE;
}

void AppStateObserverManager::OnAppStarted(const std::shared_ptr<AppRunningRecord> &appRecord)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), appRecord]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnAppStarted come.");
        self->HandleOnAppStarted(appRecord);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::OnAppStopped(const std::shared_ptr<AppRunningRecord> &appRecord)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), appRecord]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnAppStopped come.");
        self->HandleOnAppStopped(appRecord);
    };
    handler_->SubmitTask(task);
}


void AppStateObserverManager::OnAppStateChanged(
    const std::shared_ptr<AppRunningRecord> &appRecord,
    const ApplicationState state,
    bool needNotifyApp,
    bool isFromWindowFocusChanged)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), appRecord, state, needNotifyApp, isFromWindowFocusChanged]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnAppStateChanged come.");
        self->HandleAppStateChanged(appRecord, state, needNotifyApp, isFromWindowFocusChanged);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::OnProcessDied(const std::shared_ptr<AppRunningRecord> &appRecord)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), appRecord]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnProcessDied come.");
    self->HandleOnAppProcessDied(appRecord);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::OnRenderProcessDied(const std::shared_ptr<RenderRecord> &renderRecord)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), renderRecord]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnRenderProcessDied come.");
        self->HandleOnRenderProcessDied(renderRecord);
    };
    handler_->SubmitTask(task);
}

#ifdef SUPPORT_CHILD_PROCESS
void AppStateObserverManager::OnChildProcessDied(std::shared_ptr<ChildProcessRecord> childRecord)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), childRecord]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnChildProcessDied come.");
        self->HandleOnChildProcessDied(childRecord);
    };
    handler_->SubmitTask(task);
}
#endif // SUPPORT_CHILD_PROCESS

void AppStateObserverManager::OnProcessStateChanged(
    const std::shared_ptr<AppRunningRecord> &appRecord, bool isFromWindowFocusChanged)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), appRecord, isFromWindowFocusChanged]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnProcessStateChanged come.");
        self->HandleOnProcessStateChanged(appRecord, isFromWindowFocusChanged);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::OnWindowShow(const std::shared_ptr<AppRunningRecord> &appRecord)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "handler is nullptr, OnWindowShow failed.");
        return;
    }

    auto task = [weak = weak_from_this(), appRecord]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "self is nullptr, OnWindowShow failed.");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnWindowShow come.");
        self->HandleOnWindowShow(appRecord);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::OnWindowHidden(const std::shared_ptr<AppRunningRecord> &appRecord)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "handler is nullptr, OnWindowHidden failed.");
        return;
    }

    auto task = [weak = weak_from_this(), appRecord]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "self is nullptr, OnWindowHidden failed.");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnWindowHidden come.");
        self->HandleOnWindowHidden(appRecord);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::OnProcessCreated(const std::shared_ptr<AppRunningRecord> &appRecord, bool isPreload)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), appRecord, isPreload]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        self->HandleOnAppProcessCreated(appRecord, isPreload);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::OnProcessReused(const std::shared_ptr<AppRunningRecord> &appRecord)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), appRecord]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnProcessReused come.");
        self->HandleOnProcessResued(appRecord);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::OnRenderProcessCreated(const std::shared_ptr<RenderRecord> &renderRecord,
    const bool isPreload)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), renderRecord, isPreload]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnRenderProcessCreated come.");
        self->HandleOnRenderProcessCreated(renderRecord, isPreload);
    };
    handler_->SubmitTask(task);
}

#ifdef SUPPORT_CHILD_PROCESS
void AppStateObserverManager::OnChildProcessCreated(std::shared_ptr<ChildProcessRecord> childRecord)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), childRecord]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnChildProcessCreated come.");
        self->HandleOnChildProcessCreated(childRecord);
    };
    handler_->SubmitTask(task);
}
#endif // SUPPORT_CHILD_PROCESS

void AppStateObserverManager::StateChangedNotifyObserver(
    const AbilityStateData abilityStateData, bool isAbility, bool isFromWindowFocusChanged)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), abilityStateData, isAbility, isFromWindowFocusChanged]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "StateChangedNotifyObserver come.");
        self->HandleStateChangedNotifyObserver(abilityStateData, isAbility, isFromWindowFocusChanged);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::HandleOnAppStarted(const std::shared_ptr<AppRunningRecord> &appRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (appRecord == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null appRecord");
        return;
    }

    AppStateData data = WrapAppStateData(appRecord, ApplicationState::APP_STATE_CREATE);
    data.isSpecifyTokenId = appRecord->GetAssignTokenId() > 0 ? true : false;
    TAG_LOGD(AAFwkTag::APPMGR, "HandleOnAppStarted, bundle:%{public}s, uid:%{public}d, state:%{public}d",
        data.bundleName.c_str(), data.uid, data.state);
    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), data.bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            it->first->OnAppStarted(data);
        }
    }
}

void AppStateObserverManager::HandleOnAppStopped(const std::shared_ptr<AppRunningRecord> &appRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (appRecord == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null appRecord");
        return;
    }

    AppStateData data = WrapAppStateData(appRecord, ApplicationState::APP_STATE_TERMINATED);
    TAG_LOGD(AAFwkTag::APPMGR, "HandleOnAppStopped, bundle:%{public}s, uid:%{public}d, state:%{public}d",
        data.bundleName.c_str(), data.uid, data.state);
    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), data.bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            it->first->OnAppStopped(data);
        }
    }
}

void AppStateObserverManager::HandleAppStateChanged(const std::shared_ptr<AppRunningRecord> &appRecord,
    const ApplicationState state, bool needNotifyApp, bool isFromWindowFocusChanged)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (appRecord == nullptr) {
        return;
    }
    if (state == ApplicationState::APP_STATE_FOREGROUND || state == ApplicationState::APP_STATE_BACKGROUND) {
        if (needNotifyApp && !isFromWindowFocusChanged) {
            AppStateData data = WrapAppStateData(appRecord, state, isFromWindowFocusChanged);
            appRecord->GetSplitModeAndFloatingMode(data.isSplitScreenMode, data.isFloatingWindowMode);
            auto appForegroundStateObserverMap = GetAppForegroundStateObserverMapCopy();
            for (const auto &[observer, uid] : appForegroundStateObserverMap) {
                if (observer != nullptr) {
                    observer->OnAppStateChanged(data);
                }
            }
        }
        if (!AAFwk::UIExtensionUtils::IsUIExtension(appRecord->GetExtensionType()) &&
            !AAFwk::UIExtensionUtils::IsWindowExtension(appRecord->GetExtensionType())) {
            AppStateData data = WrapAppStateData(appRecord, state, isFromWindowFocusChanged);
            TAG_LOGD(AAFwkTag::APPMGR, "name:%{public}s, uid:%{public}d, state:%{public}d, notify:%{public}d",
                data.bundleName.c_str(), data.uid, data.state, needNotifyApp);
            auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
            for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
                const auto &bundleNames = it->second.bundleNames;
                auto iter = std::find(bundleNames.begin(), bundleNames.end(), data.bundleName);
                bool valid = (bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr;
                if (valid) {
                    it->first->OnForegroundApplicationChanged(data);
                }
                if (valid && needNotifyApp) {
                    it->first->OnAppStateChanged(data);
                }
            }
        }
    }
    if (state == ApplicationState::APP_STATE_CREATE || state == ApplicationState::APP_STATE_TERMINATED) {
        AppStateData data = WrapAppStateData(appRecord, state, isFromWindowFocusChanged);
        TAG_LOGD(AAFwkTag::APPMGR, "OnApplicationStateChanged, name:%{public}s, uid:%{public}d, state:%{public}d",
            data.bundleName.c_str(), data.uid, data.state);
        auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
        for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
            const auto &bundleNames = it->second.bundleNames;
            auto iter = std::find(bundleNames.begin(), bundleNames.end(), data.bundleName);
            if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
                it->first->OnApplicationStateChanged(data);
            }
        }
    }
}

void AppStateObserverManager::HandleStateChangedNotifyObserver(
    const AbilityStateData abilityStateData, bool isAbility, bool isFromWindowFocusChanged)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APPMGR,
        "Handle state change, module:%{public}s, bundle:%{public}s, ability:%{public}s, state:%{public}d,"
        "pid:%{public}d ,uid:%{public}d, abilityType:%{public}d, isAbility:%{public}d, callerBundleName:%{public}s,"
        "callerAbilityName:%{public}s, isAtomicService:%{public}d, callerUid:%{public}d",
        abilityStateData.moduleName.c_str(), abilityStateData.bundleName.c_str(),
        abilityStateData.abilityName.c_str(), abilityStateData.abilityState,
        abilityStateData.pid, abilityStateData.uid, abilityStateData.abilityType, isAbility,
        abilityStateData.callerBundleName.c_str(), abilityStateData.callerAbilityName.c_str(),
        abilityStateData.isAtomicService, abilityStateData.callerUid);
    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), abilityStateData.bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            if (isAbility) {
                it->first->OnAbilityStateChanged(abilityStateData);
            } else {
                it->first->OnExtensionStateChanged(abilityStateData);
            }
        }
    }

    if ((abilityStateData.abilityState == static_cast<int32_t>(AbilityState::ABILITY_STATE_FOREGROUND) ||
            abilityStateData.abilityState == static_cast<int32_t>(AbilityState::ABILITY_STATE_BACKGROUND)) &&
        isAbility && !isFromWindowFocusChanged) {
        auto abilityForegroundObserverMap = GetAbilityForegroundObserverMapCopy();
        for (auto &[observer, uid] : abilityForegroundObserverMap) {
            if (observer != nullptr) {
                observer->OnAbilityStateChanged(abilityStateData);
            }
        }
    }
}

void AppStateObserverManager::HandleOnAppProcessCreated(const std::shared_ptr<AppRunningRecord> &appRecord,
    bool isPreload)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!appRecord) {
        TAG_LOGE(AAFwkTag::APPMGR, "null appRecord");
        return;
    }
    ProcessData data = WrapProcessData(appRecord);
    data.isPreload = isPreload;
    data.isPreloadModule = appRecord->GetPreloadMode() != PreloadMode::PRESS_DOWN;
    if (data.bundleName == XIAOYI_BUNDLE_NAME && data.extensionType == ExtensionAbilityType::SERVICE) {
        TAG_LOGI(AAFwkTag::APPMGR, "change processType to NORMAL");
        data.processType = ProcessType::NORMAL;
    }
    TAG_LOGI(AAFwkTag::APPMGR,
        "bundle:%{public}s, pid:%{public}d, uid:%{public}d, processType:%{public}d, "
        "extensionType:%{public}d, processName:%{public}s, renderUid:%{public}d, isTestMode:%{public}d, "
        "callerPid:%{public}d, callerUid:%{public}d",
        data.bundleName.c_str(), data.pid, data.uid, data.processType, data.extensionType, data.processName.c_str(),
        data.renderUid, data.isTestMode, data.callerPid, data.callerUid);
    HandleOnProcessCreated(data);
}

void AppStateObserverManager::HandleOnProcessResued(const std::shared_ptr<AppRunningRecord> &appRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!appRecord) {
        TAG_LOGE(AAFwkTag::APPMGR, "null appRecord");
        return;
    }
    ProcessData data = WrapProcessData(appRecord);
    TAG_LOGD(AAFwkTag::APPMGR, "Process Resued, bundle:%{public}s, pid:%{public}d, uid:%{public}d",
        data.bundleName.c_str(), data.pid, data.uid);

    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), data.bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            it->first->OnProcessReused(data);
        }
    }
}

void AppStateObserverManager::HandleOnRenderProcessCreated(const std::shared_ptr<RenderRecord> &renderRecord,
    const bool isPreload)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!renderRecord) {
        TAG_LOGE(AAFwkTag::APPMGR, "null renderRecord");
        return;
    }
    ProcessData data = WrapRenderProcessData(renderRecord);
    data.isPreload = isPreload;
    TAG_LOGD(AAFwkTag::APPMGR,
        "RenderProcess Create, bundle:%{public}s, pid:%{public}d, uid:%{public}d, processType:%{public}d, "
        "processName:%{public}s, renderUid:%{public}d",
        data.bundleName.c_str(), data.pid, data.uid, data.processType, data.processName.c_str(), data.renderUid);
    HandleOnProcessCreated(data);
}

#ifdef SUPPORT_CHILD_PROCESS
void AppStateObserverManager::HandleOnChildProcessCreated(std::shared_ptr<ChildProcessRecord> childRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!childRecord) {
        TAG_LOGE(AAFwkTag::APPMGR, "null childRecord");
        return;
    }
    ProcessData data;
    if (WrapChildProcessData(data, childRecord) != ERR_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "WrapChildProcessData failed");
        return;
    }
    TAG_LOGD(AAFwkTag::APPMGR,
        "ChildProcess Create, bundleName:%{public}s, pid:%{public}d, uid:%{public}d, "
        "processType:%{public}d, processName:%{public}s",
        data.bundleName.c_str(), data.pid, data.uid, data.processType, data.processName.c_str());
    HandleOnProcessCreated(data);
}
#endif // SUPPORT_CHILD_PROCESS

void AppStateObserverManager::HandleOnProcessCreated(const ProcessData &data)
{
    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), data.bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            it->first->OnProcessCreated(data);
        }
    }
}

void AppStateObserverManager::HandleOnProcessStateChanged(
    const std::shared_ptr<AppRunningRecord> &appRecord, bool isFromWindowFocusChanged)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!appRecord) {
        TAG_LOGE(AAFwkTag::APPMGR, "null appRecord");
        return;
    }
    ProcessData data = WrapProcessData(appRecord, isFromWindowFocusChanged);
    if (data.bundleName == XIAOYI_BUNDLE_NAME && data.extensionType == ExtensionAbilityType::SERVICE) {
        TAG_LOGI(AAFwkTag::APPMGR, "change processType to NORMAL");
        data.processType = ProcessType::NORMAL;
    }
    TAG_LOGD(AAFwkTag::APPMGR,
        "bundle:%{public}s, pid:%{public}d, uid:%{public}d, state:%{public}d, "
        "isContinuousTask:%{public}d, gpuPid:%{public}d",
        data.bundleName.c_str(), data.pid, data.uid, data.state, data.isContinuousTask, data.gpuPid);
    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), data.bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            it->first->OnProcessStateChanged(data);
        }
    }
}

void AppStateObserverManager::HandleOnWindowShow(const std::shared_ptr<AppRunningRecord> &appRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!appRecord) {
        TAG_LOGE(AAFwkTag::APPMGR, "app record is null");
        return;
    }
    ProcessData data = WrapProcessData(appRecord);
    TAG_LOGD(AAFwkTag::APPMGR,
        "bundle:%{public}s, pid:%{public}d, uid:%{public}d, state:%{public}d, "
        "isContinuousTask:%{public}d, gpuPid:%{public}d",
        data.bundleName.c_str(), data.pid, data.uid, data.state, data.isContinuousTask, data.gpuPid);
    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), data.bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            it->first->OnWindowShow(data);
        }
    }
}

void AppStateObserverManager::HandleOnWindowHidden(const std::shared_ptr<AppRunningRecord> &appRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!appRecord) {
        TAG_LOGE(AAFwkTag::APPMGR, "app record is null");
        return;
    }
    ProcessData data = WrapProcessData(appRecord);
    TAG_LOGD(AAFwkTag::APPMGR,
        "bundle:%{public}s, pid:%{public}d, uid:%{public}d, state:%{public}d, "
        "isContinuousTask:%{public}d, gpuPid:%{public}d",
        data.bundleName.c_str(), data.pid, data.uid, data.state, data.isContinuousTask, data.gpuPid);
    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), data.bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            it->first->OnWindowHidden(data);
        }
    }
}

void AppStateObserverManager::HandleOnAppProcessDied(const std::shared_ptr<AppRunningRecord> &appRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!appRecord) {
        TAG_LOGE(AAFwkTag::APPMGR, "null appRecord");
        return;
    }
    ProcessData data = WrapProcessData(appRecord);
    TAG_LOGD(AAFwkTag::APPMGR, "Process died, bundle:%{public}s, pid:%{public}d, uid:%{public}d, renderUid:%{public}d,"
        " exitReason:%{public}d, exitMsg:%{public}s",
        data.bundleName.c_str(), data.pid, data.uid, data.renderUid, data.exitReason, data.exitMsg.c_str());
    HandleOnProcessDied(data);
}

void AppStateObserverManager::HandleOnRenderProcessDied(const std::shared_ptr<RenderRecord> &renderRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!renderRecord) {
        TAG_LOGE(AAFwkTag::APPMGR, "null renderRecord");
        return;
    }
    ProcessData data = WrapRenderProcessData(renderRecord);
    TAG_LOGD(AAFwkTag::APPMGR,
        "Render Process died, bundle:%{public}s, pid:%{public}d, uid:%{public}d, renderUid:%{public}d",
        data.bundleName.c_str(), data.pid, data.uid, data.renderUid);
    HandleOnProcessDied(data);
}

#ifdef SUPPORT_CHILD_PROCESS
void AppStateObserverManager::HandleOnChildProcessDied(std::shared_ptr<ChildProcessRecord> childRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!childRecord) {
        TAG_LOGE(AAFwkTag::APPMGR, "null childRecord");
        return;
    }
    ProcessData data;
    if (WrapChildProcessData(data, childRecord) != ERR_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "WrapChildProcessData failed");
        return;
    }
    TAG_LOGD(AAFwkTag::APPMGR,
        "ChildProcess died, bundleName:%{public}s, pid:%{public}d, uid:%{public}d, "
        "processType:%{public}d, processName:%{public}s",
        data.bundleName.c_str(), data.pid, data.uid, data.processType, data.processName.c_str());
    HandleOnProcessDied(data);
}
#endif // SUPPORT_CHILD_PROCESS

void AppStateObserverManager::HandleOnProcessDied(const ProcessData &data)
{
    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), data.bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            it->first->OnProcessDied(data);
        }
    }
}

ProcessData AppStateObserverManager::WrapProcessData(
    const std::shared_ptr<AppRunningRecord> &appRecord, bool isFromWindowFocusChanged)
{
    ProcessData processData;
    processData.bundleName = appRecord->GetBundleName();
    processData.pid = appRecord->GetPid();
    processData.uid = appRecord->GetUid();
    auto applicationInfo = appRecord->GetApplicationInfo();
    if (applicationInfo) {
        processData.accessTokenId = applicationInfo->accessTokenId;
    }
    processData.state = static_cast<AppProcessState>(appRecord->GetState());
    processData.isContinuousTask = appRecord->IsContinuousTask();
    processData.isKeepAlive = appRecord->IsKeepAliveApp() || appRecord->IsKeepAliveAppService();
    processData.isFocused = appRecord->GetFocusFlag();
    processData.requestProcCode = appRecord->GetRequestProcCode();
    processData.processChangeReason = static_cast<int32_t>(appRecord->GetProcessChangeReason());
    processData.processName = appRecord->GetProcessName();
    processData.extensionType = appRecord->GetExtensionType();
    processData.processType = appRecord->GetProcessType();
    if (appRecord->GetUserTestInfo() != nullptr && system::GetBoolParameter(DEVELOPER_MODE_STATE, false)) {
        processData.isTestMode = true;
    }
    processData.exitReason = appRecord->GetExitReason();
    processData.exitMsg = appRecord->GetExitMsg();
    processData.gpuPid = appRecord->GetGPUPid();
    processData.callerPid = appRecord->GetCallerPid();
    processData.callerUid = appRecord->GetCallerUid();
    processData.killReason = appRecord->GetKillReason();
    processData.isFromWindowFocusChanged = isFromWindowFocusChanged;
    return processData;
}

ProcessData AppStateObserverManager::WrapRenderProcessData(const std::shared_ptr<RenderRecord> &renderRecord)
{
    ProcessData processData;
    processData.bundleName = renderRecord->GetHostBundleName();
    processData.pid = renderRecord->GetPid();
    processData.uid = renderRecord->GetHostUid();
    processData.renderUid = renderRecord->GetUid();
    processData.processName = renderRecord->GetProcessName();
    processData.processType = renderRecord->GetProcessType();
    processData.hostPid = renderRecord->GetHostPid();
    return processData;
}

#ifdef SUPPORT_CHILD_PROCESS
int32_t AppStateObserverManager::WrapChildProcessData(ProcessData &processData,
    std::shared_ptr<ChildProcessRecord> childRecord)
{
    if (!childRecord) {
        TAG_LOGE(AAFwkTag::APPMGR, "null childRecord");
        return ERR_INVALID_VALUE;
    }
    auto hostRecord = childRecord->GetHostRecord();
    if (!hostRecord) {
        TAG_LOGE(AAFwkTag::APPMGR, "null hostRecord");
        return ERR_INVALID_VALUE;
    }
    processData.bundleName = hostRecord->GetBundleName();
    processData.uid = hostRecord->GetUid();
    processData.hostPid = childRecord->GetHostPid();
    processData.pid = childRecord->GetPid();
    processData.childUid = childRecord->GetUid();
    processData.processName = childRecord->GetProcessName();
    processData.processType = childRecord->GetProcessType();
    return ERR_OK;
}
#endif // SUPPORT_CHILD_PROCESS

bool AppStateObserverManager::ObserverExist(const sptr<IRemoteBroker> &observer)
{
    if (observer == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return false;
    }
    std::lock_guard lockRegister(observerLock_);
    for (auto it = appStateObserverMap_.begin(); it != appStateObserverMap_.end(); ++it) {
        if (it->first->AsObject() == observer->AsObject()) {
            return true;
        }
    }
    return false;
}

bool AppStateObserverManager::IsAbilityForegroundObserverExist(const sptr<IRemoteBroker> &observer)
{
    if (observer == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return false;
    }
    std::lock_guard lockRegister(abilityForegroundObserverLock_);
    for (const auto &[it, uid] : abilityForegroundObserverMap_) {
        if (it != nullptr && it->AsObject() == observer->AsObject()) {
            return true;
        }
    }
    return false;
}

bool AppStateObserverManager::IsAppForegroundObserverExist(const sptr<IRemoteBroker> &observer)
{
    if (observer == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return false;
    }
    std::lock_guard lockRegister(appForegroundObserverLock_);
    for (const auto &[it, uid] : appForegroundStateObserverMap_) {
        if (it != nullptr && it->AsObject() == observer->AsObject()) {
            return true;
        }
    }
    return false;
}

void AppStateObserverManager::AddObserverDeathRecipient(const sptr<IRemoteBroker> &observer, const ObserverType &type)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APPMGR, "Add observer death recipient begin.");
    if (observer == nullptr || observer->AsObject() == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return;
    }
    std::lock_guard lock(recipientMapMutex_);
    auto it = recipientMap_.find(observer->AsObject());
    if (it != recipientMap_.end()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Death recipient added");
        return;
    } else {
        std::weak_ptr<AppStateObserverManager> thisWeakPtr(shared_from_this());
        sptr<IRemoteObject::DeathRecipient> deathRecipient = nullptr;
        auto deathRecipientFunc = [thisWeakPtr, type](const wptr<IRemoteObject> &remote) {
            auto appStateObserverManager = thisWeakPtr.lock();
            if (appStateObserverManager) {
                appStateObserverManager->OnObserverDied(remote, type);
            }
        };
        if (type == ObserverType::APPLICATION_STATE_OBSERVER) {
            deathRecipient = new (std::nothrow) ApplicationStateObserverRecipient(deathRecipientFunc);
        } else if (type == ObserverType::APP_FOREGROUND_STATE_OBSERVER) {
            deathRecipient = new (std::nothrow) AppForegroundStateObserverRecipient(deathRecipientFunc);
        } else if (type == ObserverType::ABILITY_FOREGROUND_STATE_OBSERVER) {
            deathRecipient = new (std::nothrow) AbilityForegroundStateObserverRecipient(deathRecipientFunc);
        } else {
            TAG_LOGW(AAFwkTag::APPMGR, "null ObserverType");
            return;
        }
        if (deathRecipient == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null deathRecipient");
            return;
        }
        if (!observer->AsObject()->AddDeathRecipient(deathRecipient)) {
            TAG_LOGE(AAFwkTag::APPMGR, "AddDeathRecipient failed");
        }
        recipientMap_.emplace(observer->AsObject(), deathRecipient);
    }
}

void AppStateObserverManager::RemoveObserverDeathRecipient(const sptr<IRemoteBroker> &observer)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APPMGR, "Remove observer death recipient begin.");
    if (observer == nullptr || observer->AsObject() == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return;
    }
    std::lock_guard lock(recipientMapMutex_);
    auto it = recipientMap_.find(observer->AsObject());
    if (it != recipientMap_.end()) {
        it->first->RemoveDeathRecipient(it->second);
        recipientMap_.erase(it);
        return;
    }
}

void AppStateObserverManager::AddObserverCount(int32_t uid)
{
    std::lock_guard lock(observerCountMapMutex_);
    observerAmount_++;
    auto it = observerCountMap_.find(uid);
    if (it == observerCountMap_.end()) {
        observerCountMap_.emplace(uid, 1);
    } else {
        it->second++;
        if (it->second > OBSERVER_UID_COUNT_LOG) {
            TAG_LOGW(AAFwkTag::APPMGR, "too many observer uid: %{public}d, count: %{public}d", uid, it->second);
        }
        if (observerAmount_ % OBSERVER_AMOUNT_COUNT_LOG == 0) {
            for (const auto &[uid, count] : observerCountMap_) {
                TAG_LOGW(AAFwkTag::APPMGR, "observer overview uid: %{public}d, count: %{public}d", uid, count);
            }
        }
    }
}

void AppStateObserverManager::DecreaseObserverCount(int32_t uid)
{
    std::lock_guard lock(observerCountMapMutex_);
    auto it = observerCountMap_.find(uid);
    if (it == observerCountMap_.end()) {
        return;
    }
    it->second--;
    if (it->second <= 0) {
        observerCountMap_.erase(it);
    }
    observerAmount_--;
}

AppStateObserverMap AppStateObserverManager::GetAppStateObserverMapCopy()
{
    std::lock_guard lock(observerLock_);
    return appStateObserverMap_;
}

AppForegroundStateObserverMap AppStateObserverManager::GetAppForegroundStateObserverMapCopy()
{
    std::lock_guard lock(appForegroundObserverLock_);
    return appForegroundStateObserverMap_;
}

AbilityForegroundObserverMap AppStateObserverManager::GetAbilityForegroundObserverMapCopy()
{
    std::lock_guard lock(abilityForegroundObserverLock_);
    return abilityForegroundObserverMap_;
}

void AppStateObserverManager::OnObserverDied(const wptr<IRemoteObject> &remote, const ObserverType &type)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APPMGR, "OnObserverDied");
    auto object = remote.promote();
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null observer");
        return;
    }

    if (type == ObserverType::APPLICATION_STATE_OBSERVER) {
        sptr<IApplicationStateObserver> observer = iface_cast<IApplicationStateObserver>(object);
        UnregisterApplicationStateObserver(observer);
    } else if (type == ObserverType::ABILITY_FOREGROUND_STATE_OBSERVER) {
        sptr<IAbilityForegroundStateObserver> observer = iface_cast<IAbilityForegroundStateObserver>(object);
        UnregisterAbilityForegroundStateObserver(observer);
    } else if (type == ObserverType::APP_FOREGROUND_STATE_OBSERVER) {
        sptr<IAppForegroundStateObserver> observer = iface_cast<IAppForegroundStateObserver>(object);
        UnregisterAppForegroundStateObserver(observer);
    } else {
        TAG_LOGW(AAFwkTag::APPMGR, "null ObserverType");
        return;
    }
}

AppStateData AppStateObserverManager::WrapAppStateData(const std::shared_ptr<AppRunningRecord> &appRecord,
    const ApplicationState state, bool isFromWindowFocusChanged)
{
    AppStateData appStateData;
    appStateData.pid = appRecord->GetPid();
    appStateData.bundleName = appRecord->GetBundleName();
    appStateData.state = static_cast<int32_t>(state);
    appStateData.uid = appRecord->GetUid();
    appStateData.extensionType = appRecord->GetExtensionType();
    appStateData.isPreloadModule = appRecord->GetPreloadMode() != PreloadMode::PRESS_DOWN;
    appStateData.callerUid = appRecord->GetCallerUid();
    appStateData.isFromWindowFocusChanged = isFromWindowFocusChanged;
    if (appRecord->GetApplicationInfo() != nullptr) {
        appStateData.accessTokenId = static_cast<uint32_t>(appRecord->GetApplicationInfo()->accessTokenId);
    }
    appStateData.isFocused = appRecord->GetFocusFlag();
    auto renderRecordMap = appRecord->GetRenderRecordMap();
    if (!renderRecordMap.empty()) {
        for (auto iter : renderRecordMap) {
            auto renderRecord = iter.second;
            if (renderRecord != nullptr) {
                appStateData.renderPids.emplace_back(renderRecord->GetPid());
            }
        }
    }
    std::shared_ptr<RemoteClientManager> remoteClientManager = std::make_shared<RemoteClientManager>();
    auto bundleMgr = remoteClientManager->GetBundleManagerHelper();
    std::string callerBundleName;
    if (bundleMgr != nullptr &&
        IN_PROCESS_CALL(bundleMgr->GetNameForUid(appRecord->GetCallerUid(), callerBundleName)) == ERR_OK) {
        appStateData.callerBundleName = callerBundleName;
    } else {
        appStateData.callerBundleName = "";
    }
    appStateData.appIndex = appRecord->GetAppIndex();
    TAG_LOGD(AAFwkTag::APPMGR, "Handle state change, bundle:%{public}s, state:%{public}d, pid:%{public}d,"
        "uid:%{public}d, isFocused:%{public}d, callerBUndleName: %{public}s, appIndex:%{public}d, callerUid:%{public}d",
        appStateData.bundleName.c_str(), appStateData.state, appStateData.pid, appStateData.uid,
        appStateData.isFocused, appStateData.callerBundleName.c_str(), appStateData.appIndex, appStateData.callerUid);
    return appStateData;
}

void AppStateObserverManager::OnPageShow(const PageStateData pageStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "call");
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), pageStateData]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnProcessCreated come.");
        self->HandleOnPageShow(pageStateData);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::OnPageHide(const PageStateData pageStateData)
{
    TAG_LOGD(AAFwkTag::APPMGR, "call");
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), pageStateData]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnProcessCreated come.");
        self->HandleOnPageHide(pageStateData);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::HandleOnPageShow(const PageStateData pageStateData)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), pageStateData.bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            it->first->OnPageShow(pageStateData);
        }
    }
}

void AppStateObserverManager::HandleOnPageHide(const PageStateData pageStateData)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), pageStateData.bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            it->first->OnPageHide(pageStateData);
        }
    }
}

void AppStateObserverManager::OnAppCacheStateChanged(const std::shared_ptr<AppRunningRecord> &appRecord,
    ApplicationState state)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), appRecord, state]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnAppCacheStateChanged come.");
        self->HandleOnAppCacheStateChanged(appRecord, state);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::HandleOnAppCacheStateChanged(const std::shared_ptr<AppRunningRecord> &appRecord,
    ApplicationState state)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (appRecord == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null appRecord");
        return;
    }

    AppStateData data = WrapAppStateData(appRecord, state);
    data.isSpecifyTokenId = appRecord->GetAssignTokenId() > 0 ? true : false;
    TAG_LOGD(AAFwkTag::APPMGR, "HandleOnAppCacheStateChanged, bundle:%{public}s, uid:%{public}d, state:%{public}d",
        data.bundleName.c_str(), data.uid, data.state);
    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), data.bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            it->first->OnAppCacheStateChanged(data);
        }
    }
}

ProcessBindData AppStateObserverManager::WrapProcessBindData(
    const UIExtensionProcessBindInfo &bindInfo, int32_t bindingRelation)
{
    ProcessBindData processBindData;
    processBindData.bundleName = bindInfo.bundleName;
    processBindData.pid = bindInfo.pid;
    processBindData.uid = bindInfo.uid;
    processBindData.isKeepAlive = bindInfo.isKeepAlive;
    processBindData.extensionType = bindInfo.extensionType;
    processBindData.processType = bindInfo.processType;
    processBindData.callerPid = bindInfo.callerPid;
    processBindData.callerUid = bindInfo.callerUid;
    processBindData.callerBundleName = bindInfo.callerBundleName;
    processBindData.bindingRelation = bindingRelation;
    return processBindData;
}

void AppStateObserverManager::OnProcessBindingRelationChanged(
    const std::shared_ptr<AppRunningRecord> &appRecord,
    const UIExtensionProcessBindInfo &bindInfo, int32_t bindingRelation)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), appRecord, bindInfo, bindingRelation]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnProcessBindingRelationChanged come.");
        self->HandleOnProcessBindingRelationChanged(appRecord, bindInfo, bindingRelation);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::HandleOnProcessBindingRelationChanged(
    const std::shared_ptr<AppRunningRecord> &appRecord,
    const UIExtensionProcessBindInfo &bindInfo, int32_t bindingRelation)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (appRecord == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null appRecord");
        return;
    }

    ProcessBindData data = WrapProcessBindData(bindInfo, bindingRelation);
    TAG_LOGD(AAFwkTag::APPMGR,
        "HandleOnProcessBindingRelationChanged, pid:%{public}d, uid:%{public}d, bundleName:%{public}s, "
        "callerPid:%{public}d, callerUid:%{public}d, callerBundleName:%{public}s, bindingRelation:%{public}d",
        data.pid,
        data.uid,
        data.bundleName.c_str(),
        data.callerPid,
        data.callerUid,
        data.callerBundleName.c_str(),
        data.bindingRelation);
    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), data.bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            it->first->OnProcessBindingRelationChanged(data);
        }
    }
}

void AppStateObserverManager::OnKeepAliveStateChanged(const std::shared_ptr<AppRunningRecord> &appRecord)
{
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), appRecord]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "HandleOnKeepAliveStateChanged come.");
        self->HandleOnKeepAliveStateChanged(appRecord);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::HandleOnKeepAliveStateChanged(const std::shared_ptr<AppRunningRecord> &appRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!appRecord) {
        TAG_LOGE(AAFwkTag::APPMGR, "null appRecord");
        return;
    }
    ProcessData data = WrapProcessData(appRecord);
    TAG_LOGI(AAFwkTag::APPMGR,
        "bundle:%{public}s, pid:%{public}d, uid:%{public}d, processType:%{public}d, "
        "extensionType:%{public}d, processName:%{public}s, renderUid:%{public}d, isTestMode:%{public}d, "
        "callerPid:%{public}d, callerUid:%{public}d, isKeepAlive:%{public}d",
        data.bundleName.c_str(), data.pid, data.uid, data.processType, data.extensionType, data.processName.c_str(),
        data.renderUid, data.isTestMode, data.callerPid, data.callerUid, data.isKeepAlive);

    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), data.bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            it->first->OnKeepAliveStateChanged(data);
        }
    }
}

void AppStateObserverManager::OnProcessPreForegroundChanged(std::shared_ptr<AppRunningRecord> appRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::APPMGR, "OnProcessPreForegroundChanged");
    if (!appRecord) {
        TAG_LOGE(AAFwkTag::APPMGR, "null appRecord");
        return;
    }
    if (handler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null handler");
        return;
    }

    auto task = [weak = weak_from_this(), appRecord]() {
        auto self = weak.lock();
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "null self");
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "OnProcessPreForegroundChanged task.");
        self->HandleOnProcessPreForegroundChanged(appRecord);
    };
    handler_->SubmitTask(task);
}

void AppStateObserverManager::HandleOnProcessPreForegroundChanged(std::shared_ptr<AppRunningRecord> appRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (appRecord == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null appRecord");
        return;
    }

    auto bundleName = appRecord->GetBundleName();
    PreloadProcessData preloadProcessData;
    preloadProcessData.isPreForeground = appRecord->IsPreForeground();
    preloadProcessData.pid = appRecord->GetPid();
    preloadProcessData.uid = appRecord->GetUid();
    preloadProcessData.bundleName = bundleName;

    TAG_LOGI(AAFwkTag::APPMGR,
        "HandleOnProcessPreForegroundChanged, pid:%{public}d, bundle:%{public}s, uid:%{public}d, isPreFore:%{public}d",
        preloadProcessData.pid, bundleName.c_str(), preloadProcessData.uid, preloadProcessData.isPreForeground);
    auto appStateObserverMapCopy = GetAppStateObserverMapCopy();
    for (auto it = appStateObserverMapCopy.begin(); it != appStateObserverMapCopy.end(); ++it) {
        const auto &bundleNames = it->second.bundleNames;
        auto iter = std::find(bundleNames.begin(), bundleNames.end(), bundleName);
        if ((bundleNames.empty() || iter != bundleNames.end()) && it->first != nullptr) {
            it->first->OnProcessPreForegroundChanged(preloadProcessData);
        }
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
