/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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


#include <algorithm>

#include "ability_manager_service.h"
#include "ability_record.h"
#include "ability_manager_errors.h"
#include "common_event.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "hilog_tag_wrapper.h"
#include "interceptor/kiosk_interceptor.h"
#include "ipc_skeleton.h"
#include "kiosk_manager.h"
#include "permission_constants.h"
#include "singleton.h"
#include "utils/want_utils.h"

namespace OHOS {
namespace AAFwk {
std::shared_ptr<KioskManager> KioskManager::instance_ = nullptr;
std::once_flag KioskManager::singletonFlag_;
std::shared_ptr<KioskManager> KioskManager::GetInstance()
{
    std::call_once(singletonFlag_, [] () {
        instance_ = std::shared_ptr<KioskManager>(new KioskManager());
    });
    return instance_;
}

void KioskManager::OnAppStop(const AppInfo &info)
{
    if (info.state != AppState::TERMINATED && info.state != AppState::END) {
        return;
    }
    std::lock_guard<std::mutex> lock(kioskManagermutex_);
    if (IsInKioskModeInner() && IsInWhiteListInner(info.bundleName)) {
        ExitKioskModeInner(info.bundleName);
    }
}

int32_t KioskManager::UpdateKioskApplicationList(const std::vector<std::string> &appList)
{
    if (!CheckKioskPermission()) {
        return CHECK_PERMISSION_FAILED;
    }
    std::lock_guard<std::mutex> lock(kioskManagermutex_);
    if (IsInKioskModeInner()) {
        auto it = std::find(appList.begin(), appList.end(), kioskStatus_.kioskBundleName_);
        if (it == appList.end()) {
            auto ret = ExitKioskModeInner(kioskStatus_.kioskBundleName_);
            if (ret != ERR_OK) {
                return ret;
            }
        }
    }
    whitelist_.clear();
    for (const auto &app : appList) {
        whitelist_.insert(app);
    }

    return ERR_OK;
}

int32_t KioskManager::EnterKioskMode(sptr<IRemoteObject> callerToken)
{
    auto record = Token::GetAbilityRecordByToken(callerToken);
    if (!record) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "record null");
        return INVALID_PARAMETERS_ERR;
    }
    std::string bundleName = record->GetAbilityInfo().bundleName;
    if (!CheckCallerIsForeground(callerToken)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "The application is not in the foreground !");
        return ERR_APP_NOT_IN_FOCUS;
    }
    std::lock_guard<std::mutex> lock(kioskManagermutex_);
    if (!IsInWhiteListInner(bundleName)) {
        return ERR_KIOSK_MODE_NOT_IN_WHITELIST;
    }

    if (IsInKioskModeInner()) {
        return ERR_ALREADY_IN_KIOSK_MODE;
    }

    kioskStatus_.isKioskMode_ = true;
    kioskStatus_.kioskBundleName_ = bundleName;
    kioskStatus_.kioskBundleUid_ = IPCSkeleton::GetCallingUid();
    GetEnterKioskModeCallback()();
    notifyKioskModeChanged(kioskStatus_.isKioskMode_);

    return ERR_OK;
}

int32_t KioskManager::ExitKioskMode(sptr<IRemoteObject> callerToken)
{
    auto record = Token::GetAbilityRecordByToken(callerToken);
    if (!record) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "record null");
        return INVALID_PARAMETERS_ERR;
    }
    std::lock_guard<std::mutex> lock(kioskManagermutex_);
    return ExitKioskModeInner(record->GetAbilityInfo().bundleName);
}

int32_t KioskManager::ExitKioskModeInner(const std::string & bundleName)
{
    if (!IsInWhiteListInner(bundleName)) {
        return ERR_KIOSK_MODE_NOT_IN_WHITELIST;
    }

    if (!IsInKioskModeInner()) {
        return ERR_NOT_IN_KIOSK_MODE;
    }
    kioskStatus_.Clear();
    GetExitKioskModeCallback()();
    notifyKioskModeChanged(kioskStatus_.isKioskMode_);
    return ERR_OK;
}

int32_t KioskManager::GetKioskStatus(KioskStatus &kioskStatus)
{
    if (!CheckKioskPermission()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "without Kiosk mode permission");
        return CHECK_PERMISSION_FAILED;
    }
    std::lock_guard<std::mutex> lock(kioskManagermutex_);
    kioskStatus = kioskStatus_;
    return ERR_OK;
}

bool KioskManager::IsInKioskMode()
{
    std::lock_guard<std::mutex> lock(kioskManagermutex_);
    return IsInKioskModeInner();
}

bool KioskManager::IsInWhiteList(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(kioskManagermutex_);
    return IsInWhiteListInner(bundleName);
}

bool KioskManager::IsInKioskModeInner()
{
    return kioskStatus_.isKioskMode_;
}

void KioskManager::notifyKioskModeChanged(bool isInKioskMode)
{
    std::string eventData = isInKioskMode
                                ? EventFwk::CommonEventSupport::COMMON_EVENT_KIOSK_MODE_ON
                                : EventFwk::CommonEventSupport::COMMON_EVENT_KIOSK_MODE_OFF;
    Want want;
    want.SetAction(eventData);
    want.SetParam("bundleName", kioskStatus_.kioskBundleName_);
    want.SetParam("uid", kioskStatus_.kioskBundleUid_);
    want.SetParam("userId", kioskStatus_.kioskBundleUid_ / BASE_USER_RANGE);
    EventFwk::CommonEventData commonData {want};
    EventFwk::CommonEventManager::PublishCommonEvent(commonData);
}

bool KioskManager::IsInWhiteListInner(const std::string &bundleName)
{
    return whitelist_.count(bundleName) != 0;
}

std::function<void()> KioskManager::GetEnterKioskModeCallback()
{
    auto enterKioskModeCallback = []() {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "EnterKioskMode");
        auto kioskManager = KioskManager::GetInstance();
        if (!kioskManager) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid abilityMgr pointer");
            return;
        }
        kioskManager->AddKioskInterceptor();
    };
    return enterKioskModeCallback;
}

std::function<void()> KioskManager::GetExitKioskModeCallback()
{
    auto exitKioskModeCallback = []() {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "EnterKioskMode");
        auto kioskManager = KioskManager::GetInstance();
        if (!kioskManager) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid abilityMgr pointer");
            return;
        }
        kioskManager->RemoveKioskInterceptor();
    };
    return exitKioskModeCallback;
}

void KioskManager::AddKioskInterceptor()
{
    auto abilityMgr = DelayedSingleton<AbilityManagerService>::GetInstance();
    if (abilityMgr == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid abilityMgr pointer");
        return;
    }
    auto interceptorExecuter = abilityMgr->GetAbilityInterceptorExecuter();
    if (interceptorExecuter == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid interceptorExecuter pointer");
        return;
    }
    interceptorExecuter->AddInterceptor("KioskWhitelist", std::make_shared<KioskInterceptor>());
}

void KioskManager::RemoveKioskInterceptor()
{
    auto abilityMgr = DelayedSingleton<AbilityManagerService>::GetInstance();
    if (abilityMgr == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid abilityMgr pointer");
        return;
    }
    auto interceptorExecuter = abilityMgr->GetAbilityInterceptorExecuter();
    if (interceptorExecuter == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid interceptorExecuter pointer");
        return;
    }
    interceptorExecuter->RemoveInterceptor("KioskWhitelist");
}

bool KioskManager::CheckCallerIsForeground(sptr<IRemoteObject> callerToken)
{
    AppExecFwk::RunningProcessInfo processInfo;
    DelayedSingleton<AppScheduler>::GetInstance()->GetRunningProcessInfoByToken(
        callerToken, processInfo);

    return processInfo.state_ ==
           AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
}

bool KioskManager::CheckKioskPermission()
{
    if ((PermissionVerification::GetInstance()->IsSystemAppCall() ||
         PermissionVerification::GetInstance()->IsSACall()) &&
        PermissionVerification::GetInstance()->VerifyCallingPermission(
            PermissionConstants::PERMISSION_MANAGE_EDM_POLICY)) {
        return true;
    }

    TAG_LOGE(AAFwkTag::ABILITYMGR, "without KIOSK mode permission");
    return false;
}
} // namespace AAFwk
} // namespace OHOS
