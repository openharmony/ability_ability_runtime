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

#include "kiosk_manager.h"

#include <algorithm>

#include "ability_manager_errors.h"
#include "common_event.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "utils/want_utils.h"
#include "interceptor/kiosk_interceptor.h"

namespace OHOS {
namespace AAFwk {
void KioskManager::OnAppStop(const std::string &bundleName,  std::function<void()> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (IsInKioskModeInner() && IsInWhiteListInner(bundleName)) {
        ExitKioskModeInner(bundleName, callback);
    }
}

int32_t KioskManager::UpdateKioskApplicationList(const std::vector<std::string> &appList,
                                                 std::function<void()> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return UpdateKioskApplicationListInner(appList, callback);
}

int32_t KioskManager::EnterKioskMode(int32_t uid, const std::string &bundleName,  std::function<void()> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return EnterKioskModeInner(uid, bundleName, callback);
}

int32_t KioskManager::ExitKioskMode(const std::string &bundleName,  std::function<void()> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return ExitKioskModeInner(bundleName, callback);
}
int32_t KioskManager::GetKioskStatus(KioskStatus &kioskStatus)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return GetKioskStatusInner(kioskStatus);
}

bool KioskManager::IsInKioskMode()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return IsInKioskModeInner();
}

bool KioskManager::IsInWhiteList(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return IsInWhiteListInner(bundleName);
}

int32_t KioskManager::UpdateKioskApplicationListInner(const std::vector<std::string> &appList,
                                                      std::function<void()> callback)
{
    if (IsInKioskModeInner()) {
        auto it = std::find(appList.begin(), appList.end(), kioskStatus_.kioskBundleName_);
        if (it == appList.end()) {
            auto ret = ExitKioskModeInner(kioskStatus_.kioskBundleName_, callback);
            if (ret != ERR_OK) {
                return ret;
            }
        }
    }
    whiteList_.clear();
    for (const auto &app : appList) {
        whiteList_.insert(app);
    }

    return ERR_OK;
}

int32_t KioskManager::EnterKioskModeInner(int32_t uid, const std::string &bundleName, std::function<void()> callback)
{
    if (!IsInWhiteListInner(bundleName)) {
        return ERR_KIOSK_MODE_NOT_IN_WHITELIST;
    }

    if (IsInKioskModeInner()) {
        return ERR_ALREADY_IN_KIOSK_MODE;
    }

    kioskStatus_.isKioskMode_ = true;
    kioskStatus_.kioskBundleName_ = bundleName;
    kioskStatus_.kioskBundleUid_ = uid;
    callback();
    notifyKioskModeChanged(kioskStatus_.isKioskMode_);

    return ERR_OK;
}

int32_t KioskManager::ExitKioskModeInner(const std::string &bundleName, std::function<void()> callback)
{
    if (!IsInWhiteListInner(bundleName)) {
        return ERR_KIOSK_MODE_NOT_IN_WHITELIST;
    }

    if (!IsInKioskModeInner()) {
        return ERR_NOT_IN_KIOSK_MODE;
    }
    kioskStatus_.Clear();
    callback();
    notifyKioskModeChanged(kioskStatus_.isKioskMode_);
    return ERR_OK;
}

int32_t KioskManager::GetKioskStatusInner(KioskStatus &kioskStatus)
{
    kioskStatus = kioskStatus_;
    return ERR_OK;
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
    EventFwk::CommonEventData commonData {want};
    EventFwk::CommonEventManager::PublishCommonEvent(commonData);
}

bool KioskManager::IsInWhiteListInner(const std::string &bundleName)
{
    return whiteList_.count(bundleName) != 0;
}
} // namespace AAFwk
} // namespace OHOS
