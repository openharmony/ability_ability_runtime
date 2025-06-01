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

#ifndef OHOS_ABILITY_RUNTIME_KIOSK_MANAGER_H
#define OHOS_ABILITY_RUNTIME_KIOSK_MANAGER_H

#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>
#include "interceptor/ability_interceptor_executer.h"
#include "kiosk_status.h"

namespace OHOS {
namespace AAFwk {
class KioskManager : public std::enable_shared_from_this<KioskManager> {
public:
    int32_t UpdateKioskApplicationList(const std::vector<std::string> &appList, std::function<void()> callback);
    int32_t EnterKioskMode(int32_t uid, const std::string &bundleName, std::function<void()> callback);
    int32_t ExitKioskMode(const std::string &bundleName, std::function<void()> callback);
    int32_t GetKioskStatus(KioskStatus &kioskStatus);
    bool IsInKioskMode();
    bool IsInWhiteList(const std::string &bundleName);
    void OnAppStop(const std::string &bundleName, std::function<void()> callback);

private:
    int32_t UpdateKioskApplicationListInner(const std::vector<std::string> &appList, std::function<void()> callback);
    int32_t EnterKioskModeInner(int32_t uid, const std::string &bundleName, std::function<void()> callback);
    int32_t ExitKioskModeInner(const std::string &bundleName, std::function<void()> callback);
    int32_t GetKioskStatusInner(KioskStatus &kioskStatus);
    bool IsInKioskModeInner();
    void notifyKioskModeChanged(bool isInKioskMode);
    bool IsInWhiteListInner(const std::string &bundleName);

    std::mutex mutex_;
    std::unordered_set<std::string> whiteList_;
    KioskStatus kioskStatus_;
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_KIOSK_MANAGER_H
