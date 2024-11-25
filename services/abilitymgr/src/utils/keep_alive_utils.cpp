/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "keep_alive_utils.h"

#include "ability_resident_process_rdb.h"
#include "ability_util.h"
#include "keep_alive_process_manager.h"
#include "main_element_utils.h"

namespace OHOS {
namespace AAFwk {
void KeepAliveUtils::NotifyDisableKeepAliveProcesses(
    const std::vector<AppExecFwk::BundleInfo> &bundleInfos, int32_t userId)
{
    for (size_t i = 0; i < bundleInfos.size(); i++) {
        std::string processName = bundleInfos[i].applicationInfo.process;
        for (const auto &hapModuleInfo : bundleInfos[i].hapModuleInfos) {
            std::string mainElement;
            bool isDataAbility = false;
            std::string uriStr;
            if (!MainElementUtils::CheckMainElement(hapModuleInfo,
                processName, mainElement, isDataAbility, uriStr, userId)) {
                continue;
            }
            MainElementUtils::UpdateMainElement(hapModuleInfo.bundleName,
                hapModuleInfo.name, mainElement, false, userId);
        }
    }
}

bool KeepAliveUtils::IsKeepAliveBundle(const AppExecFwk::BundleInfo &bundleInfo, int32_t userId, KeepAliveType &type)
{
    if (KeepAliveProcessManager::GetInstance().IsKeepAliveBundle(bundleInfo.name, userId)) {
        type = KeepAliveType::THIRD_PARTY;
        return true;
    }

    bool keepAliveEnable = bundleInfo.isKeepAlive;
    AbilityRuntime::AmsResidentProcessRdb::GetInstance().GetResidentProcessEnable(bundleInfo.name, keepAliveEnable);
    if (keepAliveEnable) {
        type = KeepAliveType::RESIDENT_PROCESS;
    }
    return keepAliveEnable;
}
}  // namespace AAFwk
}  // namespace OHOS
