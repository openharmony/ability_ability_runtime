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

#ifndef OHOS_ABILITY_RUNTIME_KEEP_ALIVE_UTILS_H
#define OHOS_ABILITY_RUNTIME_KEEP_ALIVE_UTILS_H

#include "bundle_info.h"

namespace OHOS {
namespace AAFwk {
/**
 * @class KeepAliveType
 * defines what type of keep-alive.
 */
enum class KeepAliveType : int32_t {
    UNSPECIFIED = -1,
    RESIDENT_PROCESS = 0,
    THIRD_PARTY = 1,
};

/**
 * @class KeepAliveUtils
 * provides keep-alive utilities.
 */
class KeepAliveUtils final {
public:
    /**
     * NotifyDisableKeepAliveProcesses, notify disable keep-alive processes.
     *
     * @param bundleInfos The list of bundle info.
     * @param userId User id.
     * @return Whether or not the hap module has the main element.
     */
    static void NotifyDisableKeepAliveProcesses(const std::vector<AppExecFwk::BundleInfo> &bundleInfos,
        int32_t userId);

    /**
     * IsKeepAliveBundle, check if bundle is keep-alive.
     *
     * @param bundleInfo The bundle info.
     * @param userId User id.
     * @param type The returned type of keep-alive.
     * @return Whether or not the bundle is keep-alive.
     */
    static bool IsKeepAliveBundle(const AppExecFwk::BundleInfo &bundleInfo, int32_t userId, KeepAliveType &type);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_KEEP_ALIVE_UTILS_H
