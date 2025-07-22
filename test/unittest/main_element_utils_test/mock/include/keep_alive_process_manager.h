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

#ifndef OHOS_ABILITY_RUNTIME_KEEP_ALIVE_PROCESS_MANAGER_H
#define OHOS_ABILITY_RUNTIME_KEEP_ALIVE_PROCESS_MANAGER_H

#include <string>

namespace OHOS {
namespace AAFwk {
/**
 * @class KeepAliveProcessManager
 * KeepAliveProcessManager
 */
class KeepAliveProcessManager {
public:
    static bool isKeepAliveBundle;

public:
    /**
     * Get the instance of KeepAliveProcessManager.
     *
     * @return Returns the instance of KeepAliveProcessManager.
     */
    static KeepAliveProcessManager &GetInstance()
    {
        static KeepAliveProcessManager instance;
        return instance;
    }

    /**
     * Check if it is a keep-alive bundle under the specified user.
     *
     * @param bundleName, The bundle name of the keep-alive process.
     * @param userId, The user ID of the bundle.
     */
    bool IsKeepAliveBundle(const std::string &bundleName, int32_t userId)
    {
        return isKeepAliveBundle;
    }

private:
    KeepAliveProcessManager() {}
    ~KeepAliveProcessManager() {}
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_KEEP_ALIVE_PROCESS_MANAGER_H
