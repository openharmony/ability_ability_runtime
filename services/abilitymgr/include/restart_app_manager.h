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

#ifndef OHOS_ABILITY_RUNTIME_RESTART_APP_MANAGER_H
#define OHOS_ABILITY_RUNTIME_RESTART_APP_MANAGER_H

#include <mutex>
#include <string>
#include <unordered_map>
#include "cpp/mutex.h"
#include "nocopyable.h"

namespace OHOS {
namespace AAFwk {
/**
 * @class RestartAppManager
 * RestartAppManager provides a facility for managing restart app history.
 */
class RestartAppManager {
public:
    virtual ~RestartAppManager() = default;
    static RestartAppManager &GetInstance();

    bool IsRestartAppFrequent(int32_t uid, time_t time);
    void AddRestartAppHistory(int32_t uid, time_t time);
    bool IsForegroundToRestartApp() const;

private:
    RestartAppManager() = default;
    DISALLOW_COPY_AND_MOVE(RestartAppManager);

    ffrt::mutex restartAppMapLock_;
    std::unordered_map<int32_t, time_t> restartAppHistory_; // RestartAppKey:time
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_RESTART_APP_MANAGER_H
