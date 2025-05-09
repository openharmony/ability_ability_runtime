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

#include "restart_app_manager.h"

#include "app_scheduler.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AAFwk {
using OHOS::AppExecFwk::AppProcessState;
RestartAppManager &RestartAppManager::GetInstance()
{
    static RestartAppManager instance;
    return instance;
}

bool RestartAppManager::IsRestartAppFrequent(const RestartAppKeyType &key, time_t time)
{
    std::lock_guard<ffrt::mutex> lock(restartAppMapLock_);
    constexpr int64_t MIN_RESTART_TIME = 3;
    auto it = restartAppHistory_.find(key);
    if ((it != restartAppHistory_.end()) && (it->second + MIN_RESTART_TIME > time)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "restart too frequently. try again at least 3s later");
        return true;
    }
    return false;
}

void RestartAppManager::AddRestartAppHistory(const RestartAppKeyType &key, time_t time)
{
    std::lock_guard<ffrt::mutex> lock(restartAppMapLock_);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Refresh uid=%{public}d, instanceKey:%{public}s", key.uid, key.instanceKey.c_str());
    restartAppHistory_[key] = time;
}
}  // namespace AAFwk
}  // namespace OHOS
