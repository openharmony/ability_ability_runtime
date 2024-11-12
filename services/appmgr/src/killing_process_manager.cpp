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

#include "killing_process_manager.h"

#include <mutex>

#include "hilog_tag_wrapper.h"
#include "task_handler_wrap.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t CLEAR_CALLER_KEY_DELAY_TIME = 5 * 1000; // 5s
}
KillingProcessManager& KillingProcessManager::GetInstance()
{
    static KillingProcessManager instance;
    return instance;
}

bool KillingProcessManager::IsCallerKilling(std::string callerKey) const
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    return killingCallerKeySet_.find(callerKey) != killingCallerKeySet_.end();
}

void KillingProcessManager::AddKillingCallerKey(std::string callerKey)
{
    auto taskHandler = AAFwk::TaskHandlerWrap::GetFfrtHandler();
    if (taskHandler == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "handler is null");
        return;
    }
    if (callerKey.empty()) {
        TAG_LOGE(AAFwkTag::APPMGR, "invalid callerKey");
        return;
    }
    TAG_LOGI(AAFwkTag::APPMGR, "add caller:%{public}s", callerKey.c_str());
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto ret = killingCallerKeySet_.insert(callerKey);
        if (!ret.second) {
            TAG_LOGI(AAFwkTag::APPMGR, "already inserted");
        }
    }
    auto task = [callerKey] () {
        KillingProcessManager::GetInstance().RemoveKillingCallerKey(callerKey);
    };
    taskHandler->SubmitTask(task, "clearCallerKey", CLEAR_CALLER_KEY_DELAY_TIME);
}

void KillingProcessManager::RemoveKillingCallerKey(std::string callerKey)
{
    if (callerKey.empty()) {
        TAG_LOGE(AAFwkTag::APPMGR, "invalid callerKey");
        return;
    }
    TAG_LOGI(AAFwkTag::APPMGR, "remove caller:%{public}s", callerKey.c_str());
    std::lock_guard<ffrt::mutex> lock(mutex_);
    killingCallerKeySet_.erase(callerKey);
}
}  // namespace AppExecFwk
}  // namespace OHOS