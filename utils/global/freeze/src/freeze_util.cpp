/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "freeze_util.h"

#include "hilog_tag_wrapper.h"
#include "time_util.h"

namespace OHOS::AbilityRuntime {
FreezeUtil& FreezeUtil::GetInstance()
{
    static FreezeUtil instance;
    return instance;
}

void FreezeUtil::AddLifecycleEvent(const LifecycleFlow &flow, const std::string &entry)
{
    auto newEntry = TimeUtil::DefaultCurrentTimeStr() + "; " + entry;
    std::lock_guard lock(mutex_);
    auto iter = lifecycleFlow_.find(flow);
    if (iter != lifecycleFlow_.end()) {
        iter->second += "\n" + newEntry;
    } else {
        lifecycleFlow_.emplace(flow, newEntry);
    }
}

bool FreezeUtil::AppendLifecycleEvent(const LifecycleFlow &flow, const std::string &entry)
{
    std::lock_guard lock(mutex_);
    auto iter = lifecycleFlow_.find(flow);
    if (iter == lifecycleFlow_.end()) {
        return false;
    }
    auto newEntry = TimeUtil::DefaultCurrentTimeStr() + "; " + entry;
    iter->second += "\n" + newEntry;
    return true;
}

std::string FreezeUtil::GetLifecycleEvent(const LifecycleFlow &flow)
{
    std::lock_guard lock(mutex_);
    auto search = lifecycleFlow_.find(flow);
    if (search != lifecycleFlow_.end()) {
        return search->second;
    }
    return "";
}

void FreezeUtil::DeleteLifecycleEvent(const LifecycleFlow &flow)
{
    std::lock_guard lock(mutex_);
    DeleteLifecycleEventInner(flow);
}

void FreezeUtil::DeleteLifecycleEvent(sptr<IRemoteObject> token)
{
    std::lock_guard lock(mutex_);
    if (lifecycleFlow_.empty()) {
        return;
    }
    LifecycleFlow foregroundFlow = { token, TimeoutState::FOREGROUND };
    DeleteLifecycleEventInner(foregroundFlow);

    LifecycleFlow backgroundFlow = { token, TimeoutState::BACKGROUND };
    DeleteLifecycleEventInner(backgroundFlow);
}

void FreezeUtil::DeleteLifecycleEventInner(const LifecycleFlow &flow)
{
    if (lifecycleFlow_.count(flow)) {
        lifecycleFlow_.erase(flow);
    }
    TAG_LOGD(AAFwkTag::DEFAULT, "lifecycleFlow size: %{public}zu", lifecycleFlow_.size());
}

void FreezeUtil::AddAppLifecycleEvent(pid_t pid, const std::string &entry)
{
    std::lock_guard lock(mutex_);
    auto newEntry = TimeUtil::DefaultCurrentTimeStr() + "; " + entry;
    auto iter = appLifeCycleFlow_.find(pid);
    if (iter != appLifeCycleFlow_.end()) {
        iter->second += "\n" + newEntry;
    } else {
        appLifeCycleFlow_.emplace(pid, newEntry);
    }
}

void FreezeUtil::DeleteAppLifecycleEvent(pid_t pid)
{
    std::lock_guard lock(mutex_);
    appLifeCycleFlow_.erase(pid);
}

std::string FreezeUtil::GetAppLifecycleEvent(pid_t pid)
{
    std::lock_guard lock(mutex_);
    auto search = appLifeCycleFlow_.find(pid);
    if (search != appLifeCycleFlow_.end()) {
        return search->second;
    }
    return "";
}
}  // namespace OHOS::AbilityRuntime
