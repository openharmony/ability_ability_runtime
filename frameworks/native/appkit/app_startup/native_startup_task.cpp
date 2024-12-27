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

#include "native_startup_task.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
const std::string NativeStartupTask::TASK_TYPE = "Native";

NativeStartupTask::NativeStartupTask(const std::string& name, TaskInitFunc taskInitFunc) : StartupTask(name),
    taskInitFunc_(std::move(taskInitFunc))
{
}

NativeStartupTask::~NativeStartupTask() = default;

const std::string &NativeStartupTask::GetType() const
{
    return TASK_TYPE;
}

int32_t NativeStartupTask::RunTaskInit(std::unique_ptr<StartupTaskResultCallback> callback)
{
    if (taskInitFunc_ == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "task: %{public}s, taskInitFunc_ is null", name_.c_str());
    }
    return taskInitFunc_(std::move(callback));
}

int32_t NativeStartupTask::RunTaskOnDependencyCompleted(const std::string& dependencyName,
    const std::shared_ptr<StartupTaskResult>& result)
{
    // no onDependencyCompleted callback, do nothing
    return ERR_OK;
}
} // namespace AbilityRuntime
} // namespace OHOS
