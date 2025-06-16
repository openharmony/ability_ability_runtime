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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_TASK_HANDLER_WRAP_H
#define MOCK_OHOS_ABILITY_RUNTIME_TASK_HANDLER_WRAP_H

#include <string>
#include <memory>
#include <unordered_map>
#include <functional>
#include <atomic>

#include "task_utils_wrap.h"

namespace OHOS {
namespace AAFwk {
class TaskHandle {
};

class TaskHandlerWrap : public std::enable_shared_from_this<TaskHandlerWrap> {
public:
    static std::shared_ptr<TaskHandlerWrap> CreateQueueHandler(const std::string &queueName,
        TaskQoS queueQos = TaskQoS::DEFAULT)
    {
        return nullptr;
    }

    TaskHandle SubmitTask(const std::function<void()> &task)
    {
        TaskHandle handle;
        return handle;
    }

    TaskHandle SubmitTask(const std::function<void()> &task, const std::string &name)
    {
        TaskHandle handle;
        return handle;
    }

    TaskHandle SubmitTask(const std::function<void()> &task, int64_t delayMillis)
    {
        TaskHandle handle;
        return handle;
    }

    TaskHandle SubmitTask(const std::function<void()> &task, TaskQoS taskQos)
    {
        TaskHandle handle;
        return handle;
    }

    TaskHandle SubmitTask(const std::function<void()> &task, const std::string &name,
        int64_t delayMillis, bool forceSubmit = true)
    {
        TaskHandle handle;
        return handle;
    }

    TaskHandle SubmitTask(const std::function<void()> &task, const TaskAttribute &taskAttr)
    {
        TaskHandle handle;
        return handle;
    }

    TaskHandle SubmitTaskJust(const std::function<void()> &task, const std::string &name,
        int64_t delayMillis)
    {
        TaskHandle handle;
        return handle;
    }

    bool CancelTask(const std::string &name)
    {
        return false;
    }
};
}  // namespace AAFWK
}  // namespace OHOS
#endif