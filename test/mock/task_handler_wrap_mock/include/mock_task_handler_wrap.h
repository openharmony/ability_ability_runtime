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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_MOCK_TASK_HANDLER_WRAP_H
#define MOCK_OHOS_ABILITY_RUNTIME_MOCK_TASK_HANDLER_WRAP_H

#include "gmock/gmock.h"
#include "task_handler_wrap.h"

namespace OHOS {
namespace AppExecFwk {
class MockTaskHandlerWrap : public TaskHandlerWrap {
public:
    static std::shared_ptr<TaskHandlerWrap> CreateQueueHandler(const std::string &queueName,
        TaskQoS queueQos = TaskQoS::DEFAULT)
    {
        return std::make_shared<MockTaskHandlerWrap>();
    }
    static std::shared_ptr<TaskHandlerWrap> GetFfrtHandler()
    {
        return std::make_shared<MockTaskHandlerWrap>();
    }
    MockTaskHandlerWrap() = default;
    MockTaskHandlerWrap(TaskHandlerWrap &) = delete;
    void operator=(MockTaskHandlerWrap &) = delete;
    virtual ~MockTaskHandlerWrap() {}

    MOCK_METHOD1(SubmitTask, TaskHandle(const std::function<void()> &));
    MOCK_METHOD2(SubmitTask, TaskHandle(const std::function<void()> &task, TaskQoS taskQos));

    MOCK_METHOD1(SubmitTask, bool (const std::string &));
protected:
    std::shared_ptr<InnerTaskHandle> SubmitTaskInner(std::function<void()> &&task,
        const TaskAttribute &taskAttr) override
    {
        return nullptr;
    }
    bool CancelTaskInner(const std::shared_ptr<InnerTaskHandle> &taskHandle) override
    {
        return true;
    }
    void WaitTaskInner(const std::shared_ptr<InnerTaskHandle> &taskHandle) override {}
    bool RemoveTask(const std::string &name, const TaskHandle &taskHandle)
    {
        return true;
    }
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // MOCK_OHOS_ABILITY_RUNTIME_MOCK_TASK_HANDLER_WRAP_H
