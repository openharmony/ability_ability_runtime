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
using namespace OHOS::AAFwk;
class MockTaskHandlerWrap : public TaskHandlerWrap {
public:
    static std::shared_ptr<MockTaskHandlerWrap> CreateQueueHandler(const std::string &queueName,
        TaskQoS queueQos = TaskQoS::DEFAULT)
    {
        return std::make_shared<MockTaskHandlerWrap>();
    }
    static std::shared_ptr<MockTaskHandlerWrap> GetFfrtHandler()
    {
        return std::make_shared<MockTaskHandlerWrap>();
    }
    MockTaskHandlerWrap() : TaskHandlerWrap("MockTaskHandlerWrap") {}
    MockTaskHandlerWrap(TaskHandlerWrap &) = delete;
    void operator=(MockTaskHandlerWrap &) = delete;
    virtual ~MockTaskHandlerWrap() {}

    MOCK_METHOD2(SubmitTaskInner,
        std::shared_ptr<InnerTaskHandle>(std::function<void()> &&task, const TaskAttribute &));
    bool CancelTaskInner(const std::shared_ptr<InnerTaskHandle> &taskHandle) override
    {
        return true;
    }
    void WaitTaskInner(const std::shared_ptr<InnerTaskHandle> &taskHandle) override {}
    bool RemoveTask(const std::string &name, const TaskHandle &taskHandle)
    {
        return true;
    }
    std::shared_ptr<InnerTaskHandle> MockTaskHandler(const std::function<void()> &&, const TaskAttribute &);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // MOCK_OHOS_ABILITY_RUNTIME_MOCK_TASK_HANDLER_WRAP_H
