/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "queue_task_handler_wrap.h"

namespace OHOS {
namespace AAFwk {
constexpr int32_t QUEUE_TIME_OUT = 500000; // us
QueueTaskHandlerWrap::QueueTaskHandlerWrap(const std::string &queueName, TaskQoS queueQos)
    : TaskHandlerWrap(queueName),
    taskQueue_(queueName.c_str(), ffrt::queue_attr().qos(Convert2FfrtQos(queueQos)).timeout(QUEUE_TIME_OUT))
{}

QueueTaskHandlerWrap::QueueTaskHandlerWrap(const std::string &queueName, int32_t concurrentNum, TaskQoS queueQos)
    : TaskHandlerWrap(queueName), taskQueue_(
        ffrt::queue_type::queue_concurrent,
        queueName.c_str(),
        ffrt::queue_attr().qos(Convert2FfrtQos(queueQos)).timeout(QUEUE_TIME_OUT).max_concurrency(concurrentNum))
{}

std::shared_ptr<InnerTaskHandle> QueueTaskHandlerWrap::SubmitTaskInner(std::function<void()> &&task,
    const TaskAttribute &taskAttr)
{
    ffrt::task_attr ffrtTaskAttr{};
    BuildFfrtTaskAttr(taskAttr, ffrtTaskAttr);
    if (taskAttr.insertHead_) {
        return std::make_shared<InnerTaskHandle>(taskQueue_.submit_head_h(std::move(task), ffrtTaskAttr));
    }
    return std::make_shared<InnerTaskHandle>(taskQueue_.submit_h(std::move(task), ffrtTaskAttr));
}

bool QueueTaskHandlerWrap::CancelTaskInner(const std::shared_ptr<InnerTaskHandle> &taskHandle)
{
    if (!taskHandle) {
        return false;
    }
    return taskQueue_.cancel(taskHandle->GetFfrtHandle()) == 0;
}
void QueueTaskHandlerWrap::WaitTaskInner(const std::shared_ptr<InnerTaskHandle> &taskHandle)
{
    if (!taskHandle) {
        return;
    }
    taskQueue_.wait(taskHandle->GetFfrtHandle());
}

uint64_t QueueTaskHandlerWrap::GetTaskCount()
{
    return taskQueue_.get_task_cnt();
}
} // namespace AAFwk
} // namespace OHOS