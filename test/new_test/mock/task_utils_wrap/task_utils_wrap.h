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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_TASK_UTILS_WRAP_H
#define MOCK_OHOS_ABILITY_RUNTIME_TASK_UTILS_WRAP_H

#include <string>
namespace OHOS {
namespace AAFwk {
enum class TaskStatus {
    PENDING,
    EXECUTING,
    FINISHED,
    CANCELED
};

enum class TaskQoS {
    INHERENT = 0,
    BACKGROUND,
    UTILITY,
    DEFAULT,
    USER_INITIATED,
    DEADLINE_REQUEST,
    USER_INTERACTIVE
};

enum class TaskQueuePriority {
    IMMEDIATE = 0,
    HIGH,
    LOW,
    IDLE
};

struct TaskAttribute {
    std::string taskName_;
    int64_t delayMillis_ = 0;
    TaskQoS taskQos_ = TaskQoS::DEFAULT;
    TaskQueuePriority taskPriority_ = TaskQueuePriority::LOW;
    int64_t timeoutMillis_ = 0;  // task should be started within timeout
    bool insertHead_ = false;  // insert into the head of the queue
};
} // namespace AAFwk
} // namespace OHOS
#endif