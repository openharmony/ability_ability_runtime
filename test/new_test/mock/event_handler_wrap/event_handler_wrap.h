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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_EVENT_HANDLER_WRAP_H
#define MOCK_OHOS_ABILITY_RUNTIME_EVENT_HANDLER_WRAP_H

#include <string>
#include <memory>
#include <unordered_map>
#include <functional>

#include "task_handler_wrap.h"

namespace OHOS {
namespace AAFwk {
class EventDataBase {
public:
    virtual ~EventDataBase() = default;
};
class EventWrap {
public:
    EventWrap(uint32_t eventId) : EventWrap(eventId, 0) {}
    EventWrap(uint32_t eventId, int64_t param) {}
    EventWrap(uint32_t eventId, int64_t param, bool isExtension) {}
    EventWrap(uint32_t eventId, int64_t param, bool isExtension, const std::string &taskName) {}
    EventWrap(uint32_t eventId, const std::string &taskName) {}
    EventWrap(uint32_t eventId, std::shared_ptr<EventDataBase> data) {}

    uint32_t GetEventId() const
    {
        return 0;
    }

    int64_t GetParam() const
    {
        return 0;
    }

    std::shared_ptr<EventDataBase> GetEventData() const
    {
        return nullptr;
    }

    TaskHandle GetEventTask() const
    {
        return TaskHandle();
    }

    void SetEventTask(const TaskHandle &eventTask) {}

    std::string GetEventString()
    {
        return "";
    }

    bool IsSame(const EventWrap &other) const
    {
        return false;
    }

    void SetRunCount(int runCount) {}

    int GetRunCount() const
    {
        return 0;
    }

    void SetTimeout(uint32_t timeout) {}

    uint32_t GetTimeout() const
    {
        return 0;
    }

    bool IsExtension() const
    {
        return false;
    }
};

class EventHandlerWrap : public std::enable_shared_from_this<EventHandlerWrap> {
public:
    EventHandlerWrap() {}
    EventHandlerWrap(std::shared_ptr<TaskHandlerWrap> taskHandler) {}

    virtual void ProcessEvent(const EventWrap &event) {}

    bool SendEvent(uint32_t eventId)
    {
        return false;
    }

    bool SendEvent(uint32_t eventId, int64_t delayMillis)
    {
        return false;
    }

    bool SendEvent(EventWrap event)
    {
        return false;
    }

    bool SendEvent(EventWrap event, int64_t delayMillis, bool forceInsert = true)
    {
        return false;
    }

    bool RemoveEvent(uint32_t eventId, int64_t param = 0)
    {
        return false;
    }

    bool RemoveEvent(uint32_t eventId, const std::string &taskName)
    {
        return false;
    }

    bool RemoveEvent(EventWrap event, bool force = true)
    {
        return false;
    }

    void SetEventCallback(std::function<void(const EventWrap&)> eventCallback) {}
};
}  // namespace AAFWK
}  // namespace OHOS
#endif // MOCK_OHOS_ABILITY_RUNTIME_EVENT_HANDLER_WRAP_H