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
#include "oh_mock_utils.h"

namespace OHOS {
namespace AAFwk {
class EventDataBase {
public:
    virtual ~EventDataBase() = default;
};
class EventWrap {
public:
    explicit EventWrap(uint32_t eventId) : EventWrap(eventId, 0) {}
    EventWrap(uint32_t eventId, int64_t param) {}
    EventWrap(uint32_t eventId, int64_t param, bool isExtension) {}
    EventWrap(uint32_t eventId, int64_t param, bool isExtension, const std::string &taskName) {}
    EventWrap(uint32_t eventId, const std::string &taskName) {}
    EventWrap(uint32_t eventId, std::shared_ptr<EventDataBase> data) {}

    OH_MOCK_METHOD_WITH_PREFIX_AMD_SUFFIX(, const, uint32_t, EventWrap, GetEventId);

    int64_t GetParam() const
    {
        return 0;
    }

    OH_MOCK_METHOD_WITH_PREFIX_AMD_SUFFIX(, const, std::shared_ptr<EventDataBase>, EventWrap, GetEventData);

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

    void SetCreateTime(int64_t) {}

    int64_t GetCreateTime() const
    {
        return 0;
    }

    void SetTimeout(int64_t) {}

    int64_t GetTimeout() const
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