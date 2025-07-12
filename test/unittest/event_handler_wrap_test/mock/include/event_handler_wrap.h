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

#ifndef OHOS_ABILITY_RUNTIME_EVENT_HANDLER_WRAP_H
#define OHOS_ABILITY_RUNTIME_EVENT_HANDLER_WRAP_H

#include <string>
#include <memory>
#include <unordered_map>
#include <functional>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "ffrt.h"

namespace OHOS {
namespace AAFwk {
class TaskHandlerWrap {
public:
    static std::shared_ptr<TaskHandlerWrap> GetFfrtHandler();
    MOCK_METHOD(std::shared_ptr<void>, SubmitTaskJust,
        (std::function<void()> task, const std::string& name, int64_t delay), ());
};

class EventTask {
public:
    static bool cancelStatus;
    bool Cancel()
    {
        return cancelStatus;
    }
};

class EventWrap {
public:
    EventWrap() = default;
    explicit EventWrap(uint32_t eventId) : EventWrap(eventId, 0) {}
    EventWrap(uint32_t eventId, int64_t param) {}
    EventWrap(uint32_t eventId, const std::string &taskName) {}

    std::string eventString;
    std::string GetEventString() const
    {
        return eventString;
    }

    void SetTimeout(int64_t) {}
    void SetCreateTime(int64_t) {}
    void SetEventTask(std::shared_ptr<void> task) {}
    EventTask GetEventTask() const { return EventTask(); }
    bool sameStatus = false;
    bool IsSame(const EventWrap &other) const { return sameStatus; }

    int64_t createTime = 0;
    int64_t GetCreateTime() const { return createTime; }
    int64_t timeout = 0;
    int64_t GetTimeout() const { return timeout; }
};

class EventHandlerWrap : public std::enable_shared_from_this<EventHandlerWrap> {
public:
    EventHandlerWrap();
    EventHandlerWrap(std::shared_ptr<TaskHandlerWrap> taskHandler);
    EventHandlerWrap(EventHandlerWrap &) = delete;
    void operator=(EventHandlerWrap &) = delete;
    virtual ~EventHandlerWrap();
    virtual void ProcessEvent(const EventWrap &event);
    bool SendEvent(uint32_t eventId);
    bool SendEvent(uint32_t eventId, int64_t delayMillis);
    bool SendEvent(EventWrap event);
    bool SendEvent(EventWrap event, int64_t delayMillis, bool forceInsert = true);
    bool RemoveEvent(uint32_t eventId, int64_t param = 0);
    bool RemoveEvent(uint32_t eventId, const std::string &taskName);
    bool RemoveEvent(EventWrap event, bool force = true);

protected:
    std::shared_ptr<TaskHandlerWrap> taskHandler_;
    std::function<void(const EventWrap&)> eventCallback_;

    std::unique_ptr<ffrt::mutex> eventMutex_;
    std::unordered_map<std::string, EventWrap> eventMap_;
};
}  // namespace AAFWK
}  // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_EVENT_HANDLER_WRAP_H