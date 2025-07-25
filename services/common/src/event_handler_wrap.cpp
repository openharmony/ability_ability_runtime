/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "event_handler_wrap.h"

#include <cinttypes>
#include <chrono>
#include <mutex>
#include "cpp/mutex.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {
namespace {
constexpr int64_t EVENT_TIME_DIFF = 200;  // ms
constexpr int64_t EVENT_TIME_CANCEL = 3000; // ms
inline int64_t GetCurrentTimeMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
}
EventHandlerWrap::EventHandlerWrap() : taskHandler_(TaskHandlerWrap::GetFfrtHandler())
{
    eventMutex_ = std::make_unique<ffrt::mutex>();
}

EventHandlerWrap::EventHandlerWrap(std::shared_ptr<TaskHandlerWrap> taskHandler)
    : taskHandler_(taskHandler)
{
    eventMutex_ = std::make_unique<ffrt::mutex>();
}

EventHandlerWrap::~EventHandlerWrap() = default;

void EventHandlerWrap::ProcessEvent(const EventWrap &event)
{
    if (eventCallback_) {
        eventCallback_(event);
    }
}
bool EventHandlerWrap::SendEvent(uint32_t eventId)
{
    return SendEvent(EventWrap(eventId, 0));
}
bool EventHandlerWrap::SendEvent(uint32_t eventId, int64_t delayMillis)
{
    return SendEvent(EventWrap(eventId, 0), delayMillis);
}
bool EventHandlerWrap::SendEvent(EventWrap event)
{
    return SendEvent(event, 0);
}
bool EventHandlerWrap::SendEvent(EventWrap event, int64_t delayMillis, bool forceInsert)
{
    if (!taskHandler_) {
        return false;
    }
    auto eventStr = event.GetEventString();
    std::lock_guard<ffrt::mutex> guard(*eventMutex_);
    auto it  = eventMap_.find(eventStr);
    if (it != eventMap_.end() && !forceInsert) {
        return false;
    }

    event.SetTimeout(delayMillis);
    event.SetCreateTime(GetCurrentTimeMillis());
    event.SetEventTask(taskHandler_->SubmitTaskJust([wthis = weak_from_this(), event]() {
        auto timeCost = GetCurrentTimeMillis() - event.GetCreateTime();
        if (timeCost - event.GetTimeout() > EVENT_TIME_DIFF) {
            TAG_LOGW(AAFwkTag::DEFAULT, "createtime: %{public}" PRId64 ", timeout: %{public}" PRId64,
                event.GetCreateTime(), event.GetTimeout());
        }
        auto pthis = wthis.lock();
        if (pthis) {
            pthis->ProcessEvent(event);
            pthis->RemoveEvent(event, false);
        }
    }, eventStr, delayMillis));

    if (it != eventMap_.end()) {
        it->second = event;
    } else {
        eventMap_.emplace(eventStr, event);
    }

    return true;
}

bool EventHandlerWrap::RemoveEvent(uint32_t eventId, int64_t param)
{
    return RemoveEvent(EventWrap(eventId, param));
}

bool EventHandlerWrap::RemoveEvent(uint32_t eventId, const std::string &taskName)
{
    return RemoveEvent(EventWrap(eventId, taskName));
}

bool EventHandlerWrap::RemoveEvent(EventWrap event, bool force)
{
    std::lock_guard<ffrt::mutex> guard(*eventMutex_);
    auto it = eventMap_.find(event.GetEventString());
    if (it == eventMap_.end()) {
        TAG_LOGW(AAFwkTag::DEFAULT, "can't find event: %{public}s ", event.GetEventString().c_str());
        return false;
    }
    auto isSame = it->second.IsSame(event);
    const auto &origin = it->second;
    auto timeCost = GetCurrentTimeMillis() - origin.GetCreateTime();
    if (force && timeCost > EVENT_TIME_CANCEL) {
        TAG_LOGW(AAFwkTag::DEFAULT, "event: %{public}s, timecost: %{public}" PRId64", delay: %{public}" PRId64,
            origin.GetEventString().c_str(), timeCost, origin.GetTimeout());
    }
    if (force || isSame) {
        auto result = it->second.GetEventTask().Cancel();
        if (!result) {
            TAG_LOGE(AAFwkTag::DEFAULT, "remove fail: %{public}s", event.GetEventString().c_str());
        }
        eventMap_.erase(it);
        return true;
    }
    TAG_LOGD(AAFwkTag::DEFAULT, "force: %{public}d , IsSame: %{public}d", force, isSame);
    return false;
}
}  // namespace AAFWK
}  // namespace OHOS