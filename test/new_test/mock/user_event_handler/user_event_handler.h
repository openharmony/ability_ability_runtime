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

#ifndef OHOS_ABILITY_RUNTIME_USER_EVENT_HANDLER_H
#define OHOS_ABILITY_RUNTIME_USER_EVENT_HANDLER_H

#include <memory>

#include "event_handler_wrap.h"

namespace OHOS {
namespace AAFwk {
class UserController;
class UserEventHandler : public EventHandlerWrap {
public:
    UserEventHandler(
        const std::shared_ptr<TaskHandlerWrap> &taskHandler, const std::weak_ptr<UserController> &owner) {}
    
    virtual ~UserEventHandler() {}

    static constexpr uint32_t EVENT_SYSTEM_USER_START = 10;
    static constexpr uint32_t EVENT_SYSTEM_USER_CURRENT = 20;
    static constexpr uint32_t EVENT_REPORT_USER_SWITCH = 30;
    static constexpr uint32_t EVENT_CONTINUE_USER_SWITCH = 40;
    static constexpr uint32_t EVENT_USER_SWITCH_TIMEOUT = 50;
    static constexpr uint32_t EVENT_REPORT_USER_SWITCH_DONE = 60;

    void ProcessEvent(const EventWrap &event) override {}
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_USER_EVENT_HANDLER_H
