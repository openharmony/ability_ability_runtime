/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_AUTO_FILL_EVENT_HANDLER_H
#define OHOS_ABILITY_RUNTIME_AUTO_FILL_EVENT_HANDLER_H

#include <memory>

#include "event_handler.h"
#include "event_runner.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @class AutoFillEventHandler
 * AutoFillEventHandler handling the ability event.
 */
class AutoFillEventHandler : public AppExecFwk::EventHandler {
public:
    explicit AutoFillEventHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    virtual ~AutoFillEventHandler() = default;

private:
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_AUTO_FILL_EVENT_HANDLER_H
