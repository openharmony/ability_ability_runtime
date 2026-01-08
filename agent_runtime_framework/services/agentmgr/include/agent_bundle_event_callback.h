/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_AGENT_RUNTIME_AGENT_BUNDLE_EVENT_CALLBACK_H
#define OHOS_AGENT_RUNTIME_AGENT_BUNDLE_EVENT_CALLBACK_H

#include "bundle_event_callback_host.h"
#include "common_event_support.h"

namespace OHOS {
namespace AgentRuntime {
class AgentBundleEventCallback : public AppExecFwk::BundleEventCallbackHost {
public:
    void OnReceiveEvent(const EventFwk::CommonEventData eventData) override;
};
} // namespace OHOS
} // namespace AgentRuntime
#endif // OHOS_AGENT_RUNTIME_AGENT_BUNDLE_EVENT_CALLBACK_H