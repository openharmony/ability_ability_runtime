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

#include "agent_ui_extension.h"

#include "hilog_tag_wrapper.h"
#include "js_agent_ui_extension.h"
#include "runtime.h"
#include "ui_extension_context.h"

namespace OHOS {
namespace AgentRuntime {
AgentUIExtension *AgentUIExtension::Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "called");
    if (!runtime) {
        return new AgentUIExtension();
    }
    switch (runtime->GetLanguage()) {
        case AbilityRuntime::Runtime::Language::JS:
            return JsAgentUIExtension::Create(runtime);
        default:
            return new AgentUIExtension();
    }
}
} // namespace AgentRuntime
} // namespace OHOS