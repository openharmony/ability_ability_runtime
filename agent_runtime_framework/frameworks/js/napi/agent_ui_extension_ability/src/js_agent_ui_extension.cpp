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

#include "js_agent_ui_extension.h"

#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "js_ui_extension_base.h"

namespace OHOS {
namespace AgentRuntime {
JsAgentUIExtension *JsAgentUIExtension::Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime)
{
    return new JsAgentUIExtension(runtime);
}

JsAgentUIExtension::JsAgentUIExtension(const std::unique_ptr<AbilityRuntime::Runtime> &runtime)
{
    std::shared_ptr<AbilityRuntime::UIExtensionBaseImpl> uiExtensionBaseImpl =
        std::make_shared<AbilityRuntime::JsUIExtensionBase>(runtime);
    SetUIExtensionBaseImpl(uiExtensionBaseImpl);
}

JsAgentUIExtension::~JsAgentUIExtension()
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "destructor");
}
} // namespace AgentRuntime
} // namespace OHOS