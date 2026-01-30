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

#include "agent_extension.h"
#include "agent_extension_context.h"
#include "connection_manager.h"
#include "hilog_tag_wrapper.h"
#include "js_agent_extension.h"
#include "runtime.h"

namespace OHOS {
namespace AgentRuntime {
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
using Runtime = OHOS::AbilityRuntime::Runtime;

AgentExtension* AgentExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    if (!runtime) {
        return new AgentExtension();
    }

    TAG_LOGD(AAFwkTag::SER_ROUTER, "called");
    switch (runtime->GetLanguage()) {
        case Runtime::Language::JS:
            return JsAgentExtension::Create(runtime);
        default:
            return new AgentExtension();
    }
}

void AgentExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application,
    std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    ExtensionBase<AgentExtensionContext>::Init(record, application, handler, token);
    TAG_LOGD(AAFwkTag::SER_ROUTER, "begin init context");
}

std::shared_ptr<AgentExtensionContext> AgentExtension::CreateAndInitContext(
    const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application,
    std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    std::shared_ptr<AgentExtensionContext> context =
        ExtensionBase<AgentExtensionContext>::CreateAndInitContext(record, application, handler, token);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null context");
        return nullptr;
    }
    return context;
}
} // namespace AgentRuntime
} // namespace OHOS
