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

#ifndef OHOS_AGENT_RUNTIME_AGENT_EXTENSION_H
#define OHOS_AGENT_RUNTIME_AGENT_EXTENSION_H

#include "extension_base.h"

namespace OHOS {
namespace AbilityRuntime {
    class Runtime;
}

namespace AgentRuntime {
class AgentExtensionContext;
using namespace OHOS::AbilityRuntime;
using AbilityHandler = AppExecFwk::AbilityHandler;
using OHOSApplication = AppExecFwk::OHOSApplication;
/**
 * @brief Basic agent extension components.
 */
class AgentExtension : public ExtensionBase<AgentExtensionContext> {
public:
    AgentExtension() = default;
    virtual ~AgentExtension() = default;

    /**
     * @brief Create and init context.
     *
     * @param record the agent extension record.
     * @param application the application info.
     * @param handler the agent extension handler.
     * @param token the remote token.
     * @return The created context.
     */
    virtual std::shared_ptr<AgentExtensionContext> CreateAndInitContext(
        const std::shared_ptr<AbilityLocalRecord> &record,
        const std::shared_ptr<OHOSApplication> &application,
        std::shared_ptr<AbilityHandler> &handler,
        const sptr<IRemoteObject> &token) override;

    /**
     * @brief Init the agent extension record.
     *
     * @param record the agent extension record.
     * @param application the application info.
     * @param handler the agent extension handler.
     * @param token the remote token.
     */
    virtual void Init(const std::shared_ptr<AbilityLocalRecord> &record,
        const std::shared_ptr<OHOSApplication> &application,
        std::shared_ptr<AbilityHandler> &handler,
        const sptr<IRemoteObject> &token) override;
    
    /**
     * @brief Create agent extension.
     *
     * @param runtime The runtime.
     * @return The agent extension instance.
     */
    static AgentExtension* Create(const std::unique_ptr<Runtime>& runtime);
};
}  // namespace AgentRuntime
}  // namespace OHOS
#endif  // OHOS_AGENT_RUNTIME_AGENT_EXTENSION_H
