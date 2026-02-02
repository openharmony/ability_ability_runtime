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

#ifndef OHOS_AGENT_RUNTIME_AGENT_UI_EXTENSION_H
#define OHOS_AGENT_RUNTIME_AGENT_UI_EXTENSION_H

#include <memory>

#include "ui_extension_base.h"

namespace OHOS {
namespace AbilityRuntime {
class Runtime;
} // namespace AbilityRuntime

namespace AgentRuntime {
/**
 * @brief Agent UI Extension base class.
 *
 * This class provides the base functionality for Agent UI Extension abilities.
 * It extends UIExtensionBase and provides factory methods for creating
 * language-specific implementations.
 */
class AgentUIExtension : public AbilityRuntime::UIExtensionBase<> {
public:
    AgentUIExtension() = default;
    virtual ~AgentUIExtension() = default;

    /**
     * @brief Create an AgentUIExtension instance based on the runtime language.
     *
     * @param runtime The runtime instance used to determine the language implementation.
     * @return Returns a pointer to the created AgentUIExtension instance.
     */
    static AgentUIExtension *Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime);
};

} // namespace AgentRuntime
} // namespace OHOS
#endif // OHOS_AGENT_RUNTIME_AGENT_UI_EXTENSION_H
