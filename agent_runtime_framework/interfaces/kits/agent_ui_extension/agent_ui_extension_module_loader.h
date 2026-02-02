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

#ifndef OHOS_AGENT_RUNTIME_AGENT_UI_EXTENSION_MODULE_LOADER_H
#define OHOS_AGENT_RUNTIME_AGENT_UI_EXTENSION_MODULE_LOADER_H

#include <map>
#include <memory>
#include <string>

#include "extension_module_loader.h"

namespace OHOS {
namespace AbilityRuntime {
class Runtime;
} // namespace AbilityRuntime

namespace AgentRuntime {
/**
 * @brief Module loader for Agent UI Extension.
 *
 * This class is responsible for loading Agent UI Extension modules and
 * providing the necessary parameters for extension registration.
 */
class AgentUIExtensionModuleLoader : public AbilityRuntime::ExtensionModuleLoader {
public:
    AgentUIExtensionModuleLoader();
    virtual ~AgentUIExtensionModuleLoader();

    /**
     * @brief Create an Extension instance based on the runtime.
     *
     * @param runtime The runtime instance used to create the extension.
     * @return Returns a pointer to the created Extension instance.
     */
    AbilityRuntime::Extension *Create(
        const std::unique_ptr<AbilityRuntime::Runtime> &runtime) const override;

    /**
     * @brief Get the parameters for the Agent UI Extension module.
     *
     * @return Returns a map containing the module parameters including type and name.
     */
    std::map<std::string, std::string> GetParams() override;
};

} // namespace AgentRuntime
} // namespace OHOS
#endif // OHOS_AGENT_RUNTIME_AGENT_UI_EXTENSION_MODULE_LOADER_H
