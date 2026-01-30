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

#ifndef OHOS_AGENT_RUNTIME_AGENT_EXTENSION_MODULE_LOADER_H
#define OHOS_AGENT_RUNTIME_AGENT_EXTENSION_MODULE_LOADER_H

#include "extension_module_loader.h"


namespace OHOS {

namespace AbilityRuntime {
    class ExtensionModuleLoader;
    class Extension;
    class Runtime;
}

namespace AgentRuntime {
using namespace AbilityRuntime;
class AgentExtensionModuleLoader
    : public AbilityRuntime::ExtensionModuleLoader, public Singleton<AgentExtensionModuleLoader> {
    DECLARE_SINGLETON(AgentExtensionModuleLoader);

public:
    /**
     * @brief Create Extension.
     *
     * @param runtime The runtime.
     * @return The Extension instance.
     */
    virtual AbilityRuntime::Extension *Create(const std::unique_ptr<Runtime>& runtime) const override;

    virtual std::map<std::string, std::string> GetParams() override;
};

} // AgentRuntime
} // OHOS
#endif // OHOS_AGENT_RUNTIME_AGENT_EXTENSION_MODULE_LOADER_H
