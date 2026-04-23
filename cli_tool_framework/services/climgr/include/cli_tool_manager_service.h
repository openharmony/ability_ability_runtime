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

#ifndef OHOS_ABILITY_RUNTIME_CLI_TOOL_MGR_SERVICE_H
#define OHOS_ABILITY_RUNTIME_CLI_TOOL_MGR_SERVICE_H

#include <map>
#include <string>
#include <vector>

#include "cli_tool_manager_stub.h"
#include "cli_tool_data_manager.h"
#include "system_ability.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace CliTool {
class CliToolManagerService : public SystemAbility,
                        public CliToolManagerStub,
                        public std::enable_shared_from_this<CliToolManagerService> {
    DECLARE_SYSTEM_ABILITY(CliToolManagerService);

public:
    static sptr<CliToolManagerService> GetInstance();
    virtual ~CliToolManagerService() = default;

    /**
     * @brief Query all available tools
     */
    int32_t GetAllToolInfos(std::vector<ToolInfo> &tools) override;

    /**
     * @brief Query tool summaries (lightweight for listing)
     */
    int32_t GetAllToolSummaries(std::vector<ToolSummary> &summaries) override;

    /**
     * @brief Get tool information by name
     */
    int32_t GetToolInfoByName(const std::string &name, ToolInfo &tool) override;

    /**
     * @brief Register a CLI tool
     */
    int32_t RegisterTool(const ToolInfo &tool) override;

    /**
     * @brief Execute a CLI tool.
     * Implements the ICliToolManager interface method.
     */
    int32_t ExecTool(const ExecToolParam &param, const std::map<std::string, std::string> &args,
        CliSessionInfo &session) override;

protected:
    void OnStart() override;
    void OnStop() override;

private:
    CliToolManagerService() : SystemAbility(CLI_TOOL_MGR_SERVICE_ID, false) {};
    DISALLOW_COPY_AND_MOVE(CliToolManagerService);
    static sptr<CliToolManagerService> instance_;
    std::atomic<int32_t> activeSessionCount_ = 0;
};

} // namespace CliTool
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_CLI_TOOL_MGR_SERVICE_H
