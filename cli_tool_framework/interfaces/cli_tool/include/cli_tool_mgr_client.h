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

#ifndef OHOS_ABILITY_RUNTIME_CLI_SA_CLIENT_H
#define OHOS_ABILITY_RUNTIME_CLI_SA_CLIENT_H

#include <mutex>

#include "cli_session_info.h"
#include "exec_options.h"
#include "icli_tool_manager.h"

namespace OHOS {
namespace CliTool {

/**
 * @class CliToolMGRClient
 * CliToolMGRClient provides client access to the CliSaService.
 * This is a singleton class that manages connection to the service.
 */
class CliToolMGRClient {
public:
    /**
     * @brief Get the singleton instance of CliToolMGRClient.
     * @return Reference to the CliToolMGRClient instance.
     */
    static CliToolMGRClient& GetInstance();

    /**
     * @brief Destructor.
     */
    ~CliToolMGRClient() = default;

    /**
     * @brief Get all tool summaries (lightweight for listing)
     * @param summaries Output vector of ToolSummary
     * @return ErrCode ERR_OK on success
     */
    ErrCode GetAllToolSummaries(std::vector<ToolSummary> &summaries);

    /**
     * @brief Get tool information by name
     * @param name Tool name
     * @param tool Output ToolInfo
     * @return ErrCode ERR_OK on success
     */
    ErrCode GetToolInfoByName(const std::string &name, ToolInfo &tool);

    /**
     * @brief Get all tool infos
     * @param tools Output vector of ToolInfo
     * @return ErrCode ERR_OK on success
     */
    ErrCode GetAllToolInfos(std::vector<ToolInfo> &tools);

    /**
     * @brief Register a CLI tool
     * @param tool ToolInfo to register
     * @return ErrCode ERR_OK on success
     */
    ErrCode RegisterTool(const ToolInfo &tool);

    /**
     * @brief Execute a CLI tool with key-value pairs (convenience method).
     * @param name The CLI tool name.
     * @param args The tool arguments as key-value pairs.
     * @param challenge Optional challenge string.
     * @param options Execution options.
     * @param session Output session information.
     * @return Returns ERR_OK on success, error code otherwise.
     */
    int32_t ExecTool(const std::string &name,
        const std::map<std::string, std::string> &args,
        const std::string &challenge,
        const ExecOptions &options,
        CliSessionInfo &session);

private:
    CliToolMGRClient() = default;
    DISALLOW_COPY_AND_MOVE(CliToolMGRClient);
    
    class CliSaDeathRecipient : public IRemoteObject::DeathRecipient {
        public:
        CliSaDeathRecipient() = default;
        ~CliSaDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
        private:
        DISALLOW_COPY_AND_MOVE(CliSaDeathRecipient);
    };

    sptr<ICliToolManager> GetCliToolManager();
    ErrCode Connect();
    /**
     * @brief Reset the proxy when service dies.
     * @param remote The remote object that died.
     */
    void ResetProxy(const wptr<IRemoteObject>& remote);

    std::recursive_mutex mutex_;
    sptr<ICliToolManager> proxy_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};

} // namespace CliTool
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_CLI_SA_CLIENT_H
