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

#include <condition_variable>
#include <functional>
#include <mutex>

#include "cli_session_info.h"
#include "exec_options.h"
#include "icli_tool_manager.h"

namespace OHOS {
namespace CliTool {

using ClearProxyCallback = std::function<void(const wptr<IRemoteObject>&)>;

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
     * @param param The CLI tool param.
     * @param callback The callback RemoteObject.
     * @return Returns ERR_OK on success, error code otherwise.
     */
    int32_t ExecTool(const ExecToolParam &param, sptr<IRemoteObject> callback);

    /**
     * @brief On load system ability success.
     * @param remoteObject The remote object of system ability.
     */
    void OnLoadSystemAbilitySuccess(const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief On load system ability fail.
     */
    void OnLoadSystemAbilityFail();

private:
    CliToolMGRClient() = default;
    DISALLOW_COPY_AND_MOVE(CliToolMGRClient);

    class CliMgrDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit CliMgrDeathRecipient(const ClearProxyCallback &callback) : callback_(callback) {}
        ~CliMgrDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

    private:
        ClearProxyCallback callback_;
    };

    sptr<ICliToolManager> GetCliToolMgrProxy();
    bool LoadCliToolMgrService();
    void ClearProxy();
    void SetCliToolMgr(const sptr<IRemoteObject> &remoteObject);
    sptr<ICliToolManager> GetCliToolMgr();

    std::condition_variable loadSaCondation_;
    std::mutex loadSaMutex_;
    bool loadSaFinished_;
    std::mutex proxyMutex_;
    sptr<ICliToolManager> cliToolMgr_ = nullptr;
};

} // namespace CliTool
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_CLI_SA_CLIENT_H
