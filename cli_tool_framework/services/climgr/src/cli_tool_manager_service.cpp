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

#include "cli_tool_manager_service.h"

#include <atomic>
#include <sys/wait.h>
#include <unistd.h>

#include "hilog_tag_wrapper.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "tool_util.h"

namespace OHOS {
namespace CliTool {
namespace {
constexpr int32_t ERR_OK = 0;
constexpr int32_t ERR_NO_INIT = -1;
constexpr int32_t ERR_INVALID_PARAM = -2;
constexpr int32_t ERR_SESSION_LIMIT_EXCEEDED = -100;
constexpr int32_t MAX_CONCURRENT_SESSIONS = 10;
} // namespace

std::mutex g_mutex;
static std::atomic<int32_t> g_activeSessionCount{0};
sptr<CliToolManagerService> CliToolManagerService::instance_ = nullptr;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(CliToolManagerService::GetInstance().GetRefPtr());

sptr<CliToolManagerService> CliToolManagerService::GetInstance()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (instance_ != nullptr) {
        return instance_;
    }
    instance_ = new (std::nothrow) CliToolManagerService();
    return instance_;
}

void CliToolManagerService::OnStart()
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "climgr start");
    // Publish the service
    auto cliService = CliToolManagerService::GetInstance();
    if (cliService == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "cli service is nullptr");
        return;
    }
    if (!Publish(cliService)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Publish failed");
        return;
    }

    int32_t ret = CliToolDataManager::GetInstance().EnsureToolsLoaded();
    if (ret != 0) {
        TAG_LOGW(AAFwkTag::CLI_TOOL, "Failed to load: %{public}d", ret);
    } else {
        TAG_LOGI(AAFwkTag::CLI_TOOL, "Successfully loaded");
    }
}

void CliToolManagerService::OnStop()
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "climgr stop");
}

int32_t CliToolManagerService::GetAllToolInfos(std::vector<ToolInfo> &tools)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "GetAllToolInfos called");
    return CliToolDataManager::GetInstance().GetAllTools(tools);
}

int32_t CliToolManagerService::GetAllToolSummaries(std::vector<ToolSummary> &summaries)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "GetAllToolSummaries called");
    return CliToolDataManager::GetInstance().QueryToolSummaries(summaries);
}

int32_t CliToolManagerService::GetToolInfoByName(const std::string &name, ToolInfo &tool)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "GetToolInfoByName called, name='%{public}s'", name.c_str());
    return CliToolDataManager::GetInstance().GetToolByName(name, tool);
}

int32_t CliToolManagerService::RegisterTool(const ToolInfo &tool)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "RegisterTool called, tool name='%{public}s'", tool.name.c_str());
    return CliToolDataManager::GetInstance().RegisterTool(tool);
}

int32_t CliToolManagerService::ExecTool(const ExecToolParam &param, const std::map<std::string, std::string> &args,
    CliSessionInfo &session)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "ExecTool called: toolName=%{public}s, subcommand=%{public}s",
        param.toolName.c_str(), param.subcommand.c_str());
    if (g_activeSessionCount.load() >= MAX_CONCURRENT_SESSIONS) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Session limit exceeded: %{public}d/%{public}d",
            g_activeSessionCount.load(), MAX_CONCURRENT_SESSIONS);
        return ERR_SESSION_LIMIT_EXCEEDED;
    }

    ToolInfo toolInfo;
    if (GetToolInfoByName(param.toolName, toolInfo) != ERR_OK) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Tool not found");
        return ERR_INVALID_PARAM;
    }

    auto &toolUtil = ToolUtil::GetInstance();
    if (!toolUtil.ValidateInputSchemaProperties(toolInfo.inputSchema, param.toolName, param.subcommand, args)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Input schema validation failed");
        return ERR_INVALID_PARAM;
    }

    int32_t counter = g_activeSessionCount.fetch_add(1, std::memory_order_relaxed) + 1;
    toolUtil.ConstructSessionInfo(session, param.toolName, counter);

    std::string sandboxConfig;
    if (!toolUtil.GenerateSandboxConfig(param.challenge, sandboxConfig)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "caller is not hap");
        return ERR_INVALID_PARAM;
    }

    int stdoutPipe[2] = {-1, -1};
    int stderrPipe[2] = {-1, -1};

    if (!toolUtil.CreatePipe(stdoutPipe)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to create stdout pipe");
        return ERR_NO_INIT;
    }

    if (!toolUtil.CreatePipe(stderrPipe)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to create stderr pipe");
        close(stdoutPipe[0]);
        close(stdoutPipe[1]);
        return ERR_NO_INIT;
    }

    pid_t pid = fork();
    if (pid < 0) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to fork: %{public}d", errno);
        close(stdoutPipe[0]);
        close(stdoutPipe[1]);
        close(stderrPipe[0]);
        close(stderrPipe[1]);
        return ERR_NO_INIT;
    }

    if (pid == 0) {
        std::string cmdLine = param.toolName;
        if (!param.subcommand.empty()) {
            cmdLine += " " + param.subcommand;
        }
        toolUtil.ExecuteChildProcess(cmdLine, sandboxConfig, args, stdoutPipe, stderrPipe);
        _exit(EXIT_FAILURE);
    }

    close(stdoutPipe[1]);
    close(stderrPipe[1]);
    TAG_LOGI(AAFwkTag::CLI_TOOL, "Tool executed successfully: pid=%{public}d, sessionId=%{public}s",
        pid, session.sessionId.c_str());
    return ERR_OK;
}
} // namespace CliTool
} // namespace OHOS
