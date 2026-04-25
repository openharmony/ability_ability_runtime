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

#include "process_manager.h"

#include <unistd.h>

#include "cli_error_code.h"
#include "exec_tool_param.h"
#include "hilog_tag_wrapper.h"
#include "tool_util.h"

namespace OHOS {
namespace CliTool {

ProcessManager &ProcessManager::GetInstance()
{
    static ProcessManager instance;
    return instance;
}

int32_t ProcessManager::CreateChildProcess(const ExecToolParam &param, const std::string &sandboxConfig,
    pid_t &childPid) const
{
    pid_t pid = fork();
    if (pid < 0) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to fork: %{public}d", errno);
        return ERR_NO_INIT;
    }

    if (pid == 0) {
        std::string clawSandbox = "/system/bin/claw_sandbox";
        std::string configPrompt = "--config";
        std::string cmdPrompt = "--cmd";
        std::vector<char*> execArgs;
        execArgs.push_back(const_cast<char *>(clawSandbox.c_str()));
        execArgs.push_back(const_cast<char *>(configPrompt.c_str()));
        execArgs.push_back(const_cast<char *>(sandboxConfig.c_str()));
        execArgs.push_back(const_cast<char *>(cmdPrompt.c_str()));
        std::string cmdLine = param.toolName;
        if (!param.subcommand.empty()) {
            cmdLine += " " + param.subcommand;
        }
        ToolUtil::TransferToCmdParam(param.args, cmdLine);
        execArgs.push_back(const_cast<char *>(cmdLine.c_str()));
        execArgs.push_back(nullptr);
        TAG_LOGI(AAFwkTag::CLI_TOOL, "Before execvp");
        execvp(execArgs[0], execArgs.data());
        _exit(0);
    }
    childPid = pid;
    return ERR_OK;
}

} // namespace CliTool
} // namespace OHOS
