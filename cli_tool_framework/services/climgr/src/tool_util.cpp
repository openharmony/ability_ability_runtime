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

#include "tool_util.h"

#include <atomic>
#include <chrono>
#include <fcntl.h>
#include <nlohmann/json.hpp>
#include <unistd.h>
#include <vector>

#include "accesstoken_kit.h"
#include "bundle_mgr_helper.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace CliTool {

ToolUtil &ToolUtil::GetInstance()
{
    static ToolUtil instance;
    return instance;
}

bool ToolUtil::ValidateInputSchemaProperties(const std::string &inputSchema,
    const std::string &toolName, const std::string &subcommand,
    const std::map<std::string, std::string> &args)
{
    if (inputSchema.empty()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "inputSchema is empty");
        return false;
    }

    nlohmann::json schema = nlohmann::json::parse(inputSchema);
    if (!schema.contains("properties") || !schema["properties"].is_object()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "properties not found or invalid");
        return false;
    }

    auto properties = schema["properties"];

    if (!properties.contains(toolName)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "toolName not found in properties");
        return false;
    }

    if (!subcommand.empty() && !properties.contains(subcommand)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "subcommand not found in properties");
        return false;
    }

    for (auto &[key, vlue] : args) {
        if (!properties.contains(key)) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "args key not found in properties");
            return false;
        }
    }
    return true;
}

bool ToolUtil::CreatePipe(int pipeFd[2])
{
    if (pipe(pipeFd) != 0) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to create pipe: %{public}d", errno);
        return false;
    }

    // 设置读端为非阻塞
    int flags = fcntl(pipeFd[0], F_GETFL);
    if (flags == -1 || fcntl(pipeFd[0], F_SETFL, flags | O_NONBLOCK) == -1) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to set non-blocking: %{public}d", errno);
        close(pipeFd[0]);
        close(pipeFd[1]);
        return false;
    }

    return true;
}

void ToolUtil::ExecuteChildProcess(std::string &cmdLine, const std::string &sandboxConfig,
    const std::map<std::string, std::string> &args, int stdoutPipe[], int stderrPipe[])
{
    close(stdoutPipe[0]);
    close(stderrPipe[0]);

    // 重定向标准输出和标准错误
    dup2(stdoutPipe[1], STDOUT_FILENO);
    dup2(stderrPipe[1], STDERR_FILENO);

    close(stdoutPipe[1]);
    close(stderrPipe[1]);

    std::string clawSandbox = "/system/bin/claw_sandbox";
    std::string configPrompt = "--config";
    std::string cmdPrompt = "--cmd";
    std::vector<char*> execArgs;
    execArgs.push_back(const_cast<char *>(clawSandbox.c_str()));
    execArgs.push_back(const_cast<char *>(configPrompt.c_str()));
    execArgs.push_back(const_cast<char *>(sandboxConfig.c_str()));
    execArgs.push_back(const_cast<char *>(cmdPrompt.c_str()));
    for (const auto &[key, value] : args) {
        cmdLine += " " + key + " " + value;
    }

    execArgs.push_back(const_cast<char *>(cmdLine.c_str()));
    execArgs.push_back(nullptr);
    TAG_LOGI(AAFwkTag::CLI_TOOL, "Before execvp");
    execvp(execArgs[0], execArgs.data());
    _exit(EXIT_FAILURE);
}

std::string ToolUtil::GenerateCliSessionId(const std::string &name, int64_t startTime, int32_t counter) const
{
    return name + "_" + std::to_string(startTime) + "_" + std::to_string(counter);
}

void ToolUtil::ConstructSessionInfo(CliSessionInfo &session, const std::string &toolName, int32_t counter)
{
    session.startTime = std::chrono::system_clock::now().time_since_epoch().count();
    session.sessionId = GenerateCliSessionId(toolName, session.startTime, counter);
    session.toolName = toolName;
    session.status = "running";
    session.endTime = 0;
    session.result = std::make_shared<ExecResult>();
}

bool ToolUtil::GenerateSandboxConfig(const std::string &challenge, std::string &sandboxConfig) const
{
    AppExecFwk::BundleInfo bundleInfo;
    if (!ToolUtil::GetInstance().GetBundleInfoByTokenId(bundleInfo)) {
        return false;
    }

    nlohmann::json config;
    config["callerTokenId"] = IPCSkeleton::GetCallingFullTokenID();
    config["challenge"] = challenge;
    config["uid"] = IPCSkeleton::GetCallingUid();
    config["callerPid"] = IPCSkeleton::GetCallingPid();
    config["gid"] = bundleInfo.gid;
    config["appId"] = bundleInfo.appId;
    sandboxConfig = config.dump();
    return true;
}

bool ToolUtil::GetBundleInfoByTokenId(AppExecFwk::BundleInfo &bundleInfo) const
{
    OHOS::Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType != Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "caller is not hap");
        return false;
    }
    Security::AccessToken::HapTokenInfo hapInfo;
    auto ret = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapInfo);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "GetHapTokenInfo failed, ret:%{public}d", ret);
        return false;
    }

    auto bundleMgrHelper = DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance();
    if (bundleMgrHelper == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "bundlerMgrHelper is invalid");
        return false;
    }
    auto flag = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    if (bundleMgrHelper->GetCloneBundleInfo(hapInfo.bundleName, flag, hapInfo.instIndex, bundleInfo, hapInfo.userID) !=
        ERR_OK) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Fail to get bundle info");
        return false;
    }
    return true;
}

} // namespace CliTool
} // namespace OHOS
