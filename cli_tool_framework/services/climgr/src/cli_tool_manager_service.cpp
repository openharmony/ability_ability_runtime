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

#include <sys/wait.h>

#include "accesstoken_kit.h"
#include "ccm_util.h"
#include "cli_error_code.h"
#include "hilog_tag_wrapper.h"
#include "iexec_tool_callback.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "permission_util.h"
#include "process_manager.h"
#include "session_record.h"
#include "tokenid_kit.h"
#include "tool_util.h"

namespace OHOS {
namespace CliTool {
namespace {
constexpr const char* PERMISSION_EXEC_CLI_TOOL = "ohos.permission.EXEC_CLI_TOOL";
constexpr const char* PERMISSION_QUERY_CLI_TOOL = "ohos.permission.QUERY_CLI_TOOL";

constexpr int32_t COEFFICIENT = 1000;
} // namespace

std::mutex g_mutex;
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

    int32_t ret = CliToolDataManager::GetInstance().EnsureToolsLoaded();
    if (ret != 0) {
        TAG_LOGW(AAFwkTag::CLI_TOOL, "Failed to load: %{public}d", ret);
    } else {
        TAG_LOGI(AAFwkTag::CLI_TOOL, "Successfully loaded");
    }

    if (!Publish(cliService)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Publish failed");
        return;
    }
}

void CliToolManagerService::OnStop()
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "climgr stop");
}

int32_t CliToolManagerService::GetAllToolInfos(std::vector<ToolInfo> &tools)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "GetAllToolInfos called");

    auto fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    if (!AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "GetAllToolInfos: Not system app");
        return ERR_NOT_SYSTEM_APP;
    }

    auto tokenId = IPCSkeleton::GetCallingTokenID();
    if (!PermissionUtil::VerifyAccessToken(tokenId, PERMISSION_QUERY_CLI_TOOL)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "GetAllToolInfos: Permission denied");
        return ERR_PERMISSION_DENIED;
    }

    return CliToolDataManager::GetInstance().GetAllTools(tools);
}

int32_t CliToolManagerService::GetAllToolSummaries(std::vector<ToolSummary> &summaries)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "GetAllToolSummaries called");

    auto fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    if (!AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "GetAllToolSummaries: Not system app");
        return ERR_NOT_SYSTEM_APP;
    }

    auto tokenId = IPCSkeleton::GetCallingTokenID();
    if (!PermissionUtil::VerifyAccessToken(tokenId, PERMISSION_QUERY_CLI_TOOL)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "GetAllToolSummaries: Permission denied");
        return ERR_PERMISSION_DENIED;
    }

    return CliToolDataManager::GetInstance().QueryToolSummaries(summaries);
}

int32_t CliToolManagerService::GetToolInfoByName(const std::string &name, ToolInfo &tool)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "GetToolInfoByName called, name='%{public}s'", name.c_str());

    auto fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    if (!AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "GetToolInfoByName: Not system app");
        return ERR_NOT_SYSTEM_APP;
    }

    auto tokenId = IPCSkeleton::GetCallingTokenID();
    if (!PermissionUtil::VerifyAccessToken(tokenId, PERMISSION_QUERY_CLI_TOOL)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "GetToolInfoByName: Permission denied");
        return ERR_PERMISSION_DENIED;
    }

    return CliToolDataManager::GetInstance().GetToolByName(name, tool);
}

int32_t CliToolManagerService::RegisterTool(const ToolInfo &tool)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "RegisterTool called, tool name='%{public}s'", tool.name.c_str());
    return CliToolDataManager::GetInstance().RegisterTool(tool);
}

int32_t CliToolManagerService::ExecTool(const ExecToolParam &param, const sptr<IRemoteObject> &objectCallback)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "ExecTool called: toolName=%{public}s, subcommand=%{public}s",
        param.toolName.c_str(), param.subcommand.c_str());

    auto fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    if (!AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Not system app");
        return ERR_NOT_SYSTEM_APP;
    }

    auto tokenId = IPCSkeleton::GetCallingTokenID();
    if (!PermissionUtil::VerifyAccessToken(tokenId, PERMISSION_EXEC_CLI_TOOL)) {
        return ERR_PERMISSION_DENIED;
    }

    if (objectCallback == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "objectCallback is null");
        return ERR_INNER_PARAM_INVALID;
    }

    auto cliQuantity = CcmUtil::GetInstance().GetCliConcurrencyLimit();
    if (activeSessionCount_.load() >= cliQuantity) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Session limit exceeded: %{public}d", cliQuantity);
        return ERR_SESSION_LIMIT_EXCEEDED;
    }

    ToolInfo toolInfo;
    if (GetToolInfoByName(param.toolName, toolInfo) != ERR_OK) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Tool not found");
        return ERR_TOOL_NOT_EXIST;
    }

    auto checkPramRet = ToolUtil::ValidateProperties(toolInfo, const_cast<ExecToolParam &>(param), tokenId);
    if (checkPramRet != ERR_OK) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Input schema validation failed");
        return checkPramRet;
    }
    
    std::string sandboxConfig;
    if (!ToolUtil::GenerateSandboxConfig(param.challenge, tokenId, sandboxConfig)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "caller is not hap");
        return ERR_NOT_HAP;
    }

    pid_t childPid = -1;
    auto createRet =
        ProcessManager::GetInstance().CreateChildProcess(param, sandboxConfig, toolInfo.executablePath, childPid);
    if (createRet != ERR_OK) {
        return createRet;
    }
    activeSessionCount_.fetch_add(1, std::memory_order_relaxed);

    struct sigaction sa = {};
    sa.sa_handler = CliToolManagerService::sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, nullptr);

    auto session = std::make_shared<CliSessionInfo>();
    auto sessionRecord = std::make_shared<SessionRecord>(session, childPid, objectCallback);
    {
        std::lock_guard<ffrt::mutex> guard(callbackMutex_);
        session->sessionId = ToolUtil::GenerateCliSessionId(param.toolName, sessionRecord);
        session->toolName = param.toolName;
        session->status = "running";
        sessionCallbacks_[session->sessionId] = sessionRecord;
    }

    TAG_LOGI(AAFwkTag::CLI_TOOL, "Tool executed successfully: sessionId=%{public}s", session->sessionId.c_str());
    if (param.options.background) {
        auto cbProxy = sptr<IExecToolCallback>(iface_cast<IExecToolCallback>(objectCallback));
        if (cbProxy != nullptr) {
            cbProxy->SendResult(*session);
        }
        return ERR_OK;
    }
    if (param.options.yieldMs != 0) {
        PostExecToolTask(param.options.yieldMs, session->sessionId, false);
    }
    if (param.options.timeout != 0) {
        PostExecToolTask(param.options.timeout * COEFFICIENT, session->sessionId, true);
    }

    return ERR_OK;
}

void CliToolManagerService::PostExecToolTask(int32_t time, const std::string &sessionId, bool isTimeout)
{
    auto timeoutTask = [wThis = weak_from_this(), sessionId, isTimeout]() {
        auto pThis = wThis.lock();
        if (pThis != nullptr) {
            pThis->TimeIsUp(sessionId, isTimeout);
        }
    };
    ffrt::submit(std::move(timeoutTask), ffrt::task_attr().delay(time * COEFFICIENT));
}

void CliToolManagerService::TimeIsUp(const std::string &sessionId, bool isTimeout)
{
    std::lock_guard<ffrt::mutex> guard(callbackMutex_);
    auto search = sessionCallbacks_.find(sessionId);
    if (search == sessionCallbacks_.end()) {
        TAG_LOGI(AAFwkTag::CLI_TOOL, "sessionId=%{public}s not exist", sessionId.c_str());
        return;
    }

    auto sessionRecord = search->second;
    if (sessionRecord == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "sessionRecord is nullptr");
        // need erase
        sessionCallbacks_.erase(search);
        return;
    }

    if (isTimeout) {
        auto sessionInfo = sessionRecord->GetCliSessionInfo();
        if (sessionInfo != nullptr) {
            sessionInfo->status = "failed";
            auto result = std::make_shared<ExecResult>();
            result->timedOut = true;
            auto timestamp = std::chrono::system_clock::now().time_since_epoch();
            auto endTime = std::chrono::duration_cast<std::chrono::milliseconds>(timestamp).count();
            result->executionTime = endTime - sessionRecord->GetStartTime();
            sessionInfo->result = result;
        }
    }

    auto cbProxy = sptr<IExecToolCallback>(iface_cast<IExecToolCallback>(sessionRecord->GetCallback()));
    if (cbProxy != nullptr) {
        cbProxy->SendResult(*(sessionRecord->GetCliSessionInfo()));
    }
}

void CliToolManagerService::WaitPid(pid_t pid, int32_t status)
{
    std::lock_guard<ffrt::mutex> guard(callbackMutex_);
    for (auto iter = sessionCallbacks_.begin(); iter != sessionCallbacks_.end(); ++iter) {
        if (iter->second == nullptr || pid != iter->second->GetPid()) {
            continue;
        }
        auto sessionInfo = iter->second->GetCliSessionInfo();
        if (sessionInfo == nullptr) {
            continue;
        }
        if (status == 0) {
            sessionInfo->status = "completed";
        } else {
            sessionInfo->status = "failed";
        }
        auto result = std::make_shared<ExecResult>();
        auto timestamp = std::chrono::system_clock::now().time_since_epoch();
        auto endTime = std::chrono::duration_cast<std::chrono::milliseconds>(timestamp).count();
        result->executionTime = endTime - iter->second->GetStartTime();
        result->exitCode = status;
        sessionInfo->result = result;
        auto cbProxy = sptr<IExecToolCallback>(iface_cast<IExecToolCallback>(iter->second->GetCallback()));
        if (cbProxy != nullptr) {
            cbProxy->SendResult(*(iter->second->GetCliSessionInfo()));
        }
        sessionCallbacks_.erase(iter);
        break;
    }
}

void CliToolManagerService::sigchld_handler(int sig)
{
    int32_t status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        auto instance = CliToolManagerService::GetInstance();
        if (instance != nullptr) {
            instance->WaitPid(pid, status);
        }
        pid_t gPid = getpgid(pid);
        TAG_LOGI(AAFwkTag::CLI_TOOL, "gPid=%{public}d", gPid);
        if (gPid == -1) {
            TAG_LOGI(AAFwkTag::CLI_TOOL, "Fial to get gPid");
            return;
        }
        int32_t killRet = killpg(gPid, SIGTERM);
        TAG_LOGI(AAFwkTag::CLI_TOOL, "killpg result:%{public}d", killRet);
    }
}
} // namespace CliTool
} // namespace OHOS
