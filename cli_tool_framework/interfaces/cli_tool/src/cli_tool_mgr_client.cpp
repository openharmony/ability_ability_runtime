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

#include "cli_tool_mgr_client.h"

#include "cli_error_code.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "cli_mgr_load_callback.h"

namespace OHOS {
namespace CliTool {
CliToolMGRClient& CliToolMGRClient::GetInstance()
{
    static CliToolMGRClient instance;
    return instance;
}

int32_t CliToolMGRClient::ExecTool(const ExecToolParam &param, const std::map<std::string, std::string> &args,
    CliSessionInfo &session)
{
    auto proxy = GetCliToolMgrProxy();
    if (proxy == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "connect failed");
        return GET_CLI_TOOL_MGR_SERVICE_FAILED;
    }
    return proxy->ExecTool(param, args, session);
}

ErrCode CliToolMGRClient::GetAllToolSummaries(std::vector<ToolSummary> &summaries)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto proxy = GetCliToolMgrProxy();
    if (proxy == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "proxy is null");
        return GET_CLI_TOOL_MGR_SERVICE_FAILED;
    }
    return proxy->GetAllToolSummaries(summaries);
}

ErrCode CliToolMGRClient::GetToolInfoByName(const std::string &name, ToolInfo &tool)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto proxy = GetCliToolMgrProxy();
    if (proxy == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "proxy is null");
        return GET_CLI_TOOL_MGR_SERVICE_FAILED;
    }
    return proxy->GetToolInfoByName(name, tool);
}

ErrCode CliToolMGRClient::GetAllToolInfos(std::vector<ToolInfo> &tools)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto proxy = GetCliToolMgrProxy();
    if (proxy == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "proxy is null");
        return GET_CLI_TOOL_MGR_SERVICE_FAILED;
    }
    return proxy->GetAllToolInfos(tools);
}

ErrCode CliToolMGRClient::RegisterTool(const ToolInfo &tool)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto proxy = GetCliToolMgrProxy();
    if (proxy == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "proxy is null");
        return GET_CLI_TOOL_MGR_SERVICE_FAILED;
    }
    return proxy->RegisterTool(tool);
}

void CliToolMGRClient::OnLoadSystemAbilitySuccess(const sptr<IRemoteObject> &remoteObject)
{
    SetCliToolMgr(remoteObject);
    std::unique_lock<std::mutex> lock(loadSaMutex_);
    loadSaFinished_ = true;
    loadSaCondation_.notify_one();
}

void CliToolMGRClient::OnLoadSystemAbilityFail()
{
    SetCliToolMgr(nullptr);
    std::unique_lock<std::mutex> lock(loadSaMutex_);
    loadSaFinished_ = true;
    loadSaCondation_.notify_one();
}

sptr<ICliToolManager> CliToolMGRClient::GetCliToolMgrProxy()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::CLI_TOOL, "called");
    auto cliToolMgr = GetCliToolMgr();
    if (cliToolMgr != nullptr) {
        TAG_LOGD(AAFwkTag::CLI_TOOL, "Cli tool manager has been started");
        return cliToolMgr;
    }

    if (!LoadCliToolMgrService()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Load cli tool manager service failed");
        return nullptr;
    }

    cliToolMgr = GetCliToolMgr();
    if (cliToolMgr == nullptr || cliToolMgr->AsObject() == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to get cli tool manager");
        return nullptr;
    }

    const auto &onClearProxyCallback = [](const wptr<IRemoteObject> &remote) {
        auto &instance = GetInstance();
        if (instance.cliToolMgr_ == remote) {
            instance.ClearProxy();
        }
    };

    sptr<CliMgrDeathRecipient> recipient(new (std::nothrow) CliMgrDeathRecipient(onClearProxyCallback));
    cliToolMgr->AsObject()->AddDeathRecipient(recipient);

    return cliToolMgr;
}

bool CliToolMGRClient::LoadCliToolMgrService()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    const int32_t LOAD_SA_TIMEOUT_MS = 4 * 1000;
    {
        std::unique_lock<std::mutex> lock(loadSaMutex_);
        loadSaFinished_ = false;
    }

    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, "GetSystemAbilityManager");
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to get SystemAbilityManager");
        return false;
    }

    sptr<CliMgrLoadCallback> loadCallback = new (std::nothrow) CliMgrLoadCallback();
    if (loadCallback == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Create load callback failed");
        return false;
    }

    auto ret = systemAbilityMgr->LoadSystemAbility(CLI_TOOL_MGR_SERVICE_ID, loadCallback);
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Load system ability %{public}d failed with %{public}d", CLI_TOOL_MGR_SERVICE_ID,
            ret);
        return false;
    }

    {
        std::unique_lock<std::mutex> lock(loadSaMutex_);
        auto waitStatus = loadSaCondation_.wait_for(lock, std::chrono::milliseconds(LOAD_SA_TIMEOUT_MS),
            [this]() {
                return loadSaFinished_;
            });
        if (!waitStatus) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Wait for load sa timeout");
            return false;
        }
    }

    return true;
}

void CliToolMGRClient::SetCliToolMgr(const sptr<IRemoteObject> &remoteObject)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    cliToolMgr_ = iface_cast<ICliToolManager>(remoteObject);
}

sptr<ICliToolManager> CliToolMGRClient::GetCliToolMgr()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    return cliToolMgr_;
}

void CliToolMGRClient::ClearProxy()
{
    TAG_LOGD(AAFwkTag::CLI_TOOL, "called");
    std::lock_guard<std::mutex> lock(proxyMutex_);
    cliToolMgr_ = nullptr;
}

void CliToolMGRClient::CliMgrDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (callback_ != nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "cli tool manager service died");
        callback_(remote);
    }
}

} // namespace CliTool
} // namespace OHOS
