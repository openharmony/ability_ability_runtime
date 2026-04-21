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

#include "ability_manager_errors.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace CliTool {
namespace {
constexpr int32_t CLI_TOOL_MGR_SERVICE_ID = 186;
}

CliToolMGRClient& CliToolMGRClient::GetInstance()
{
    static CliToolMGRClient instance;
    return instance;
}

sptr<ICliToolManager> CliToolMGRClient::GetCliToolManager()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!proxy_) {
        (void)Connect();
    }

    return proxy_;
}

ErrCode CliToolMGRClient::Connect()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return ERR_OK;
    }
    sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemManager == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "get registry failed");
        return AAFwk::GET_CLI_TOOL_MGR_SERVICE_FAILED;
    }
    sptr<IRemoteObject> remoteObj = systemManager->GetSystemAbility(CLI_TOOL_MGR_SERVICE_ID);
    if (remoteObj == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "connect failed");
        return AAFwk::GET_CLI_TOOL_MGR_SERVICE_FAILED;
    }

    deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new CliSaDeathRecipient());
    if (deathRecipient_ == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "create CliSaDeathRecipient failed");
        return AAFwk::GET_CLI_TOOL_MGR_SERVICE_FAILED;
    }
    if ((remoteObj->IsProxyObject()) && (!remoteObj->AddDeathRecipient(deathRecipient_))) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "add deathRecipient failed");
        return AAFwk::GET_CLI_TOOL_MGR_SERVICE_FAILED;
    }

    proxy_ = iface_cast<ICliToolManager>(remoteObj);
    if (proxy_ == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "iface_cast failed");
        return AAFwk::GET_CLI_TOOL_MGR_SERVICE_FAILED;
    }
    TAG_LOGD(AAFwkTag::CLI_TOOL, "Connect cli manager service success.");
    return ERR_OK;
}

void CliToolMGRClient::CliSaDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    TAG_LOGD(AAFwkTag::CLI_TOOL, "CliSaDeathRecipient handle remote died.");
    CliToolMGRClient::GetInstance().ResetProxy(remote);
}

void CliToolMGRClient::ResetProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!proxy_) {
        return;
    }

    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        TAG_LOGD(AAFwkTag::CLI_TOOL, "To remove death recipient.");
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

ErrCode CliToolMGRClient::GetAllToolSummaries(std::vector<ToolSummary> &summaries)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto proxy = GetCliToolManager();
    if (proxy == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "proxy is null");
        return AAFwk::GET_CLI_TOOL_MGR_SERVICE_FAILED;
    }
    return proxy->GetAllToolSummaries(summaries);
}

ErrCode CliToolMGRClient::GetToolInfoByName(const std::string &name, ToolInfo &tool)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto proxy = GetCliToolManager();
    if (proxy == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "proxy is null");
        return AAFwk::GET_CLI_TOOL_MGR_SERVICE_FAILED;
    }
    return proxy->GetToolInfoByName(name, tool);
}

ErrCode CliToolMGRClient::GetAllToolInfos(std::vector<ToolInfo> &tools)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto proxy = GetCliToolManager();
    if (proxy == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "proxy is null");
        return AAFwk::GET_CLI_TOOL_MGR_SERVICE_FAILED;
    }
    return proxy->GetAllToolInfos(tools);
}

ErrCode CliToolMGRClient::RegisterTool(const ToolInfo &tool)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto proxy = GetCliToolManager();
    if (proxy == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "proxy is null");
        return AAFwk::GET_CLI_TOOL_MGR_SERVICE_FAILED;
    }
    return proxy->RegisterTool(tool);
}
} // namespace CliTool
} // namespace OHOS
