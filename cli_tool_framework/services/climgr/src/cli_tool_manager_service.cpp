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

#include "hilog_tag_wrapper.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace CliTool {
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
    if (!Publish(cliService)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Publish failed");
        return;
    }

    int32_t ret = CliToolDataManager::GetInstance().EnsureToolsLoaded();
    if (ret != 0) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "Failed to load: %{public}d", ret);
    } else {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "Successfully loaded");
    }
}

void CliToolManagerService::OnStop()
{
}

int32_t CliToolManagerService::QueryTools(std::vector<ToolInfo> &tools)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "QueryTools called");
    return CliToolDataManager::GetInstance().GetAllTools(tools);
}

int32_t CliToolManagerService::QueryToolSummaries(std::vector<ToolSummary> &summaries)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "QueryToolSummaries called");
    return CliToolDataManager::GetInstance().QueryToolSummaries(summaries);
}

int32_t CliToolManagerService::GetToolInfoByName(const std::string &name, ToolInfo &tool)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "GetToolInfoByName called, name='%{public}s'", name.c_str());
    return CliToolDataManager::GetInstance().GetToolByName(name, tool);
}

int32_t CliToolManagerService::RegisterCliTool(const ToolInfo &tool)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "RegisterCliTool called, tool name='%{public}s'", tool.name.c_str());
    return CliToolDataManager::GetInstance().RegisterTool(tool);
}
} // namespace CliTool
} // namespace OHOS
