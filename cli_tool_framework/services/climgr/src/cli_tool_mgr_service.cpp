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

#include "cli_tool_mgr_service.h"

#include "hilog_tag_wrapper.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace CliTool {
std::mutex g_mutex;
sptr<CliSaMGRService> CliSaMGRService::instance_ = nullptr;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(CliSaMGRService::GetInstance().GetRefPtr());

sptr<CliSaMGRService> CliSaMGRService::GetInstance()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (instance_ != nullptr) {
        return instance_;
    }
    instance_ = new (std::nothrow) CliSaMGRService();
    return instance_;
}

void CliSaMGRService::OnStart()
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "climgr start");
    // Publish the service
    if (!Publish(CliSaMGRService::GetInstance())) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Publish failed");
        return;
    }
}

void CliSaMGRService::OnStop()
{
}
} // namespace CliTool
} // namespace OHOS
