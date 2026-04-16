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

#ifndef OHOS_ABILITY_RUNTIME_CLI_TOOL_MGR_SERVICE_H
#define OHOS_ABILITY_RUNTIME_CLI_TOOL_MGR_SERVICE_H

#include "cli_tool_mgr_stub.h"
#include "system_ability.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace CliTool {
class CliSaMGRService : public SystemAbility,
                        public CliToolMGRStub,
                        public std::enable_shared_from_this<CliSaMGRService> {
    DECLARE_SYSTEM_ABILITY(CliSaMGRService);

public:
    static sptr<CliSaMGRService> GetInstance();
    virtual ~CliSaMGRService() = default;

protected:
    void OnStart() override;
    void OnStop() override;

private:
    CliSaMGRService() : SystemAbility(CLI_TOOL_MGR_SERVICE_ID, true) {};
    DISALLOW_COPY_AND_MOVE(CliSaMGRService);
    static sptr<CliSaMGRService> instance_;
};

} // namespace CliTool
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_CLI_TOOL_MGR_SERVICE_H
