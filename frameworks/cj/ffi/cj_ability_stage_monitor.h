/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_CJ_ABILITY_STAGE_MONITOR_H
#define OHOS_ABILITY_RUNTIME_CJ_ABILITY_STAGE_MONITOR_H

#include <cstdint>

#include "cj_iability_stage_monitor.h"

namespace OHOS {
namespace AbilityDelegatorCJ {
using namespace OHOS::AppExecFwk;
class CJAbilityStageMonitor : public CJIAbilityStageMonitor {
public:
    /**
     * A constructor used to create a CJAbilityStageMonitor instance with the input
     * parameter passed.
     *
     * @param moduleName Indicates the specified module name.
     * @param srcEntrance Indicates the abilityStage source path.
     */
    CJAbilityStageMonitor(const std::string& moduleName, const std::string& srcEntrance, const int64_t stageMonitorId)
        : CJIAbilityStageMonitor(moduleName, srcEntrance), stageMonitorId_(stageMonitorId)
    {}

    /**
     * Default deconstructor used to deconstruct.
     */
    ~CJAbilityStageMonitor() = default;

    int64_t GetId()
    {
        return stageMonitorId_;
    }

private:
    int64_t stageMonitorId_;
};
} // namespace AbilityDelegatorCJ
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_CJ_ABILITY_STAGE_MONITOR_H