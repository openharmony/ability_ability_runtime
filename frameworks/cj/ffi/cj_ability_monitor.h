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

#ifndef OHOS_ABILITY_RUNTIME_CJ_ABILITY_MONITOR_H
#define OHOS_ABILITY_RUNTIME_CJ_ABILITY_MONITOR_H

#include "cj_ability_monitor_object.h"
#include "cj_iability_monitor.h"

namespace OHOS {
namespace AbilityDelegatorCJ {
using namespace OHOS::AppExecFwk;
class CJAbilityMonitor : public CJIAbilityMonitor {
public:
    /**
     * A constructor used to create a CJAbilityMonitor instance with the input
     * parameter passed.
     *
     * @param name Indicates the specified ability name.
     * @param cjAbilityMonitor Indicates the CJMonitorObject object.
     */
    CJAbilityMonitor(const std::string& name, const std::shared_ptr<CJMonitorObject>& cjAbilityMonitor);

    /**
     * A constructor used to create a CJAbilityMonitor instance with the input
     * parameter passed.
     *
     * @param name Indicates the specified ability name.
     * @param moduleName Indicates the specified ability moduleName.
     * @param cjAbilityMonitor Indicates the CJMonitorObject object.
     */
    CJAbilityMonitor(const std::string& name, const std::string& moduleName,
        const std::shared_ptr<CJMonitorObject>& cjAbilityMonitor);

    /**
     * Default deconstructor used to deconstruct.
     */
    ~CJAbilityMonitor() = default;

    /**
     * Called when ability is started.
     *
     * @param abilityId Indicates the ability object.
     */
    void OnAbilityStart(const int64_t abilityId) override;

    /**
     * Called when ability is in foreground.
     *
     * @param abilityId Indicates the ability object.
     */
    void OnAbilityForeground(const int64_t abilityId) override;

    /**
     * Called when ability is in background.
     *
     * @param abilityId Indicates the ability object.
     */
    void OnAbilityBackground(const int64_t abilityId) override;

    /**
     * Called when ability is stopped.
     *
     * @param abilityId Indicates the ability object.
     */
    void OnAbilityStop(const int64_t abilityId) override;

    /**
     * Called when window stage is created.
     *
     * @param abilityId Indicates the ability object.
     */
    void OnWindowStageCreate(const int64_t abilityId) override;

    /**
     * Called when window stage is restored.
     *
     * @param abilityId Indicates the ability object.
     */
    void OnWindowStageRestore(const int64_t abilityId) override;

    /**
     * Called when window stage is destroyed.
     *
     * @param abilityId Indicates the ability object.
     */
    void OnWindowStageDestroy(const int64_t abilityId) override;

private:
    std::shared_ptr<CJMonitorObject> cjMonitor_;
};
} // namespace AbilityDelegatorCJ
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_CJ_ABILITY_MONITOR_H
