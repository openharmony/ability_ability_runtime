/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "cj_ability_monitor.h"

#include "cj_ability_monitor_object.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityDelegatorCJ {

CJAbilityMonitor::CJAbilityMonitor(const std::string& name, const std::shared_ptr<CJMonitorObject>& cjAbilityMonitor)
    : CJIAbilityMonitor(name), cjMonitor_(cjAbilityMonitor)
{}

CJAbilityMonitor::CJAbilityMonitor(
    const std::string& name, const std::string& moduleName, const std::shared_ptr<CJMonitorObject>& cjAbilityMonitor)
    : CJIAbilityMonitor(name, moduleName), cjMonitor_(cjAbilityMonitor)
{}

void CJAbilityMonitor::OnAbilityStart(const int64_t abilityId)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "CJAbilityMonitor::OnAbilityStart called");

    if (cjMonitor_ == nullptr) {
        return;
    }

    cjMonitor_->OnAbilityCreate(abilityId);
}

void CJAbilityMonitor::OnAbilityForeground(const int64_t abilityId)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "CJAbilityMonitor::OnAbilityForeground called");

    if (cjMonitor_ == nullptr) {
        return;
    }

    cjMonitor_->OnAbilityForeground(abilityId);
}

void CJAbilityMonitor::OnAbilityBackground(const int64_t abilityId)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "CJAbilityMonitor::OnAbilityBackground called");

    if (cjMonitor_ == nullptr) {
        return;
    }

    cjMonitor_->OnAbilityBackground(abilityId);
}

void CJAbilityMonitor::OnAbilityStop(const int64_t abilityId)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "CJAbilityMonitor::OnAbilityStop called");

    if (cjMonitor_ == nullptr) {
        return;
    }

    cjMonitor_->OnAbilityDestroy(abilityId);
}

void CJAbilityMonitor::OnWindowStageCreate(const int64_t abilityId)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "CJAbilityMonitor::OnWindowStageCreate called");

    if (cjMonitor_ == nullptr) {
        return;
    }

    cjMonitor_->OnWindowStageCreate(abilityId);
}

void CJAbilityMonitor::OnWindowStageRestore(const int64_t abilityId)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "CJAbilityMonitor::OnWindowStageRestore called");

    if (cjMonitor_ == nullptr) {
        return;
    }

    cjMonitor_->OnWindowStageRestore(abilityId);
}

void CJAbilityMonitor::OnWindowStageDestroy(const int64_t abilityId)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "CJAbilityMonitor::OnWindowStageDestroy called");

    if (cjMonitor_ == nullptr) {
        return;
    }

    cjMonitor_->OnWindowStageDestroy(abilityId);
}
} // namespace AbilityDelegatorCJ
} // namespace OHOS