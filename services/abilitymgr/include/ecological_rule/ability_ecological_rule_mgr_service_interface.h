/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef ABILITY_SERVICES_INCLUDE_ECOLOGICALRULEMANAGERSERVICE_INTERFACE_H
#define ABILITY_SERVICES_INCLUDE_ECOLOGICALRULEMANAGERSERVICE_INTERFACE_H

#include <string>
#include "iremote_broker.h"
#include "ability_ecological_rule_mgr_service_param.h"
#include "want.h"
#include "ability_info.h"

namespace OHOS {
namespace EcologicalRuleMgrService {
class IAbilityEcologicalRuleMgrService : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.cloud.ecologicalrulemgrservice.IAbilityEcologicalRuleMgrService");

    using Want = OHOS::AAFwk::Want;

    using AbilityInfo = OHOS::AppExecFwk::AbilityInfo;

    /**
     * @brief the start experience rule for the given Want and caller information.
     * @param want The Want object representing the desired ability.
     * @param callerInfo Information about the caller initiating the query.
     * @param rule Output parameter to store the retrieved ability experience rule.
     * @return Returns 0 on success, non-zero on failure.
     */
    virtual int32_t QueryStartExperience(const Want &want, const AbilityCallerInfo &callerInfo,
        AbilityExperienceRule &rule) = 0;

    /**
     * @brief Evaluates the resolve infos for the given Want, caller information, and type.
     * @param want The Want object representing the desired ability.
     * @param callerInfo Information about the caller initiating the evaluation.
     * @param type The type of evaluation to perform.
     * @param abilityInfos Output parameter to store the evaluated ability infos.
     * @return Returns 0 on success, non-zero on failure.
     */
    virtual int32_t EvaluateResolveInfos(const Want &want, const AbilityCallerInfo &callerInfo, int32_t type,
        std::vector<AbilityInfo> &abilityInfos) = 0;

    /**
     * @brief Enumeration of command IDs for interface methods.
     */
    enum {
        QUERY_START_EXPERIENCE_CMD = 1,
        EVALUATE_RESOLVE_INFO_CMD = 2
    };

    enum ErrCode {
        ERR_BASE = (-99),
        ERR_FAILED = (-1),
        ERR_PERMISSION_DENIED = (-2),
        ERR_OK = 0,
    };
};
} // namespace EcologicalRuleMgrService
} // namespace OHOS

#endif // ABILITY_SERVICES_INCLUDE_ECOLOGICALRULEMGRSERVICE_INTERFACE_H