/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SERVICES_INCLUDE_ECOLOGICAL_RULE_MANAGER_SERVICE_PROXY_H
#define SERVICES_INCLUDE_ECOLOGICAL_RULE_MANAGER_SERVICE_PROXY_H

#include "ability_ecological_rule_mgr_service_interface.h"

namespace OHOS {
namespace EcologicalRuleMgrService {

using namespace std;
using Want = OHOS::AAFwk::Want;

class AbilityEcologicalRuleMgrServiceClient : public RefBase {
public:
    DISALLOW_COPY_AND_MOVE(AbilityEcologicalRuleMgrServiceClient);
    static sptr<AbilityEcologicalRuleMgrServiceClient> GetInstance();
    int32_t QueryStartExperience(const Want &want, const AbilityCallerInfo &callerInfo, AbilityExperienceRule &rule);

public:
    static int32_t retQueryStartExperience;
    static AbilityExperienceRule queryStartExperienceRule;

private:
    AbilityEcologicalRuleMgrServiceClient() {};
    ~AbilityEcologicalRuleMgrServiceClient();
};
} // namespace EcologicalRuleMgrService
} // namespace OHOS

#endif // SERVICES_INCLUDE_ECOLOGICAL_RULE_MANAGER_SERVICE_PROXY_H
