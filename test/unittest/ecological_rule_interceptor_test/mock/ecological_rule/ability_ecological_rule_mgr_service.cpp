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

#include "ecological_rule/ability_ecological_rule_mgr_service.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace EcologicalRuleMgrService {
int32_t AbilityEcologicalRuleMgrServiceClient::retQueryStartExperience = 0;
AbilityExperienceRule AbilityEcologicalRuleMgrServiceClient::queryStartExperienceRule;

AbilityEcologicalRuleMgrServiceClient::~AbilityEcologicalRuleMgrServiceClient()
{}

sptr<AbilityEcologicalRuleMgrServiceClient> AbilityEcologicalRuleMgrServiceClient::GetInstance()
{
    static sptr<AbilityEcologicalRuleMgrServiceClient> instance_ = new AbilityEcologicalRuleMgrServiceClient;
    return instance_;
}

int32_t AbilityEcologicalRuleMgrServiceClient::QueryStartExperience(const OHOS::AAFwk::Want &want,
    const AbilityCallerInfo &callerInfo, AbilityExperienceRule &rule)
{
    rule = queryStartExperienceRule;
    return retQueryStartExperience;
}
} // namespace EcologicalRuleMgrService
} // namespace OHOS
