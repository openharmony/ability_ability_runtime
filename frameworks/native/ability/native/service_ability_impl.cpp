/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "service_ability_impl.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
using AbilityManagerClient = OHOS::AAFwk::AbilityManagerClient;
void ServiceAbilityImpl::HandleAbilityTransaction(const Want &want, const AAFwk::LifeCycleStateInfo &targetState,
    sptr<AAFwk::SessionInfo> sessionInfo)
{
    TAG_LOGD(AAFwkTag::ABILITY,
        "begin sourceState:%{public}d; targetState: %{public}d; "
        "isNewWant: %{public}d",
        lifecycleState_,
        targetState.state,
        targetState.isNewWant);
    if (lifecycleState_ == targetState.state) {
        TAG_LOGE(AAFwkTag::ABILITY, "lifeCycleStat:org=Dst");
        return;
    }

    bool ret = true;

    switch (targetState.state) {
        case AAFwk::ABILITY_STATE_INITIAL: {
            if (lifecycleState_ == AAFwk::ABILITY_STATE_ACTIVE) {
#ifdef SUPPORT_GRAPHICS
                Background();
#endif
                Stop();
            }
            break;
        }
        case AAFwk::ABILITY_STATE_INACTIVE: {
            if (lifecycleState_ == AAFwk::ABILITY_STATE_INITIAL) {
                SetUriString(targetState.caller.deviceId + "/" + targetState.caller.bundleName + "/" +
                             targetState.caller.abilityName);
                Start(want);
            }
            break;
        }
        default: {
            ret = false;
            TAG_LOGE(AAFwkTag::ABILITY, "error");
            break;
        }
    }

    if (ret) {
        AbilityTransactionCallback(targetState.state);
    }
}

void ServiceAbilityImpl::AbilityTransactionCallback(const AbilityLifeCycleState &state)
{
    TAG_LOGD(AAFwkTag::ABILITY, "called");
    AbilityManagerClient::GetInstance()->AbilityTransitionDone(token_, state, GetRestoreData());
}
}  // namespace AppExecFwk
}  // namespace OHOS
