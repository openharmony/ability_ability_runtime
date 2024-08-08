/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "utils/start_option_utils.h"

#include "hilog_tag_wrapper.h"
#include "string_wrapper.h"

namespace OHOS {
namespace AAFwk {
void StartOptionUtils::UpdateStartOptionsToSetDisplayID(StartOptions &startOptions,
    const sptr<IRemoteObject> &callerToken)
{
    sptr<IRemoteObject> caller;
    if (startOptions.GetDisplayID() == 0) {
        if (callerToken != nullptr) {
            caller = callerToken;
        }
        std::shared_ptr<AbilityRecord> abilityRecord = Token::GetAbilityRecordByToken(caller);
        if (abilityRecord != nullptr) {
            std::string displayId = abilityRecord->GetWant().GetParams().GetStringParam(Want::PARAM_RESV_DISPLAY_ID);
            startOptions.SetDisplayID(std::stoi(displayId));
        }
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "start ability displayID is %{public}d", startOptions.GetDisplayID());
}

void StartOptionUtils::UpdateWantToSetDisplayID(Want &want,
   const sptr<IRemoteObject> &callerToken)
{
    sptr<IRemoteObject> caller;
    OHOS::AAFwk::WantParams params = want.GetParams();
    if (callerToken != nullptr) {
        caller = callerToken;
    } else {
        params.SetParam(Want::PARAM_RESV_DISPLAY_ID, AAFwk::String::Box("0"));
        want.SetParams(params);
        TAG_LOGD(AAFwkTag::ABILITYMGR, "start ability displayID is 0");
        return;
    }
    std::shared_ptr<AbilityRecord> abilityRecord = Token::GetAbilityRecordByToken(caller);
    if (abilityRecord != nullptr) {
        std::string displayId = abilityRecord->GetWant().GetParams().GetStringParam(Want::PARAM_RESV_DISPLAY_ID);
        params.SetParam(Want::PARAM_RESV_DISPLAY_ID, AAFwk::String::Box(displayId));
        want.SetParams(params);
    } else {
        params.SetParam(Want::PARAM_RESV_DISPLAY_ID, AAFwk::String::Box("0"));
        want.SetParams(params);
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "start ability displayID is %{public}s",
        want.GetParams().GetStringParam(Want::PARAM_RESV_DISPLAY_ID).c_str());
}
}  // namespace AAFwk
}  // namespace OHOS