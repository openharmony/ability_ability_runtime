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

#include "utils/window_options_utils.h"

#include "ability_record.h"
#include "app_utils.h"

namespace OHOS {
namespace AAFwk {
void WindowOptionsUtils::SetWindowPositionAndSize(Want& want,
    const sptr<IRemoteObject>& callerToken, const StartOptions& startOptions)
{
    if (!AppUtils::GetInstance().IsStartOptionsWithAnimation()) {
        return;
    }
    if (startOptions.windowLeftUsed_) {
        want.SetParam(Want::PARAM_RESV_WINDOW_LEFT, startOptions.GetWindowLeft());
    }
    if (startOptions.windowTopUsed_) {
        want.SetParam(Want::PARAM_RESV_WINDOW_TOP, startOptions.GetWindowTop());
    }
    if (startOptions.windowWidthUsed_) {
        want.SetParam(Want::PARAM_RESV_WINDOW_WIDTH, startOptions.GetWindowWidth());
    }
    if (startOptions.windowHeightUsed_) {
        want.SetParam(Want::PARAM_RESV_WINDOW_HEIGHT, startOptions.GetWindowHeight());
    }
    bool withAnimation = startOptions.GetWithAnimation();
    auto abilityRecord = Token::GetAbilityRecordByToken(callerToken);
    if (!withAnimation && abilityRecord != nullptr &&
        abilityRecord->GetAbilityInfo().bundleName == want.GetBundle()) {
        want.SetParam(Want::PARAM_RESV_WITH_ANIMATION, withAnimation);
    }
}

std::pair<bool, AppExecFwk::SupportWindowMode> WindowOptionsUtils::WindowModeMap(int32_t windowMode)
{
    std::pair<bool, AppExecFwk::SupportWindowMode> result(false, AppExecFwk::SupportWindowMode::FULLSCREEN);

    if (windowMode == MULTI_WINDOW_DISPLAY_FULLSCREEN) {
        result.first = true;
        result.second = AppExecFwk::SupportWindowMode::FULLSCREEN;
    } else if (windowMode == MULTI_WINDOW_DISPLAY_PRIMARY) {
        result.first = true;
        result.second = AppExecFwk::SupportWindowMode::SPLIT;
    } else if (windowMode == MULTI_WINDOW_DISPLAY_SECONDARY) {
        result.first = true;
        result.second = AppExecFwk::SupportWindowMode::SPLIT;
    } else if (windowMode == MULTI_WINDOW_DISPLAY_FLOATING) {
        result.first = true;
        result.second = AppExecFwk::SupportWindowMode::FLOATING;
    }
    return result;
}

void WindowOptionsUtils::UpdateStartOptionsToSetDisplayID(StartOptions &startOptions,
    const sptr<IRemoteObject> &callerToken)
{
    if (!AppUtils::GetInstance().IsStartOptionsWithAnimation()) {
        return;
    }
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

void WindowOptionsUtils::UpdateWantToSetDisplayID(Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    if (!AppUtils::GetInstance().IsStartOptionsWithAnimation()) {
        return;
    }
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
