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

#ifndef OHOS_ABILITY_RUNTIME_DLP_UTILS_H
#define OHOS_ABILITY_RUNTIME_DLP_UTILS_H

#include "ability_record.h"
// #include "dlp_permission_kit.h"
#include "iremote_object.h"
#include "want.h"

namespace OHOS {
namespace AAFwk {
namespace DlpUtils {
// using Dlp = Security::DlpPermission;
static bool DlpAccessOtherAppsCheck(const sptr<IRemoteObject> &callerToken, const Want &want)
{
    if (callerToken == nullptr) {
        return true;
    }
    auto abilityRecord = Token::GetAbilityRecordByToken(callerToken);
    if (abilityRecord == nullptr) {
        HILOG_ERROR("Ability has already been destroyed.");
        return false;
    }
    if (abilityRecord->GetAppIndex() == 0) {
        return true;
    }
    if (abilityRecord->GetApplicationInfo().bundleName == want.GetElement().GetBundleName()) {
        return true;
    }
    int32_t uid = abilityRecord->GetApplicationInfo().uid;
    //Dlp::SandBoxExternalAuthorType result = Dlp::GetSandBoxExternalAuthorization(uid, want);
    //if (result == Dlp::SandBoxExternalAuthorType::ALLOW_START_ABILITY) {
    //    return true;
    //}
    HILOG_ERROR("Ability has already been destroyed %{public}d.", uid);
    return false;
}
}  // namespace DlpUtils
}  // namespace AAFwk
}  // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_DLP_UTILS_H
