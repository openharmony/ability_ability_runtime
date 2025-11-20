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

#include "ability_record/ability_request.h"

#include "ipc_skeleton.h"

namespace OHOS {
namespace AAFwk {
std::pair<bool, LaunchReason> AbilityRequest::IsContinuation() const
{
    auto flags = want.GetFlags();
    if ((flags & Want::FLAG_ABILITY_CONTINUATION) == Want::FLAG_ABILITY_CONTINUATION) {
        return {true, LaunchReason::LAUNCHREASON_CONTINUATION};
    }
    if ((flags & Want::FLAG_ABILITY_PREPARE_CONTINUATION) == Want::FLAG_ABILITY_PREPARE_CONTINUATION) {
        return {true, LaunchReason::LAUNCHREASON_PREPARE_CONTINUATION};
    }
    return {false, LaunchReason::LAUNCHREASON_UNKNOWN};
}

void AbilityRequest::Dump(std::vector<std::string> &state)
{
    std::string dumpInfo = "      want [" + want.ToUri() + "]";
    state.push_back(dumpInfo);
    dumpInfo = "      app name [" + abilityInfo.applicationName + "]";
    state.push_back(dumpInfo);
    dumpInfo = "      main name [" + abilityInfo.name + "]";
    state.push_back(dumpInfo);
    dumpInfo = "      request code [" + std::to_string(requestCode) + "]";
    state.push_back(dumpInfo);
}

void AbilityRequest::Voluation(const Want &srcWant, int srcRequestCode,
    const sptr<IRemoteObject> &srcCallerToken, const std::shared_ptr<AbilityStartSetting> srcStartSetting,
    int srcCallerUid)
{
    want = srcWant;
    requestCode = srcRequestCode;
    callerToken = srcCallerToken;
    startSetting = srcStartSetting;
    callerUid = srcCallerUid == -1 ? IPCSkeleton::GetCallingUid() : srcCallerUid;
}
}  // namespace AAFwk
}  // namespace OHOS