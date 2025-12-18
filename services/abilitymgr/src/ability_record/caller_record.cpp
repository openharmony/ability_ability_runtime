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

#include "ability_record/caller_record.h"

#include "ability_record.h"

namespace OHOS {
namespace AAFwk {
CallerRecord::CallerRecord(int requestCode, std::weak_ptr<AbilityRecord> caller)
    : requestCode_(requestCode), caller_(caller)
{
    auto callerAbilityRecord = caller.lock();
    if  (callerAbilityRecord != nullptr) {
        callerInfo_ = std::make_shared<CallerAbilityInfo>();
        callerInfo_->callerBundleName = callerAbilityRecord->GetAbilityInfo().bundleName;
        callerInfo_->callerAbilityName = callerAbilityRecord->GetAbilityInfo().name;
        callerInfo_->callerTokenId = callerAbilityRecord->GetApplicationInfo().accessTokenId;
        callerInfo_->callerUid =  callerAbilityRecord->GetUid();
        callerInfo_->callerPid =  callerAbilityRecord->GetPid();
        callerInfo_->callerAppCloneIndex = callerAbilityRecord->GetAppIndex();
    }
}
}  // namespace AAFwk
}  // namespace OHOS