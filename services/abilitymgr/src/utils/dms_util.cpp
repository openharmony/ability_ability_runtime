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

#include "dms_util.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AAFwk {
constexpr const char* IS_CALLING_FROM_DMS = "supportCollaborativeCallingFromDmsInAAFwk";
constexpr int32_t DMS_UID = 5522;

DmsUtil &DmsUtil::GetInstance()
{
    static DmsUtil instance;
    return instance;
}

void DmsUtil::UpdateFlagForCollaboration(const Want &want)
{
    if ((want.GetFlags() & Want::FLAG_ABILITY_ON_COLLABORATE) == Want::FLAG_ABILITY_ON_COLLABORATE &&
        IPCSkeleton::GetCallingUid() == DMS_UID) {
        (const_cast<Want &>(want)).SetParam(IS_CALLING_FROM_DMS, true);
    } else {
        (const_cast<Want &>(want)).RemoveParam(IS_CALLING_FROM_DMS);
    }
}
} // namespace AAFwk
} // namespace OHOS
