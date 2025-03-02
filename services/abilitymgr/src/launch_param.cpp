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

#include "launch_param.h"

#include "hilog_tag_wrapper.h"
#include "string_ex.h"

namespace OHOS {
namespace AAFwk {
bool LaunchParam::ReadFromParcel(Parcel &parcel)
{
    int32_t reason = 0;
    if (!parcel.ReadInt32(reason)) {
        return false;
    }
    launchReason = static_cast<LaunchReason>(reason);

    if (!parcel.ReadInt32(reason)) {
        return false;
    }
    lastExitReason = static_cast<LastExitReason>(reason);

    lastExitMessage = Str16ToStr8(parcel.ReadString16());
    return true;
}

LaunchParam *LaunchParam::Unmarshalling(Parcel &parcel)
{
    LaunchParam *param = new (std::nothrow) LaunchParam();
    if (param == nullptr) {
        return nullptr;
    }

    if (!param->ReadFromParcel(parcel)) {
        delete param;
        param = nullptr;
    }
    return param;
}

bool LaunchParam::Marshalling(Parcel &parcel) const
{
    // write launchReason
    if (!parcel.WriteInt32(static_cast<int32_t>(launchReason))) {
        return false;
    }
    // write lastExitReason
    if (!parcel.WriteInt32(static_cast<int32_t>(lastExitReason))) {
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(lastExitMessage))) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write lastExitMessage failed");
        return false;
    }
    return true;
}
//  enum LaunchReason {
//     UNKNOWN = 0,
//     START_ABILITY = 1,
//     CALL = 2,
//     CONTINUATION = 3,
//     APP_RECOVERY = 4,
//     SHARE = 5,
//     AUTO_STARTUP = 8,
//     INSIGHT_INTENT = 9,
//     PREPARE_CONTINUATION = 10,
//   }
static constexpr std::array<int32_t, 9> LaunchReasonArray_ = {0, 1, 2, 3, 4, 5, 8, 9, 10};
LaunchReason LaunchReason_ConvertStsToNative(const int32_t index)
{
    if (index < 0 || index >= LaunchReasonArray_.size()) {
        return LaunchReason::LAUNCHREASON_UNKNOWN;
    }
    return static_cast<LaunchReason>(LaunchReasonArray_[index]);
}
int32_t LaunchReason_ConvertNativeToSts(const LaunchReason value)
{
    for (int32_t index = 0; index < LaunchReasonArray_.size(); index++) {
        if (value == LaunchReasonArray_[index]) {
            return index;
        }
    }
    return 0;
}
// enum LastExitReason {
//     UNKNOWN = 0,
//     ABILITY_NOT_RESPONDING = 1,
//     NORMAL = 2,
//     CPP_CRASH = 3,
//     JS_ERROR = 4,
//     APP_FREEZE = 5,
//     PERFORMANCE_CONTROL = 6,
//     RESOURCE_CONTROL = 7,
//     UPGRADE = 8
//   }
LastExitReason LastExitReason_ConvertStsToNative(const int32_t index)
{
    if (index < 0 || index > LastExitReason::LASTEXITREASON_UPGRADE) {
        return LastExitReason::LASTEXITREASON_UNKNOWN;
    }
    return static_cast<LastExitReason>(index);
}
int32_t LastExitReason_ConvertNativeToSts(const LastExitReason value)
{
    return value;
}
// enum OnContinueResult {
//     AGREE = 0,
//     REJECT = 1,
//     MISMATCH = 2
//   }
OnContinueResult OnContinueResult_ConvertStsToNative(const int index)
{
    return static_cast<OnContinueResult>(index);
}
int32_t OnContinueResult_ConvertNativeToSts(const OnContinueResult value)
{
    return value;
}
}  // namespace AAFwk
}  // namespace OHOS
