/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_LAUNCH_PARAM_H
#define OHOS_ABILITY_RUNTIME_LAUNCH_PARAM_H

#include <string>

#include "parcel.h"

namespace OHOS {
namespace AAFwk {
/**
 * @enum LaunchReason
 * LaunchReason defines the reason of launching ability.
 */
enum LaunchReason {
    LAUNCHREASON_UNKNOWN = 0,
    LAUNCHREASON_START_ABILITY,
    LAUNCHREASON_CALL,
    LAUNCHREASON_CONTINUATION,
    LAUNCHREASON_APP_RECOVERY,
    LAUNCHREASON_SHARE,
    LAUNCHREASON_START_EXTENSION,
    LAUNCHREASON_CONNECT_EXTENSION,
    LAUNCHREASON_AUTO_STARTUP,
    LAUNCHREASON_INSIGHT_INTENT,
    LAUNCHREASON_PREPARE_CONTINUATION
};

/**
 * @enum LastExitReason
 * LastExitReason defines the reason of last exist.
 */
enum LastExitReason {
    LASTEXITREASON_UNKNOWN = 0,
    LASTEXITREASON_ABILITY_NOT_RESPONDING,
    LASTEXITREASON_NORMAL,
    LASTEXITREASON_CPP_CRASH,
    LASTEXITREASON_JS_ERROR,
    LASTEXITREASON_APP_FREEZE,
    LASTEXITREASON_PERFORMANCE_CONTROL,
    LASTEXITREASON_RESOURCE_CONTROL,
    LASTEXITREASON_UPGRADE
};

/**
 * @enum OnContinueResult
 * OnContinueResult defines the result of onContinue.
 */
enum OnContinueResult {
    ONCONTINUE_AGREE = 0,
    ONCONTINUE_REJECT,
    ONCONTINUE_MISMATCH
};

/**
 * @struct LaunchParam
 * LaunchParam is used to save information about ability launch param.
 */
struct LaunchParam : public Parcelable {
    LaunchReason launchReason = LaunchReason::LAUNCHREASON_UNKNOWN;
    LastExitReason lastExitReason = LastExitReason::LASTEXITREASON_NORMAL;
    std::string lastExitMessage = "";

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static LaunchParam *Unmarshalling(Parcel &parcel);
};
[[maybe_unused]] static LaunchReason LaunchReason_ConvertStsToNative(const int32_t index);
[[maybe_unused]] static int32_t LaunchReason_ConvertNativeToSts(const LaunchReason value);
[[maybe_unused]] static LastExitReason LastExitReason_ConvertStsToNative(const int32_t index);
[[maybe_unused]] static int32_t LastExitReason_ConvertNativeToSts(const LastExitReason value);
[[maybe_unused]] static OnContinueResult OnContinueResult_ConvertStsToNative(const int index);
[[maybe_unused]] static int32_t OnContinueResult_ConvertNativeToSts(const OnContinueResult value);
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_LAUNCH_PARAM_H
