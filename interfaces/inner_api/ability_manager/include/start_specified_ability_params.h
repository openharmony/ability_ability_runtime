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

#ifndef OHOS_ABILITY_RUNTIME_START_SPECIFIED_ABILITY_PARAMS_H
#define OHOS_ABILITY_RUNTIME_START_SPECIFIED_ABILITY_PARAMS_H

#include "parcel.h"

namespace OHOS {
namespace AAFwk {
enum class SpecifiedReason : int32_t {
    UNDEFINED = 0,
    BY_SCB,
    FROM_RECENT,
};

struct StartSpecifiedAbilityParams : public Parcelable {
    StartSpecifiedAbilityParams() = default;
    StartSpecifiedAbilityParams(int32_t persistentId, SpecifiedReason reason);
    StartSpecifiedAbilityParams(const StartSpecifiedAbilityParams &other);

    int32_t persistentId = 0;
    SpecifiedReason specifiedReason = SpecifiedReason::UNDEFINED;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static StartSpecifiedAbilityParams *Unmarshalling(Parcel &parcel);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_START_SPECIFIED_ABILITY_PARAMS_H
