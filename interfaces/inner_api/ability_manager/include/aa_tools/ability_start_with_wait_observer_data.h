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

#ifndef OHOS_ABILITY_ABILITY_START_WITH_WAIT_OBSERVER_DATA_H
#define OHOS_ABILITY_ABILITY_START_WITH_WAIT_OBSERVER_DATA_H

#include "parcel.h"

namespace OHOS {
namespace AAFwk {
struct AbilityStartWithWaitObserverData : public Parcelable {
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static AbilityStartWithWaitObserverData *Unmarshalling(Parcel &parcel);

    bool coldStart = false;
    uint32_t reason = 0;
    int64_t startTime = 0;
    int64_t foregroundTime = 0; // ability foreground time
    std::string bundleName;
    std::string abilityName;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_ABILITY_START_WITH_WAIT_OBSERVER_DATA_H