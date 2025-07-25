/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_MISSION_SNAPSHOT_H
#define OHOS_ABILITY_RUNTIME_MISSION_SNAPSHOT_H

#include "parcel.h"
#include "element_name.h"
namespace OHOS {
namespace Media {
#ifdef SUPPORT_SCREEN
class PixelMap;
#endif //SUPPORT_SCREEN
}
namespace AAFwk {
struct MissionSnapshot : public Parcelable {
    AppExecFwk::ElementName topAbility;
#ifdef SUPPORT_SCREEN
    std::shared_ptr<OHOS::Media::PixelMap> snapshot;
#endif //SUPPORT_SCREEN
    // If is private, ability is secure, the snapshot is a blank picture.
    bool isPrivate = false;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static MissionSnapshot *Unmarshalling(Parcel &parcel);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_MISSION_SNAPSHOT_H
