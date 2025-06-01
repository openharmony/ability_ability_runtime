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

#include "kiosk_status.h"
#include "string_ex.h"

namespace OHOS {
namespace AAFwk {
bool KioskStatus::ReadFromParcel(Parcel &parcel)
{
    isKioskMode_ = parcel.ReadBool();
    kioskBundleName_ = Str16ToStr8(parcel.ReadString16());
    kioskBundleUid_ = parcel.ReadInt32();
    return true;
}

KioskStatus *KioskStatus::Unmarshalling(Parcel &parcel)
{
    KioskStatus *info = new KioskStatus();
    if (!info->ReadFromParcel(parcel)) {
        delete info;
        info = nullptr;
    }
    return info;
}

bool KioskStatus::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(isKioskMode_)) {
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(kioskBundleName_))) {
        return false;
    }

    if (!parcel.WriteInt32(kioskBundleUid_)) {
        return false;
    }
    return true;
}

void KioskStatus::Clear()
{
    isKioskMode_ = false;
    kioskBundleUid_ = 0;
    kioskBundleName_.clear();
}
} // namespace AAFwk
} // namespace OHOS
