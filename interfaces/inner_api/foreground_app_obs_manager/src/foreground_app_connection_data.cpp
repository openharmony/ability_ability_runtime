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

#include "foreground_app_connection_data.h"
#include "string_ex.h"

namespace OHOS {
namespace AbilityRuntime {
bool ForegroundAppConnectionData::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(callerPid_)) {
        return false;
    }
    if (!parcel.WriteInt32(targetPid_)) {
        return false;
    }
    if (!parcel.WriteInt32(callerUid_)) {
        return false;
    }
    if (!parcel.WriteInt32(targetUid_)) {
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(callerBundleName_))) {
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(targetBundleName_))) {
        return false;
    }

    return true;
}

bool ForegroundAppConnectionData::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt32(callerPid_)) {
        return false;
    }

    if (!parcel.ReadInt32(targetPid_)) {
        return false;
    }
    if (!parcel.ReadInt32(callerUid_)) {
        return false;
    }
    if (!parcel.ReadInt32(targetUid_)) {
        return false;
    }

    std::u16string strValue;
    if (!parcel.ReadString16(strValue)) {
        return false;
    }
    callerBundleName_ = Str16ToStr8(strValue);

    if (!parcel.ReadString16(strValue)) {
        return false;
    }
    targetBundleName_ = Str16ToStr8(strValue);

    return true;
}

ForegroundAppConnectionData *ForegroundAppConnectionData::Unmarshalling(Parcel &parcel)
{
    ForegroundAppConnectionData *data = new ForegroundAppConnectionData();
    if (!data->ReadFromParcel(parcel)) {
        delete data;
        data = nullptr;
    }
    return data;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
