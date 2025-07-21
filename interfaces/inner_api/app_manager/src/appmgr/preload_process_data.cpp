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

#include "preload_process_data.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
bool PreloadProcessData::ReadFromParcel(Parcel &parcel)
{
    isPreForeground = parcel.ReadBool();
    pid = parcel.ReadInt32();
    uid = parcel.ReadInt32();
    bundleName = parcel.ReadString();
    return true;
}

bool PreloadProcessData::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(isPreForeground)) {
        TAG_LOGE(AAFwkTag::APPMGR, "write isPreForeground failed.");
        return false;
    }
    if (!parcel.WriteInt32(pid)) {
        TAG_LOGE(AAFwkTag::APPMGR, "write pid failed.");
        return false;
    }
    if (!parcel.WriteInt32(uid)) {
        TAG_LOGE(AAFwkTag::APPMGR, "write uid failed.");
        return false;
    }
    if (!parcel.WriteString(bundleName)) {
        TAG_LOGE(AAFwkTag::APPMGR, "write bundleName failed.");
        return false;
    }
    return true;
}

PreloadProcessData *PreloadProcessData::Unmarshalling(Parcel &parcel)
{
    PreloadProcessData *data = new (std::nothrow) PreloadProcessData();
    if (data && !data->ReadFromParcel(parcel)) {
        delete data;
        data = nullptr;
    }
    return data;
}
}  // namespace AppExecFwk
}  // namespace OHOS