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

#include "killed_process_info.h"

#include "hilog_tag_wrapper.h"
#include "parcel_macro_base.h"

namespace OHOS {
namespace AppExecFwk {
bool KilledProcessInfo::ReadFromParcel(Parcel &parcel)
{
    accessTokenId = parcel.ReadUint32();
    bundleName = parcel.ReadString();
    std::unique_ptr<RunningProcessInfo> tmpInfo(parcel.ReadParcelable<RunningProcessInfo>());
    if (tmpInfo == nullptr) {
        return false;
    }
    processInfo = *tmpInfo;
    return true;
}

KilledProcessInfo *KilledProcessInfo::Unmarshalling(Parcel &parcel)
{
    KilledProcessInfo *info = new (std::nothrow) KilledProcessInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        TAG_LOGW(AAFwkTag::APPMGR, "read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool KilledProcessInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, accessTokenId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, bundleName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &processInfo);
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS