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

#include "background_app_info.h"
#include "hilog_tag_wrapper.h"
#include "nlohmann/json.hpp"
#include "parcel_macro_base.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {

bool BackgroundAppInfo::ReadFromParcel(Parcel &parcel)
{
    bandleName = Str16ToStr8(parcel.ReadString16());
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);
    
    return true;
}

BackgroundAppInfo *BackgroundAppInfo::Unmarshalling(Parcel &parcel)
{
    BackgroundAppInfo *info = new (std::nothrow) BackgroundAppInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        TAG_LOGE(AAFwkTag::APPMGR, "read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool BackgroundAppInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bandleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);
    
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS