/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "intent_exemption_info.h"
#include "hilog_tag_wrapper.h"
#include "parcel_macro_base.h"

namespace OHOS {
namespace AppExecFwk {
bool IntentExemptionInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uid_);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, duration_);
    return true;
}

IntentExemptionInfo *IntentExemptionInfo::Unmarshalling(Parcel &parcel)
{
    IntentExemptionInfo *info = new (std::nothrow) IntentExemptionInfo();
    if (info == nullptr) {
        return nullptr;
    }

    if (!info->ReadFromParcel(parcel)) {
        delete info;
        info = nullptr;
    }
    return info;
}

bool IntentExemptionInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uid_);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, duration_);
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS
