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

#include "start_specified_ability_params.h"

#include "hilog_tag_wrapper.h"
#include "parcel_macro_base.h"
#include "string_ex.h"

namespace OHOS {
namespace AAFwk {
StartSpecifiedAbilityParams::StartSpecifiedAbilityParams(int32_t persistentId, SpecifiedReason reason)
{
    this->persistentId = persistentId;
    specifiedReason = reason;
}

StartSpecifiedAbilityParams::StartSpecifiedAbilityParams(const StartSpecifiedAbilityParams &other)
{
    persistentId = other.persistentId;
    specifiedReason = other.specifiedReason;
}

bool StartSpecifiedAbilityParams::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, persistentId);
    int32_t reason = 0;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, reason);
    specifiedReason = SpecifiedReason(reason);
    return true;
}

StartSpecifiedAbilityParams *StartSpecifiedAbilityParams::Unmarshalling(Parcel &parcel)
{
    StartSpecifiedAbilityParams *data = new (std::nothrow) StartSpecifiedAbilityParams();
    if (!data) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null data");
        return nullptr;
    }
    if (!data->ReadFromParcel(parcel)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "read failed");
        delete data;
        data = nullptr;
    }
    return data;
}

bool StartSpecifiedAbilityParams::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, persistentId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(specifiedReason));
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
