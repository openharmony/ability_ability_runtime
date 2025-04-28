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

#include "configuration_policy.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
bool ConfigurationPolicy::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt8(maxCountPerBatch)) {
        TAG_LOGE(AAFwkTag::APPMGR, "maxCountPerBatch read int8 failed.");
        return false;
    }
    if (!parcel.ReadInt16(intervalTime)) {
        TAG_LOGE(AAFwkTag::APPMGR, "intervalTime read int16 failed.");
        return false;
    }

    return true;
}

ConfigurationPolicy *ConfigurationPolicy::Unmarshalling(Parcel &parcel)
{
    ConfigurationPolicy *policy = new (std::nothrow) ConfigurationPolicy();
    if (policy && !policy->ReadFromParcel(parcel)) {
        delete policy;
        policy = nullptr;
    }
    return policy;
}

bool ConfigurationPolicy::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt8(maxCountPerBatch)) {
        TAG_LOGE(AAFwkTag::APPMGR, "countPerTime write int8 failed.");
        return false;
    }

    if (!parcel.WriteInt16(intervalTime)) {
        TAG_LOGE(AAFwkTag::APPMGR, "intervalTime write int16 failed.");
        return false;
    }

    return true;
}
} // namespace AppExecFwk
} // namespace OHOS