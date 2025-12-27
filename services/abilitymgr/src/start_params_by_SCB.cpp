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

#include "start_params_by_SCB.h"

namespace OHOS {
namespace AbilityRuntime {
bool StartParamsBySCB::ReadFromParcel(Parcel &parcel)
{
    sceneFlag = parcel.ReadUint32();
    isRestart = parcel.ReadBool();
    pageConfig = parcel.ReadString();
    return true;
}

StartParamsBySCB *StartParamsBySCB::Unmarshalling(Parcel &parcel)
{
    StartParamsBySCB *info = new (std::nothrow) StartParamsBySCB();
    if (info == nullptr) {
        return nullptr;
    }

    if (!info->ReadFromParcel(parcel)) {
        delete info;
        info = nullptr;
    }
    return info;
}

bool StartParamsBySCB::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteUint32(sceneFlag)) {
        return false;
    }
    if (!parcel.WriteBool(isRestart)) {
        return false;
    }
    if (!parcel.WriteString(pageConfig)) {
        return false;
    }
    return true;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
