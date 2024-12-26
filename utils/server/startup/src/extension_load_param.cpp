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

#include "extension_load_param.h"

namespace OHOS::AbilityRuntime {
bool ExtensionLoadParam::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(networkEnableFlags)) {
        return false;
    }
    if (!parcel.WriteBool(saEnableFlags)) {
        return false;
    }
    if (!parcel.WriteBool(strictMode)) {
        return false;
    }
    return true;
}

bool ExtensionLoadParam::ReadFromParcel(Parcel &parcel)
{
    networkEnableFlags = parcel.ReadBool();
    saEnableFlags = parcel.ReadBool();
    strictMode = parcel.ReadBool();
    return true;
}

ExtensionLoadParam *ExtensionLoadParam::Unmarshalling(Parcel &parcel)
{
    ExtensionLoadParam *param = new (std::nothrow) ExtensionLoadParam();
    if (param && !param->ReadFromParcel(parcel)) {
        delete param;
        param = nullptr;
    }
    return param;
}
}