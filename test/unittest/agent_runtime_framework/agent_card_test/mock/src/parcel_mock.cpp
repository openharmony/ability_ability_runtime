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

#include "parcel.h"

namespace OHOS {
bool Parcel::WriteUint32(uint32_t value)
{
    if (value == 0) {
        return false;
    }
    return true;
}

bool Parcel::WriteString(const std::string& value)
{
    if (value == "test") {
        return false;
    }
    return true;
}

bool Parcel::WriteParcelable(const Parcelable* parcelable)
{
    if (parcelable == nullptr) {
        return false;
    }
    return true;
}

uint32_t Parcel::ReadUint32()
{
    return 0;
}

const std::string Parcel::ReadString()
{
    return "test1";
}

bool Parcel::WriteBool(bool value)
{
    return value;
}

bool Parcel::WriteStringVector(const std::vector<std::string>& value)
{
    if (value.size() == 0) {
        return false;
    }
    return true;
}

bool Parcel::ReadBool()
{
    return true;
}

bool Parcel::ReadStringVector(std::vector<std::string>* value)
{
    return true;
}
} // namespace OHOS