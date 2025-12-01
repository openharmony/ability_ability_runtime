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

#ifndef OHOS_ABILITY_RUNTIME_CHECK_RESULT_H
#define OHOS_ABILITY_RUNTIME_CHECK_RESULT_H

#include <sys/types.h>
#include "parcel.h"

namespace OHOS {
namespace AAFwk {

struct CheckResult : public Parcelable {
    bool result = false;
    int32_t permissionType = 0;

    CheckResult() = default;

    CheckResult(bool res, int32_t type) : result(res), permissionType(type) {}

    virtual bool Marshalling(Parcel &parcel) const override
    {
        if (!parcel.WriteBool(result)) {
            return false;
        }
        if (!parcel.WriteInt32(permissionType)) {
            return false;
        }
        return true;
    }

    static CheckResult *Unmarshalling(Parcel &parcel)
    {
        CheckResult *checkResult = new (std::nothrow) CheckResult();
        if (checkResult == nullptr) {
            return nullptr;
        }
        checkResult->result = parcel.ReadBool();
        checkResult->permissionType = parcel.ReadInt32();
        return checkResult;
    }
};
}  // AAFwk
}  // OHOS
#endif  // OHOS_ABILITY_RUNTIME_CHECK_RESULT_H