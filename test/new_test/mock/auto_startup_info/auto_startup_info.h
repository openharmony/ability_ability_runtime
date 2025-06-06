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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_AUTO_STARTUP_INFO_H
#define MOCK_OHOS_ABILITY_RUNTIME_AUTO_STARTUP_INFO_H

#include <string>
#include "parcel.h"

namespace OHOS {
namespace AbilityRuntime {
struct AutoStartupInfo : public Parcelable {
public:
    int32_t appCloneIndex = 0;
    int32_t userId = -1;
    int32_t retryCount = 0;
    std::string bundleName;
    std::string abilityName;
    std::string moduleName;
    std::string abilityTypeName;
    std::string accessTokenId;
 
    bool ReadFromParcel(Parcel &parcel)
    {
        return false;
    }
    virtual bool Marshalling(Parcel &parcel) const override
    {
        return false;
    }
    static AutoStartupInfo *Unmarshalling(Parcel &parcel)
    {
        return nullptr;
    }
};

struct AutoStartupStatus {
    bool isAutoStartup = false;
    bool isEdmForce = false;
    int32_t code = -1;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_AUTO_STARTUP_INFO_H