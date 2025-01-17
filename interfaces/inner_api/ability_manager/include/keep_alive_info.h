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

#ifndef OHOS_ABILITY_RUNTIME_KEEP_ALIVE_INFO_H
#define OHOS_ABILITY_RUNTIME_KEEP_ALIVE_INFO_H

#include <string>

#include "parcel.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @class KeepAliveSetter
 * defines who sets the keep-alive flag for apps.
 */
enum class KeepAliveSetter : int32_t {
    UNSPECIFIED = -1,
    SYSTEM = 0,
    USER = 1,
};

/**
 * @class KeepAliveAppType
 * defines the app type.
 */
enum class KeepAliveAppType : int32_t {
    UNSPECIFIED = 0,
    THIRD_PARTY = 1,
    SYSTEM = 2,
};

/**
 * @struct KeepAliveInfo
 * Defines keep-alive info.
 */
struct KeepAliveInfo : public Parcelable {
public:
    int32_t userId = -1;
    KeepAliveAppType appType = KeepAliveAppType::UNSPECIFIED;
    KeepAliveSetter setter = KeepAliveSetter::UNSPECIFIED;
    std::string bundleName;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static KeepAliveInfo *Unmarshalling(Parcel &parcel);
};

struct KeepAliveStatus {
    int32_t code;
    KeepAliveSetter setter;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_KEEP_ALIVE_INFO_H