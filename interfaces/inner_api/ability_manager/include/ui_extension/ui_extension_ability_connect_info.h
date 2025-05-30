/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_UI_EXTENSION_ABILITY_CONNECT_INFO_H
#define OHOS_ABILITY_RUNTIME_UI_EXTENSION_ABILITY_CONNECT_INFO_H

#include "parcel.h"

namespace OHOS {
namespace AbilityRuntime {
class UIExtensionAbilityConnectInfo : public Parcelable {
public:
    UIExtensionAbilityConnectInfo() = default;
    virtual ~UIExtensionAbilityConnectInfo() = default;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static UIExtensionAbilityConnectInfo *Unmarshalling(Parcel &parcel);

    std::string hostBundleName = "";  // The bundleName of uiextensionability user.
    int32_t uiExtensionAbilityId = 0; // The uiextensionability id.
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_UI_EXTENSION_ABILITY_CONNECT_INFO_H
