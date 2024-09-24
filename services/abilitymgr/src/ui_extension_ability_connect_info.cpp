/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "ui_extension_ability_connect_info.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
bool UIExtensionAbilityConnectInfo::ReadFromParcel(Parcel &parcel)
{
    hostBundleName = parcel.ReadString();
    uiExtensionAbilityId = parcel.ReadInt32();
    return true;
}

UIExtensionAbilityConnectInfo *UIExtensionAbilityConnectInfo::Unmarshalling(Parcel &parcel)
{
    UIExtensionAbilityConnectInfo *connectInfo = new (std::nothrow) UIExtensionAbilityConnectInfo();
    if (connectInfo == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "new connect Info failed");
        return nullptr;
    }

    if (!connectInfo->ReadFromParcel(parcel)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "read connect info from parcel failed");
        delete connectInfo;
        return nullptr;
    }

    return connectInfo;
}

bool UIExtensionAbilityConnectInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(hostBundleName)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write hostBundleName failed");
        return false;
    }

    if (!parcel.WriteInt32(uiExtensionAbilityId)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write uiExtensionAbilityId failed");
        return false;
    }

    return true;
}
} // namespace AbilityRuntime
} // namespace OHOS
