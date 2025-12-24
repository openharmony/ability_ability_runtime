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

#include "agent_card.h"

#include "hilog_tag_wrapper.h"
#include "string_ex.h"

namespace OHOS {
namespace AgentRuntime {
bool Provider::ReadFromParcel(Parcel &parcel)
{
    organization = parcel.ReadString();
    url = parcel.ReadString();
    return true;
}

bool Provider::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(organization)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write organization failed");
        return false;
    }
    if (!parcel.WriteString(url)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write url failed");
        return false;
    }
    return true;
}

Provider *Provider::Unmarshalling(Parcel &parcel)
{
    Provider *provider = new (std::nothrow) Provider();
    if (provider && !provider->ReadFromParcel(parcel)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "provider unmarshalling failed");
        delete provider;
        provider = nullptr;
    }
    return provider;
}

bool Capabilities::ReadFromParcel(Parcel &parcel)
{
    streaming = parcel.ReadBool();
    pushNotifications = parcel.ReadBool();
    stateTransitionHistory = parcel.ReadBool();
    return true;
}

bool Capabilities::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(streaming)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write streaming failed");
        return false;
    }
    if (!parcel.WriteBool(pushNotifications)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write pushNotifications failed");
        return false;
    }
    if (!parcel.WriteBool(stateTransitionHistory)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write stateTransitionHistory failed");
        return false;
    }
    return true;
}

Capabilities *Capabilities::Unmarshalling(Parcel &parcel)
{
    Capabilities *capabilities = new (std::nothrow) Capabilities();
    if (capabilities && !capabilities->ReadFromParcel(parcel)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "capabilities unmarshalling failed");
        delete capabilities;
        capabilities = nullptr;
    }
    return capabilities;
}

bool Authentication::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadStringVector(&schemes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "read schemes failed");
        return false;
    }
    credentials = parcel.ReadString();
    return true;
}

bool Authentication::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteStringVector(schemes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write schemes failed");
        return false;
    }
    if (!parcel.WriteString(credentials)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write credentials failed");
        return false;
    }
    return true;
}

Authentication *Authentication::Unmarshalling(Parcel &parcel)
{
    Authentication *authentication = new (std::nothrow) Authentication();
    if (authentication && !authentication->ReadFromParcel(parcel)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "authentication unmarshalling failed");
        delete authentication;
        authentication = nullptr;
    }
    return authentication;
}

bool Skill::ReadFromParcel(Parcel &parcel)
{
    id = parcel.ReadString();
    name = parcel.ReadString();
    description = parcel.ReadString();
    if (!parcel.ReadStringVector(&tags)) {
        return false;
    }
    if (!parcel.ReadStringVector(&examples)) {
        return false;
    }
    if (!parcel.ReadStringVector(&inputModes)) {
        return false;
    }
    if (!parcel.ReadStringVector(&outputModes)) {
        return false;
    }
    return true;
}

bool Skill::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(id)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write id failed");
        return false;
    }
    if (!parcel.WriteString(name)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write name failed");
        return false;
    }
    if (!parcel.WriteString(description)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write description failed");
        return false;
    }
    if (!parcel.WriteStringVector(tags)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write tags failed");
        return false;
    }
    if (!parcel.WriteStringVector(examples)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write examples failed");
        return false;
    }
    if (!parcel.WriteStringVector(inputModes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write inputModes failed");
        return false;
    }
    if (!parcel.WriteStringVector(outputModes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write outputModes failed");
        return false;
    }
    return true;
}

Skill *Skill::Unmarshalling(Parcel &parcel)
{
    Skill *skill = new (std::nothrow) Skill();
    if (skill && !skill->ReadFromParcel(parcel)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "skill unmarshalling failed");
        delete skill;
        skill = nullptr;
    }
    return skill;
}
} // namespace AgentRuntime
} // namespace OHOS