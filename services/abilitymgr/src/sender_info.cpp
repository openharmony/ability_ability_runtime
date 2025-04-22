/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "sender_info.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {
bool SenderInfo::ReadFromParcel(Parcel &parcel)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");

    code = parcel.ReadInt32();
    std::unique_ptr<Want> wantResquest(parcel.ReadParcelable<Want>());
    if (wantResquest == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null wantResquest");
        return false;
    }
    want = *wantResquest;
    resolvedType = Str16ToStr8(parcel.ReadString16());

    if (parcel.ReadBool()) {
        sptr<IRemoteObject> finishedReceiverResquest = (static_cast<MessageParcel*>(&parcel))->ReadRemoteObject();
        if (finishedReceiverResquest == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "null remote object");
            return false;
        }
        finishedReceiver = iface_cast<IWantReceiver>(finishedReceiverResquest);
        if (!finishedReceiver) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "null receiver");
            return false;
        }
    }
    requiredPermission = Str16ToStr8(parcel.ReadString16());
    if (parcel.ReadBool()) {
        startOptions = parcel.ReadParcelable<StartOptions>();
    }
    if (parcel.ReadBool()) {
        callerToken = (static_cast<MessageParcel*>(&parcel))->ReadRemoteObject();
        if (callerToken == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "null remote object");
            return false;
        }
    }
    return true;
}

SenderInfo *SenderInfo::Unmarshalling(Parcel &parcel)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");

    SenderInfo *info = new (std::nothrow) SenderInfo();
    if (info == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null senderInfo");
        return nullptr;
    }

    if (!info->ReadFromParcel(parcel)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ReadFromParcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool SenderInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(code)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write code failed");
        return false;
    }
    if (!parcel.WriteParcelable(&want)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write want failed");
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(resolvedType))) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write resolvedType failed");
        return false;
    }
    if (!parcel.WriteBool(finishedReceiver != nullptr)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write flag failed");
        return false;
    }
    if (finishedReceiver) {
        if (finishedReceiver->AsObject() == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "null object");
            return false;
        }
        if (!(static_cast<MessageParcel*>(&parcel))->WriteRemoteObject(finishedReceiver->AsObject())) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "write receiver failed");
            return false;
        }
    }
    if (!parcel.WriteString16(Str8ToStr16(requiredPermission))) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write requiredPermission failed");
        return false;
    }
    if (!parcel.WriteBool(startOptions != nullptr)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write flag failed");
        return false;
    }
    if (startOptions) {
        if (!parcel.WriteParcelable(startOptions)) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "write startOptions failed");
            return false;
        }
    }
    if (callerToken) {
        if (!parcel.WriteBool(true) ||
            !(static_cast<MessageParcel*>(&parcel))->WriteRemoteObject(callerToken)) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "write callerToken failed");
            return false;
        }
    }
    return true;
}
}  // namespace AAFwk
}  // namespace OHOS
