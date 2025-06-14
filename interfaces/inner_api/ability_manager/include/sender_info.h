/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_SENDER_INFO_H
#define OHOS_ABILITY_RUNTIME_SENDER_INFO_H

#include <string>

#include "parcel.h"

#include "iremote_object.h"
#include "start_options.h"
#include "want.h"

#include "want_receiver_interface.h"

namespace OHOS {
namespace AAFwk {
struct SenderInfo : public Parcelable {
    int32_t code;
    sptr<IWantReceiver> finishedReceiver;
    sptr<StartOptions> startOptions;
    std::string resolvedType;
    std::string requiredPermission;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t operType = 0;
    int32_t uid = 0;
    uint32_t tokenId = 0;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    bool MarshallingInner(Parcel &parcel) const;
    static SenderInfo *Unmarshalling(Parcel &parcel);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_SENDER_INFO_H
