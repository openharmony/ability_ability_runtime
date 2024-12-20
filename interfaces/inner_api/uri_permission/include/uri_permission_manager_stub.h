/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_URI_PERMISSION_MANAGER_STUB_H
#define OHOS_ABILITY_RUNTIME_URI_PERMISSION_MANAGER_STUB_H

#include <vector>

#include "iremote_stub.h"
#include "message_parcel.h"
#include "nocopyable.h"
#include "uri_permission_manager_interface.h"

namespace OHOS {
namespace AAFwk {
class UriPermissionManagerStub : public IRemoteStub<IUriPermissionManager> {
public:
    UriPermissionManagerStub() = default;
    virtual ~UriPermissionManagerStub() = default;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    DISALLOW_COPY_AND_MOVE(UriPermissionManagerStub);

    int HandleRevokeAllUriPermission(MessageParcel &data, MessageParcel &reply);
    int HandleGrantUriPermission(MessageParcel &data, MessageParcel &reply);
    int32_t HandleGrantUriPermissionPrivileged(MessageParcel &data, MessageParcel &reply);
    int32_t HandleCheckUriAuthorization(MessageParcel &data, MessageParcel &reply);
    int HandleBatchGrantUriPermission(MessageParcel &data, MessageParcel &reply);
    int HandleRevokeUriPermissionManually(MessageParcel &data, MessageParcel &reply);
    int HandleVerifyUriPermission(MessageParcel &data, MessageParcel &reply);
    int HandleClearPermissionTokenByMap(MessageParcel &data, MessageParcel &reply);
#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
    int HandleActive(MessageParcel &data, MessageParcel &reply);
#endif // ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_URI_PERMISSION_MANAGER_STUB_H
