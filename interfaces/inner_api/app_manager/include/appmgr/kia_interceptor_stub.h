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

#ifndef OHOS_ABILITY_RUNTIME_KIA_INTERCEPTOR_STUB_H
#define OHOS_ABILITY_RUNTIME_KIA_INTERCEPTOR_STUB_H

#include "kia_interceptor_interface.h"

#include <iremote_object.h>
#include <iremote_stub.h>

namespace OHOS {
namespace AppExecFwk {
/**
 * @class KiaInterceptorStub
 * IPC stub of IKiaInterceptor.
 */
class KiaInterceptorStub : public IRemoteStub<IKiaInterceptor> {
public:
    /**
     * KiaInterceptorStub, constructor.
     *
     */
    KiaInterceptorStub();

    /**
     * KiaInterceptorStub, destructor.
     *
     */
    virtual ~KiaInterceptorStub();

    /**
     * OnRemoteRequest, IPC method.
     *
     * @param code The IPC code.
     * @param data The message parcel data.
     * @param reply The message parcel reply.
     * @param option The message parcel option.
     * @return Error code of calling the function.
     */
    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    /**
     * OnInterceptInner, inner processing method from KIA.
     *
     * @param data The message parcel data.
     * @param reply The message parcel reply.
     * @return Error code of calling the function.
     */
    int OnInterceptInner(MessageParcel &data, MessageParcel &reply);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_KIA_INTERCEPTOR_STUB_H
