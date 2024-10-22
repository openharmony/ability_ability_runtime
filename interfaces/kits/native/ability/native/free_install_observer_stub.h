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

#ifndef OHOS_ABILITY_RUNTIME_FREE_INSTALL_OBSERVER_STUB_H
#define OHOS_ABILITY_RUNTIME_FREE_INSTALL_OBSERVER_STUB_H

#include <map>

#include "iremote_stub.h"
#include "free_install_observer_interface.h"
#include "nocopyable.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @class FreeInstallObserverStub
 * IPC proxy of IFreeInstallObserver.
 */
class FreeInstallObserverStub : public IRemoteStub<IFreeInstallObserver> {
public:
    /**
     * FreeInstallObserverStub, constructor.
     *
     */
    FreeInstallObserverStub();

    /**
     * FreeInstallObserverStub, destructor.
     *
     */
    virtual ~FreeInstallObserverStub();

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
    DISALLOW_COPY_AND_MOVE(FreeInstallObserverStub);

    /**
     * OnInstallFinishedInner, inner processing method for OnInstallFinished.
     *
     * @param data The message parcel data.
     * @param reply The message parcel reply.
     * @return Error code of calling the function.
     */
    int OnInstallFinishedInner(MessageParcel &data, MessageParcel &reply);

    /**
     * OnInstallFinishedByUrlInner, inner processing method for OnInstallFinishedByUrl.
     *
     * @param data The message parcel data.
     * @param reply The message parcel reply.
     * @return Error code of calling the function.
     */
    int OnInstallFinishedByUrlInner(MessageParcel &data, MessageParcel &reply);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_FREE_INSTALL_OBSERVER_STUB_H