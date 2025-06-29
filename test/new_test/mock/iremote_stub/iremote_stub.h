/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_OHOS_IPC_IREMOTE_STUB_H
#define MOCK_OHOS_IPC_IREMOTE_STUB_H

#include <string>
#include "iremote_broker.h"
#include "iremote_object.h"
 
namespace OHOS {
template <typename INTERFACE> class IRemoteStub : public IRemoteObject, public INTERFACE {
public:
    IRemoteStub() {}
    virtual ~IRemoteStub() = default;

    sptr<IRemoteObject> AsObject() override;
 
    sptr<IRemoteBroker> AsInterface() override;
};

template <typename INTERFACE> sptr<IRemoteBroker> IRemoteStub<INTERFACE>::AsInterface()
{
    return this;
}
 
template <typename INTERFACE> sptr<IRemoteObject> IRemoteStub<INTERFACE>::AsObject()
{
    return this;
}
} // namespace OHOS
#endif