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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_MOCK_APP_MGR_SERVICE_H
#define MOCK_OHOS_ABILITY_RUNTIME_MOCK_APP_MGR_SERVICE_H

#include <gtest/gtest.h>
#include "gmock/gmock.h"

#include "app_mgr_interface.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AppExecFwk {
class AppMgrStub : public IRemoteStub<IAppMgr> {
public:
    AppMgrStub() = default;
    virtual ~AppMgrStub() = default;

    virtual int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
    {
        return 0;
    }

private:
    DISALLOW_COPY_AND_MOVE(AppMgrStub);
};

class AppMgrProxy : public IRemoteProxy<IAppMgr> {
public:
    explicit AppMgrProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IAppMgr>(impl)
    {}

    virtual ~AppMgrProxy() = default;

private:
    DISALLOW_COPY_AND_MOVE(AppMgrProxy);
};

class MockAppMgrService : public AppMgrStub {};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // MOCK_OHOS_ABILITY_RUNTIME_MOCK_APP_MGR_SERVICE_H
