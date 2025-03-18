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

#ifndef ABILITY_MANAGER_SERVICE_TWELFTH_TEST_MOCK_TEST_OBJECT_H
#define ABILITY_MANAGER_SERVICE_TWELFTH_TEST_MOCK_TEST_OBJECT_H

#include "user_callback.h"
#include "ability_connect_callback_interface.h"

class MockIUserCallback : public OHOS::AAFwk::IUserCallback {
public:
    MockIUserCallback() = default;
    virtual ~MockIUserCallback() = default;
    virtual void OnStopUserDone(int userId, int errcode) override {}
    virtual void OnStartUserDone(int userId, int errcode) override {}
    virtual void OnLogoutUserDone(int userId, int errcode) override {}
    virtual OHOS::sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    }
};

class MockIAbilityConnection : public OHOS::AAFwk::IAbilityConnection {
public:
    MockIAbilityConnection() = default;
    virtual ~MockIAbilityConnection() = default;
    virtual void OnAbilityConnectDone(const OHOS::AppExecFwk::ElementName &element,
            const OHOS::sptr<IRemoteObject> &remoteObject, int resultCode) override {}
    virtual void OnAbilityDisconnectDone(const OHOS::AppExecFwk::ElementName &element, int resultCode) override {}
    virtual OHOS::sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};
#endif // ABILITY_MANAGER_SERVICE_TWELFTH_TEST_MOCK_TEST_OBJECT_H
