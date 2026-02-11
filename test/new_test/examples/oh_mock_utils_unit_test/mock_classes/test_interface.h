/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_TEST_INTERFACE_H
#define OHOS_ABILITY_RUNTIME_TEST_INTERFACE_H

#include "iremote_broker.h"
#include "iremote_object.h"
#include "refbase.h"
#include "oh_mock_utils.h"

namespace OHOS {
namespace TestMock {

/**
 * @class ITestInterface
 * @brief Test interface for sptr-related mock testing
 */
class ITestInterface : public IRemoteBroker {
public:
    virtual ~ITestInterface() = default;
    virtual int32_t GetData() = 0;
};

/**
 * @class MockTestInterfaceImpl
 * @brief Actual implementation of ITestInterface for testing
 */
class MockTestInterfaceImpl : public ITestInterface {
public:
    MockTestInterfaceImpl() = default;
    ~MockTestInterfaceImpl() override = default;

    int32_t GetData() override
    {
        return 0;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

/**
 * @class TestInterfaceImpl
 * @brief Mock implementation for testing OH_MOCK_METHOD_RET_SPTR and OH_MOCK_METHOD_RET_SPTR_WITH_DECORATOR
 */
class TestInterfaceImpl {
public:
    /**
     * @brief Mock getInstance method returning sptr<ITestInterface>
     */
    OH_MOCK_METHOD_RET_SPTR(sptr<ITestInterface>, TestInterfaceImpl, GetInstance);

    /**
     * @brief Mock static method with decorator returning sptr<ITestInterface>
     *        This demonstrates OH_MOCK_METHOD_RET_SPTR_WITH_DECORATOR usage
     * @param configId Configuration identifier
     * @return sptr<ITestInterface> Mocked interface instance based on config
     */
    OH_MOCK_METHOD_RET_SPTR_WITH_DECORATOR(static, sptr<ITestInterface>, TestInterfaceImpl,
        GetConfiguredInstance, const std::string&);

    /**
     * @brief Mock method to get data
     */
    OH_MOCK_METHOD(int32_t, TestInterfaceImpl, GetData);
};

} // namespace TestMock
} // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_TEST_INTERFACE_H
