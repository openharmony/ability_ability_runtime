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

#include <gtest/gtest.h>
#include <singleton.h>
#include "ability_business_error.h"
#include "errors.h"
#include "hilog_wrapper.h"
#include "ui_service_proxy.h"
#include "ui_service_stub.h"
#include "ui_service_host_proxy.h"
#include "ui_service_host_stub.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AbilityRuntime {

class UIServiceStubImpl : public AAFwk::UIServiceStub {
public:
    UIServiceStubImpl() {}
    ~UIServiceStubImpl() = default;
    virtual int32_t SendData(sptr<IRemoteObject> hostProxy, OHOS::AAFwk::WantParams &data) override;

    bool HasDataReceived() const { return hasDataReceived_; }
protected:
    bool hasDataReceived_ = false;
};

int32_t UIServiceStubImpl::SendData(sptr<IRemoteObject> hostProxy, OHOS::AAFwk::WantParams &data)
{
    hasDataReceived_ = true;
    return 0;
}

class UIServiceHostStubImpl : public AAFwk::UIServiceHostStub {
public:
    UIServiceHostStubImpl() {}
    ~UIServiceHostStubImpl() = default;
    virtual int32_t SendData(OHOS::AAFwk::WantParams &data) override;

    bool HasDataReceived() const { return hasDataReceived_; }
protected:
    bool hasDataReceived_ = false;
};

int32_t UIServiceHostStubImpl::SendData(OHOS::AAFwk::WantParams &data)
{
    hasDataReceived_ = true;
    return 0;
}

class UiServiceExtensionConnectionTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void UiServiceExtensionConnectionTest::SetUpTestCase()
{
}

void UiServiceExtensionConnectionTest::TearDownTestCase()
{
}

void UiServiceExtensionConnectionTest::SetUp()
{
}

void UiServiceExtensionConnectionTest::TearDown()
{
}

HWTEST_F(UiServiceExtensionConnectionTest, ConnectionTest_0100, TestSize.Level1)
{
    OHOS::AAFwk::WantParams params;
    sptr<UIServiceHostStubImpl> hostStub = sptr<UIServiceHostStubImpl>::MakeSptr();
    sptr<UIServiceStubImpl> stub = sptr<UIServiceStubImpl>::MakeSptr();
    sptr<IUIService> proxy = iface_cast<IUIService>(stub->AsObject());
    proxy->SendData(hostStub->AsObject(), params);
    EXPECT_TRUE(stub->HasDataReceived());
}

HWTEST_F(UiServiceExtensionConnectionTest, ConnectionTest_0101, TestSize.Level1)
{
    OHOS::AAFwk::WantParams params;
    sptr<UIServiceHostStubImpl> stub = sptr<UIServiceHostStubImpl>::MakeSptr();
    sptr<IUIServiceHost> proxy = iface_cast<IUIServiceHost>(stub->AsObject());
    proxy->SendData(params);
    EXPECT_TRUE(stub->HasDataReceived());
}

}  // namespace AAFwk
}  // namespace OHOS