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

#include "ui_service_stub.h"
#include "ui_service_proxy.h"
#include "hilog_tag_wrapper.h"
#include "mock_ability_token.h"

using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace AbilityRuntime {
class MockUIServiceStubTest : public AAFwk::UIServiceStub {
public:
    MockUIServiceStubTest() = default;
    ~MockUIServiceStubTest() override = default;
    int32_t SendData(sptr<IRemoteObject> hostProxy, OHOS::AAFwk::WantParams &data) override
    {
        return 0;
    }
};
class UIServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    void WriteInterfaceToken(MessageParcel &data);
};

void UIServiceStubTest::SetUpTestCase(void)
{}

void UIServiceStubTest::TearDownTestCase(void)
{}

void UIServiceStubTest::SetUp()
{}

void UIServiceStubTest::TearDown()
{}

void UIServiceStubTest::WriteInterfaceToken(MessageParcel& data)
{
    data.WriteInterfaceToken(UIServiceStub::GetDescriptor());
}

/**
 * @tc.number: OnRemoteRequest_0100
 * @tc.name: OnRemoteRequest
 * @tc.desc: UIServiceStub OnRemoteRequest
 */
HWTEST_F(UIServiceStubTest, OnRemoteRequest_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnRemoteRequest_0100 start");
    std::shared_ptr<UIServiceStub> stub = std::make_shared<MockUIServiceStubTest>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    auto result = stub->OnRemoteRequest(IUIService::SEND_DATA, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_STATE);
    TAG_LOGI(AAFwkTag::TEST, "OnRemoteRequest_0100 end");
}

/**
 * @tc.number: OnRemoteRequest_0200
 * @tc.name: OnRemoteRequest
 * @tc.desc: UIServiceStub OnRemoteRequest
 */
HWTEST_F(UIServiceStubTest, OnRemoteRequest_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnRemoteRequest_0200 start");
    std::shared_ptr<UIServiceStub> stub = std::make_shared<MockUIServiceStubTest>();

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(UIServiceStub::GetDescriptor());

    AAFwk::Want want;
    const std::string name = "name";
    const std::string dataStr = "data";
    sptr<AppExecFwk::MockAbilityToken> token = new (std::nothrow) AppExecFwk::MockAbilityToken();
    data.WriteRemoteObject(token);
    data.WriteParcelable(&want);
    if (!data.WriteString(name)) {
        return;
    }
    if (!data.WriteString(dataStr)) {
        return;
    }

    int res = stub->OnRemoteRequest(IUIService::SEND_DATA, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "OnRemoteRequest_0200 end");
}

/**
 * @tc.number: OnSendData_0100
 * @tc.name: OnSendData
 * @tc.desc: UIServiceStub OnSendData
 */
HWTEST_F(UIServiceStubTest, OnSendData_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnSendData_0100 start");
    std::shared_ptr<UIServiceStub> stub = std::make_shared<MockUIServiceStubTest>();

    MessageParcel data;
    MessageParcel reply;

    data.WriteInterfaceToken(UIServiceStub::GetDescriptor());

    AAFwk::Want want;
    const std::string name = "name";
    const std::string dataStr = "data";
    sptr<AppExecFwk::MockAbilityToken> token = new (std::nothrow) AppExecFwk::MockAbilityToken();
    data.WriteRemoteObject(token);
    data.WriteParcelable(&want);
    if (!data.WriteString(name)) {
        return;
    }
    if (!data.WriteString(dataStr)) {
        return;
    }

    int res = stub->OnSendData(data, reply);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "OnSendData_0100 end");
}

/**
 * @tc.number: OnSendData_0200
 * @tc.name: OnSendData
 * @tc.desc: UIServiceStub OnSendData
 */
HWTEST_F(UIServiceStubTest, OnSendData_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnSendData_0200 start");
    std::shared_ptr<UIServiceStub> stub = std::make_shared<MockUIServiceStubTest>();

    MessageParcel data;
    MessageParcel reply;
    sptr<AppExecFwk::MockAbilityToken> token = new (std::nothrow) AppExecFwk::MockAbilityToken();
    data.WriteRemoteObject(token);
    
    data.WriteInterfaceToken(UIServiceStub::GetDescriptor());

    auto result = stub->OnSendData(data, reply);
    EXPECT_EQ(result, NO_ERROR);
    TAG_LOGI(AAFwkTag::TEST, "OnSendData_0200 end");
}
} // namespace AbilityRuntime
} // namespace OHOS
