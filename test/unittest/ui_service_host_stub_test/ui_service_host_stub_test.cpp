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

#include "ui_service_host_stub.h"
#include "ui_service_host_proxy.h"
#include "hilog_tag_wrapper.h"

using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace AbilityRuntime {
class MockUIServiceHostStubTest : public UIServiceHostStub {
public:
    MockUIServiceHostStubTest() = default;
    ~MockUIServiceHostStubTest() override = default;
    int32_t SendData(OHOS::AAFwk::WantParams &data) override
    {
        return 0;
    }
};
class UIServiceHostStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    void WriteInterfaceToken(MessageParcel &data);
};

void UIServiceHostStubTest::SetUpTestCase(void)
{}

void UIServiceHostStubTest::TearDownTestCase(void)
{}

void UIServiceHostStubTest::SetUp()
{}

void UIServiceHostStubTest::TearDown()
{}

void UIServiceHostStubTest::WriteInterfaceToken(MessageParcel& data)
{
    data.WriteInterfaceToken(UIServiceHostStub::GetDescriptor());
}

/**
 * @tc.number: OnRemoteRequest_0100
 * @tc.name: OnRemoteRequest
 * @tc.desc: UIServiceHostStub OnRemoteRequest
 */
HWTEST_F(UIServiceHostStubTest, OnRemoteRequest_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnRemoteRequest_0100 start");
    std::shared_ptr<UIServiceHostStub> stub = std::make_shared<MockUIServiceHostStubTest>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    auto result = stub->OnRemoteRequest(IUIServiceHost::SEND_DATA, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_STATE);
    TAG_LOGI(AAFwkTag::TEST, "OnRemoteRequest_0100 end");
}

/**
 * @tc.number: OnRemoteRequest_0200
 * @tc.name: OnRemoteRequest
 * @tc.desc: UIServiceHostStub OnRemoteRequest
 */
HWTEST_F(UIServiceHostStubTest, OnRemoteRequest_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnRemoteRequest_0200 start");
    std::shared_ptr<UIServiceHostStub> stub = std::make_shared<MockUIServiceHostStubTest>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    AAFwk::Want want;
    const std::string name = "name";
    const std::string jsonPath = "jsonPath";
    const std::string dataStr = "data";
    const std::string extraData = "extraData";
    data.WriteInterfaceToken(UIServiceHostProxy::GetDescriptor());
    data.WriteParcelable(&want);

    if (!data.WriteString(name)) {
        return;
    }

    if (!data.WriteString(jsonPath)) {
        return;
    }
    if (!data.WriteString(dataStr)) {
        return;
    }
    if (!data.WriteString(extraData)) {
        return;
    }
    
    auto result = stub->OnRemoteRequest(IUIServiceHost::SEND_DATA, data, reply, option);
    EXPECT_EQ(result, NO_ERROR);
    TAG_LOGI(AAFwkTag::TEST, "OnRemoteRequest_0200 end");
}

/**
 * @tc.number: OnSendData_0100
 * @tc.name: OnSendData
 * @tc.desc: UIServiceHostStub OnSendData
 */
HWTEST_F(UIServiceHostStubTest, OnSendData_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnSendData_0100 start");
    std::shared_ptr<UIServiceHostStub> stub = std::make_shared<MockUIServiceHostStubTest>();

    MessageParcel data;
    MessageParcel reply;

    WriteInterfaceToken(data);
    
    auto result = stub->OnSendData(data, reply);
    EXPECT_EQ(result, NO_ERROR);
    TAG_LOGI(AAFwkTag::TEST, "OnSendData_0100 end");
}

/**
 * @tc.number: OnSendData_0200
 * @tc.name: OnSendData
 * @tc.desc: UIServiceHostStub OnSendData
 */
HWTEST_F(UIServiceHostStubTest, OnSendData_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnSendData_0200 start");
    std::shared_ptr<UIServiceHostStub> stub = std::make_shared<MockUIServiceHostStubTest>();

    MessageParcel data;
    MessageParcel reply;
    
    auto result = stub->OnSendData(data, reply);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "OnSendData_0200 end");
}
} // namespace AbilityRuntime
} // namespace OHOS
