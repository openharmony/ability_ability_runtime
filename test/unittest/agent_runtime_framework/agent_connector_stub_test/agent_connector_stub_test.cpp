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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "agent_connector_stub.h"
#include "agent_connector_stub_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AgentRuntime {
class AgentConnectorStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    void WriteInterfaceToken(MessageParcel& data);

    sptr<AgentConnectorStubTestMock> stub_{ nullptr };
};

void AgentConnectorStubTest::SetUpTestCase(void)
{}
void AgentConnectorStubTest::TearDownTestCase(void)
{}
void AgentConnectorStubTest::SetUp()
{
    stub_ = new AgentConnectorStubTestMock();
}
void AgentConnectorStubTest::TearDown()
{
    stub_ = nullptr;
}

void AgentConnectorStubTest::WriteInterfaceToken(MessageParcel& data)
{
    data.WriteInterfaceToken(AgentConnectorStubTestMock::GetDescriptor());
}

/*
 * Feature: AgentConnectorStub
 * Function: Constructor
 * SubFunction: NA
 * FunctionPoints: AgentConnectorStub construction
 * EnvConditions: NA
 * CaseDescription: Verify that AgentConnectorStub can be constructed successfully
 */
HWTEST_F(AgentConnectorStubTest, AgentConnectorStub_Constructor_001, TestSize.Level1)
{
    sptr<AgentConnectorStubTestMock> stub = new AgentConnectorStubTestMock();
    EXPECT_NE(stub, nullptr);
}

/*
 * Feature: AgentConnectorStub
 * Function: OnRemoteRequest
 * SubFunction: NA
 * FunctionPoints: OnRemoteRequest with invalid descriptor
 * EnvConditions: Descriptor mismatch
 * CaseDescription: Verify that OnRemoteRequest returns ERR_INVALID_STATE with invalid descriptor
 */
HWTEST_F(AgentConnectorStubTest, AgentConnectorStub_OnRemoteRequest_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(u"invalid.descriptor");

    int result = stub_->OnRemoteRequest(IAgentConnector::SEND_DATA, data, reply, option);

    EXPECT_EQ(result, ERR_INVALID_STATE);
}

/*
 * Feature: AgentConnectorStub
 * Function: OnRemoteRequest
 * SubFunction: NA
 * FunctionPoints: OnRemoteRequest with unknown code
 * EnvConditions: Unknown command code
 * CaseDescription: Verify that OnRemoteRequest handles unknown code correctly
 */
HWTEST_F(AgentConnectorStubTest, AgentConnectorStub_OnRemoteRequest_002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    WriteInterfaceToken(data);

    int result = stub_->OnRemoteRequest(9999, data, reply, option);

    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/*
 * Feature: AgentConnectorStub
 * Function: OnRemoteRequest
 * SubFunction: SEND_DATA
 * FunctionPoints: OnRemoteRequest with SEND_DATA code
 * EnvConditions: Valid descriptor and data
 * CaseDescription: Verify that OnRemoteRequest handles SEND_DATA correctly
 */
HWTEST_F(AgentConnectorStubTest, AgentConnectorStub_OnRemoteRequest_003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    WriteInterfaceToken(data);
    data.WriteString("test data");

    int result = stub_->OnRemoteRequest(IAgentConnector::SEND_DATA, data, reply, option);

    EXPECT_EQ(result, NO_ERROR);
}

/*
 * Feature: AgentConnectorStub
 * Function: OnRemoteRequest
 * SubFunction: AUTHORIZE
 * FunctionPoints: OnRemoteRequest with AUTHORIZE code
 * EnvConditions: Valid descriptor and data
 * CaseDescription: Verify that OnRemoteRequest handles AUTHORIZE correctly
 */
HWTEST_F(AgentConnectorStubTest, AgentConnectorStub_OnRemoteRequest_004, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    WriteInterfaceToken(data);
    data.WriteString("auth data");

    int result = stub_->OnRemoteRequest(IAgentConnector::AUTHORIZE, data, reply, option);

    EXPECT_EQ(result, NO_ERROR);
}

/*
 * Feature: AgentConnectorStub
 * Function: OnSendData
 * SubFunction: NA
 * FunctionPoints: OnSendData with valid data
 * EnvConditions: Valid data parcel
 * CaseDescription: Verify that OnSendData returns NO_ERROR with valid data
 */
HWTEST_F(AgentConnectorStubTest, AgentConnectorStub_OnSendData_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;

    WriteInterfaceToken(data);
    data.WriteString("test data");

    int result = stub_->OnSendData(data, reply);

    EXPECT_EQ(result, NO_ERROR);
}

/*
 * Feature: AgentConnectorStub
 * Function: OnSendData
 * SubFunction: NA
 * FunctionPoints: OnSendData with empty string
 * EnvConditions: Valid data parcel with empty string
 * CaseDescription: Verify that OnSendData works with empty string
 */
HWTEST_F(AgentConnectorStubTest, AgentConnectorStub_OnSendData_003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;

    WriteInterfaceToken(data);
    data.WriteString("");

    int result = stub_->OnSendData(data, reply);

    EXPECT_EQ(result, NO_ERROR);
}

/*
 * Feature: AgentConnectorStub
 * Function: OnSendData
 * SubFunction: NA
 * FunctionPoints: OnSendData with long string
 * EnvConditions: Valid data parcel with long string
 * CaseDescription: Verify that OnSendData works with long string
 */
HWTEST_F(AgentConnectorStubTest, AgentConnectorStub_OnSendData_004, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;

    WriteInterfaceToken(data);
    std::string longData(10000, 'x');
    data.WriteString(longData);

    int result = stub_->OnSendData(data, reply);

    EXPECT_EQ(result, NO_ERROR);
}

/*
 * Feature: AgentConnectorStub
 * Function: OnAuthorize
 * SubFunction: NA
 * FunctionPoints: OnAuthorize with valid data
 * EnvConditions: Valid data parcel
 * CaseDescription: Verify that OnAuthorize returns NO_ERROR with valid data
 */
HWTEST_F(AgentConnectorStubTest, AgentConnectorStub_OnAuthorize_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;

    WriteInterfaceToken(data);
    data.WriteString("auth data");

    int result = stub_->OnAuthorize(data, reply);

    EXPECT_EQ(result, NO_ERROR);
}

/*
 * Feature: AgentConnectorStub
 * Function: OnAuthorize
 * SubFunction: NA
 * FunctionPoints: OnAuthorize with empty string
 * EnvConditions: Valid data parcel with empty string
 * CaseDescription: Verify that OnAuthorize works with empty string
 */
HWTEST_F(AgentConnectorStubTest, AgentConnectorStub_OnAuthorize_003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;

    WriteInterfaceToken(data);
    data.WriteString("");

    int result = stub_->OnAuthorize(data, reply);

    EXPECT_EQ(result, NO_ERROR);
}

/*
 * Feature: AgentConnectorStub
 * Function: OnAuthorize
 * SubFunction: NA
 * FunctionPoints: OnAuthorize with long string
 * EnvConditions: Valid data parcel with long string
 * CaseDescription: Verify that OnAuthorize works with long string
 */
HWTEST_F(AgentConnectorStubTest, AgentConnectorStub_OnAuthorize_004, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;

    WriteInterfaceToken(data);
    std::string longData(10000, 'y');
    data.WriteString(longData);

    int result = stub_->OnAuthorize(data, reply);

    EXPECT_EQ(result, NO_ERROR);
}

/*
 * Feature: AgentConnectorStub
 * Function: SendData (interface method)
 * SubFunction: NA
 * FunctionPoints: SendData implementation
 * EnvConditions: NA
 * CaseDescription: Verify that SendData returns correct error code
 */
HWTEST_F(AgentConnectorStubTest, AgentConnectorStub_SendData_001, TestSize.Level1)
{
    std::string testData = "test data";
    int result = stub_->SendData(testData);

    EXPECT_EQ(result, 0);
}

/*
 * Feature: AgentConnectorStub
 * Function: Authorize (interface method)
 * SubFunction: NA
 * FunctionPoints: Authorize implementation
 * EnvConditions: NA
 * CaseDescription: Verify that Authorize returns correct error code
 */
HWTEST_F(AgentConnectorStubTest, AgentConnectorStub_Authorize_001, TestSize.Level1)
{
    std::string authData = "auth data";
    int result = stub_->Authorize(authData);

    EXPECT_EQ(result, 0);
}

} // namespace AgentRuntime
} // namespace OHOS
