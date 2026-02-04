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

#include "ability_business_error.h"
#include "agent_connector_proxy.h"
#include "agent_connector_proxy_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AgentRuntime {
class AgentConnectorProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    sptr<MockRemoteObject> mockRemoteObject_{ nullptr };
    sptr<AgentConnectorProxy> proxy_{ nullptr };
};

void AgentConnectorProxyTest::SetUpTestCase(void)
{}
void AgentConnectorProxyTest::TearDownTestCase(void)
{}
void AgentConnectorProxyTest::SetUp()
{
    mockRemoteObject_ = new MockRemoteObject();
}
void AgentConnectorProxyTest::TearDown()
{
    mockRemoteObject_ = nullptr;
    proxy_ = nullptr;
}

/*
 * Feature: AgentConnectorProxy
 * Function: Constructor
 * SubFunction: NA
 * FunctionPoints: AgentConnectorProxy construction
 * EnvConditions: NA
 * CaseDescription: Verify that AgentConnectorProxy can be constructed successfully
 */
HWTEST_F(AgentConnectorProxyTest, AgentConnectorProxy_Constructor_001, TestSize.Level1)
{
    proxy_ = new AgentConnectorProxy(mockRemoteObject_);
    EXPECT_NE(proxy_, nullptr);
}

/*
 * Feature: AgentConnectorProxy
 * Function: SendData
 * SubFunction: NA
 * FunctionPoints: SendData with null remote object
 * EnvConditions: Remote object is null
 * CaseDescription: Verify that SendData returns error when remote object is null
 */
HWTEST_F(AgentConnectorProxyTest, AgentConnectorProxy_SendData_001, TestSize.Level1)
{
    sptr<IRemoteObject> nullObject = nullptr;
    proxy_ = new AgentConnectorProxy(nullObject);

    std::string testData = "test data";
    int32_t result = proxy_->SendData(testData);

    EXPECT_EQ(result, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER));
}

/*
 * Feature: AgentConnectorProxy
 * Function: SendData
 * SubFunction: NA
 * FunctionPoints: SendData with successful SendRequest
 * EnvConditions: Valid remote object
 * CaseDescription: Verify that SendData succeeds when SendRequest succeeds
 */
HWTEST_F(AgentConnectorProxyTest, AgentConnectorProxy_SendData_002, TestSize.Level1)
{
    EXPECT_CALL(*mockRemoteObject_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_OK));

    proxy_ = new AgentConnectorProxy(mockRemoteObject_);

    std::string testData = "test data";
    int32_t result = proxy_->SendData(testData);

    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: AgentConnectorProxy
 * Function: SendData
 * SubFunction: NA
 * FunctionPoints: SendData with failed SendRequest
 * EnvConditions: SendRequest returns error
 * CaseDescription: Verify that SendData returns error when SendRequest fails
 */
HWTEST_F(AgentConnectorProxyTest, AgentConnectorProxy_SendData_003, TestSize.Level1)
{
    EXPECT_CALL(*mockRemoteObject_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_INVALID_OPERATION));

    proxy_ = new AgentConnectorProxy(mockRemoteObject_);

    std::string testData = "test data";
    int32_t result = proxy_->SendData(testData);

    EXPECT_EQ(result, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER));
}

/*
 * Feature: AgentConnectorProxy
 * Function: SendData
 * SubFunction: NA
 * FunctionPoints: SendData with empty string
 * EnvConditions: Valid remote object
 * CaseDescription: Verify that SendData works with empty string
 */
HWTEST_F(AgentConnectorProxyTest, AgentConnectorProxy_SendData_004, TestSize.Level1)
{
    EXPECT_CALL(*mockRemoteObject_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_OK));

    proxy_ = new AgentConnectorProxy(mockRemoteObject_);

    std::string emptyData = "";
    int32_t result = proxy_->SendData(emptyData);

    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: AgentConnectorProxy
 * Function: SendData
 * SubFunction: NA
 * FunctionPoints: SendData with long string
 * EnvConditions: Valid remote object
 * CaseDescription: Verify that SendData works with long string
 */
HWTEST_F(AgentConnectorProxyTest, AgentConnectorProxy_SendData_005, TestSize.Level1)
{
    EXPECT_CALL(*mockRemoteObject_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_OK));

    proxy_ = new AgentConnectorProxy(mockRemoteObject_);

    std::string longData(10000, 'x');
    int32_t result = proxy_->SendData(longData);

    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: AgentConnectorProxy
 * Function: Authorize
 * SubFunction: NA
 * FunctionPoints: Authorize with null remote object
 * EnvConditions: Remote object is null
 * CaseDescription: Verify that Authorize returns error when remote object is null
 */
HWTEST_F(AgentConnectorProxyTest, AgentConnectorProxy_Authorize_001, TestSize.Level1)
{
    sptr<IRemoteObject> nullObject = nullptr;
    proxy_ = new AgentConnectorProxy(nullObject);

    std::string authData = "auth data";
    int32_t result = proxy_->Authorize(authData);

    EXPECT_EQ(result, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER));
}

/*
 * Feature: AgentConnectorProxy
 * Function: Authorize
 * SubFunction: NA
 * FunctionPoints: Authorize with successful SendRequest
 * EnvConditions: Valid remote object
 * CaseDescription: Verify that Authorize succeeds when SendRequest succeeds
 */
HWTEST_F(AgentConnectorProxyTest, AgentConnectorProxy_Authorize_002, TestSize.Level1)
{
    EXPECT_CALL(*mockRemoteObject_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_OK));

    proxy_ = new AgentConnectorProxy(mockRemoteObject_);

    std::string authData = "auth data";
    int32_t result = proxy_->Authorize(authData);

    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: AgentConnectorProxy
 * Function: Authorize
 * SubFunction: NA
 * FunctionPoints: Authorize with failed SendRequest
 * EnvConditions: SendRequest returns error
 * CaseDescription: Verify that Authorize returns error when SendRequest fails
 */
HWTEST_F(AgentConnectorProxyTest, AgentConnectorProxy_Authorize_003, TestSize.Level1)
{
    EXPECT_CALL(*mockRemoteObject_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_INVALID_OPERATION));

    proxy_ = new AgentConnectorProxy(mockRemoteObject_);

    std::string authData = "auth data";
    int32_t result = proxy_->Authorize(authData);

    EXPECT_EQ(result, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER));
}

/*
 * Feature: AgentConnectorProxy
 * Function: Authorize
 * SubFunction: NA
 * FunctionPoints: Authorize with empty string
 * EnvConditions: Valid remote object
 * CaseDescription: Verify that Authorize works with empty string
 */
HWTEST_F(AgentConnectorProxyTest, AgentConnectorProxy_Authorize_004, TestSize.Level1)
{
    EXPECT_CALL(*mockRemoteObject_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_OK));

    proxy_ = new AgentConnectorProxy(mockRemoteObject_);

    std::string emptyData = "";
    int32_t result = proxy_->Authorize(emptyData);

    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: AgentConnectorProxy
 * Function: Authorize
 * SubFunction: NA
 * FunctionPoints: Authorize with long string
 * EnvConditions: Valid remote object
 * CaseDescription: Verify that Authorize works with long string
 */
HWTEST_F(AgentConnectorProxyTest, AgentConnectorProxy_Authorize_005, TestSize.Level1)
{
    EXPECT_CALL(*mockRemoteObject_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_OK));

    proxy_ = new AgentConnectorProxy(mockRemoteObject_);

    std::string longData(10000, 'y');
    int32_t result = proxy_->Authorize(longData);

    EXPECT_EQ(result, ERR_OK);
}

} // namespace AgentRuntime
} // namespace OHOS
