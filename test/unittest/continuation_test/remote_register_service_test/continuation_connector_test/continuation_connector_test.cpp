/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <chrono>
#include <thread>
#include <gtest/gtest.h>

#define private public
#define protected public
#include "ability.h"
#include "continuation_connector.h"
#include "remote_register_service_stub.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
using namespace std::chrono;

namespace OHOS {
namespace AppExecFwk {
class ContinuationConnectorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ContinuationConnectorTest::SetUpTestCase(void)
{}
void ContinuationConnectorTest::TearDownTestCase(void)
{}

void ContinuationConnectorTest::SetUp(void)
{}

void ContinuationConnectorTest::TearDown(void)
{}

class MockRegisterService : public RemoteRegisterServiceStub {
public:
    MockRegisterService() {};
    ~MockRegisterService() {};

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        GTEST_LOG_(INFO) << "MockRegisterService::SendRequest called. return value " << returnCode_;
        reply.WriteInt32(ERR_NONE);
        return returnCode_;
    }

    int Register(const std::string &bundleName, const sptr<IRemoteObject> &token, const ExtraParams &extras,
        const sptr<IConnectCallback> &callback) override
    {
        return register_;
    };
    bool Unregister(int registerToken) override
    {
        return unregister_;
    };
    bool UpdateConnectStatus(int registerToken, const std::string &deviceId, int status) override
    {
        return updateConnectStatus_;
    };
    bool ShowDeviceList(int registerToken, const ExtraParams &extras) override
    {
        return showDeviceList_;
    };

    sptr<IRemoteBroker> AsInterface() override
    {
        if (!asInterface_) {
            return nullptr;
        }

        return this;
    }

    int32_t returnCode_ = ERR_NONE;
    int32_t register_ = ERR_NONE;
    bool unregister_ = true;
    bool updateConnectStatus_ = true;
    bool showDeviceList_ = true;
    bool asInterface_ = true;
};

class MockRequest : public ContinuationRequest {
public:
    MockRequest() {};
    virtual ~MockRequest() {};

    void Execute() override
    {
        flag = true;
    };

    bool flag = false;
};

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: GetInstance
 * FunctionPoints: The parameter of function GetInstance.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function GetInstance register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_GetInstance_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_GetInstance_001 start.";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    EXPECT_TRUE(ability != nullptr);
    EXPECT_TRUE(ContinuationConnector::GetInstance(ability) != nullptr);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_GetInstance_001 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: GetInstance
 * FunctionPoints: The parameter of function GetInstance.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function GetInstance register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_GetInstance_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_GetInstance_002 start.";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    EXPECT_TRUE(ability != nullptr);
    EXPECT_TRUE(ContinuationConnector::GetInstance(ability) != nullptr);
    EXPECT_TRUE(ContinuationConnector::GetInstance(ability) != nullptr);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_GetInstance_002 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: OnAbilityConnectDone
 * FunctionPoints: The parameter of function OnAbilityConnectDone.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function OnAbilityConnectDone register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_OnAbilityConnectDone_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_OnAbilityConnectDone_001 start.";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    EXPECT_TRUE(ability != nullptr);
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    auto mockRequest = std::make_shared<MockRequest>();
    EXPECT_TRUE(mockRequest != nullptr);
    EXPECT_FALSE(mockRequest->flag);
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    testConnector->continuationRequestList_.push_back(mockRequest);
    AppExecFwk::ElementName element;
    constexpr int32_t registerToken = 0;
    testConnector->OnAbilityConnectDone(element, object, registerToken);
    EXPECT_TRUE(mockRequest->flag);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_OnAbilityConnectDone_001 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: OnAbilityConnectDone
 * FunctionPoints: The parameter of function OnAbilityConnectDone.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function OnAbilityConnectDone register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_OnAbilityConnectDone_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_OnAbilityConnectDone_002 start.";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    EXPECT_TRUE(ability != nullptr);
    sptr<MockRegisterService> object = nullptr;
    EXPECT_TRUE(object == nullptr);
    auto mockRequest = std::make_shared<MockRequest>();
    EXPECT_TRUE(mockRequest != nullptr);
    EXPECT_FALSE(mockRequest->flag);
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    testConnector->continuationRequestList_.push_back(mockRequest);
    AppExecFwk::ElementName element;
    constexpr int32_t registerToken = 0;
    testConnector->OnAbilityConnectDone(element, object, registerToken);
    EXPECT_FALSE(mockRequest->flag);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_OnAbilityConnectDone_002 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: OnAbilityConnectDone
 * FunctionPoints: The parameter of function OnAbilityConnectDone.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function OnAbilityConnectDone register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_OnAbilityConnectDone_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_OnAbilityConnectDone_003 start.";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    EXPECT_TRUE(ability != nullptr);
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    auto mockRequest = std::make_shared<MockRequest>();
    EXPECT_TRUE(mockRequest != nullptr);
    EXPECT_FALSE(mockRequest->flag);
    auto testConnector = ContinuationConnector::GetInstance(ability);
    EXPECT_TRUE(testConnector != nullptr);
    testConnector->continuationRequestList_.push_back(mockRequest);
    AppExecFwk::ElementName element;
    constexpr int32_t registerToken = 0;
    object->asInterface_ = false;
    testConnector->OnAbilityConnectDone(element, object, registerToken);
    EXPECT_FALSE(mockRequest->flag);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_OnAbilityConnectDone_003 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: OnAbilityConnectDone
 * FunctionPoints: The parameter of function OnAbilityConnectDone.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function OnAbilityConnectDone register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_OnAbilityConnectDone_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_OnAbilityConnectDone_004 start.";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    EXPECT_TRUE(ability != nullptr);
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    AppExecFwk::ElementName element;
    constexpr int32_t registerToken = 0;
    EXPECT_TRUE(testConnector->continuationRequestList_.size() == 0);
    testConnector->OnAbilityConnectDone(element, object, registerToken);
    EXPECT_TRUE(testConnector->continuationRequestList_.size() == 0);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_OnAbilityConnectDone_004 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: OnAbilityDisconnectDone
 * FunctionPoints: The parameter of function OnAbilityDisconnectDone.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function OnAbilityDisconnectDone register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_OnAbilityDisconnectDone_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_OnAbilityDisconnectDone_001 start.";
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    AppExecFwk::ElementName element;
    constexpr int32_t registerToken = 0;
    EXPECT_TRUE(testConnector->remoteRegisterService_ == nullptr);
    testConnector->OnAbilityDisconnectDone(element, registerToken);
    EXPECT_TRUE(testConnector->remoteRegisterService_ == nullptr);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_OnAbilityDisconnectDone_001 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: OnAbilityDisconnectDone
 * FunctionPoints: The parameter of function OnAbilityDisconnectDone.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function OnAbilityDisconnectDone register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_OnAbilityDisconnectDone_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_OnAbilityDisconnectDone_002 start.";
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    AppExecFwk::ElementName element;
    constexpr int32_t registerToken = 0;
    testConnector->remoteRegisterService_ = object;
    EXPECT_TRUE(testConnector->remoteRegisterService_ != nullptr);
    testConnector->OnAbilityDisconnectDone(element, registerToken);
    EXPECT_TRUE(testConnector->remoteRegisterService_ == nullptr);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_OnAbilityDisconnectDone_002 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: BindRemoteRegisterAbility
 * FunctionPoints: The parameter of function BindRemoteRegisterAbility.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function BindRemoteRegisterAbility register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_001 start.";
    auto mockRequest = std::make_shared<MockRequest>();
    EXPECT_TRUE(mockRequest != nullptr);
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    EXPECT_TRUE(ability != nullptr);
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    testConnector->isConnected_.store(false);
    EXPECT_FALSE(testConnector->isConnected_.load());
    GTEST_LOG_(INFO) << "continuationRequestList_.size is " << testConnector->continuationRequestList_.size();
    testConnector->BindRemoteRegisterAbility(mockRequest);
    GTEST_LOG_(INFO) << "continuationRequestList_.size is " << testConnector->continuationRequestList_.size();
    // EXPECT_TRUE(testConnector->continuationRequestList_.size() == 1);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_001 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: BindRemoteRegisterAbility
 * FunctionPoints: The parameter of function BindRemoteRegisterAbility.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function BindRemoteRegisterAbility register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_002 start.";
    auto mockRequest = std::make_shared<MockRequest>();
    EXPECT_TRUE(mockRequest != nullptr);
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    testConnector->BindRemoteRegisterAbility(mockRequest);
    EXPECT_TRUE(testConnector->continuationRequestList_.size() == 0);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_002 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: BindRemoteRegisterAbility
 * FunctionPoints: The parameter of function BindRemoteRegisterAbility.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function BindRemoteRegisterAbility register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_003 start.";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    EXPECT_TRUE(ability != nullptr);
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    testConnector->BindRemoteRegisterAbility(nullptr);
    EXPECT_TRUE(testConnector->continuationRequestList_.size() == 0);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_003 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: BindRemoteRegisterAbility
 * FunctionPoints: The parameter of function BindRemoteRegisterAbility.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function BindRemoteRegisterAbility register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_004 start.";
    auto mockRequest = std::make_shared<MockRequest>();
    EXPECT_TRUE(mockRequest != nullptr);
    EXPECT_FALSE(mockRequest->flag);
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    EXPECT_TRUE(ability != nullptr);
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    testConnector->isConnected_.store(true);
    EXPECT_TRUE(testConnector->isConnected_.load());
    testConnector->BindRemoteRegisterAbility(mockRequest);
    EXPECT_TRUE(testConnector->continuationRequestList_.size() == 0);
    EXPECT_TRUE(mockRequest->flag);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_004 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: UnbindRemoteRegisterAbility
 * FunctionPoints: The parameter of function UnbindRemoteRegisterAbility.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function UnbindRemoteRegisterAbility register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_UnbindRemoteRegisterAbility_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_UnbindRemoteRegisterAbility_001 start.";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    EXPECT_TRUE(ability != nullptr);
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    testConnector->isConnected_.store(true);
    EXPECT_TRUE(testConnector->isConnected_.load());
    testConnector->UnbindRemoteRegisterAbility();
    EXPECT_FALSE(testConnector->isConnected_.load());
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_UnbindRemoteRegisterAbility_001 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: UnbindRemoteRegisterAbility
 * FunctionPoints: The parameter of function UnbindRemoteRegisterAbility.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function UnbindRemoteRegisterAbility register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_UnbindRemoteRegisterAbility_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_UnbindRemoteRegisterAbility_002 start.";
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    testConnector->isConnected_.store(true);
    EXPECT_TRUE(testConnector->isConnected_.load());
    testConnector->UnbindRemoteRegisterAbility();
    EXPECT_TRUE(testConnector->isConnected_.load());
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_UnbindRemoteRegisterAbility_002 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: IsAbilityConnected
 * FunctionPoints: The parameter of function IsAbilityConnected.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function IsAbilityConnected register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_IsAbilityConnected_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_IsAbilityConnected_001 start.";
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    testConnector->isConnected_.store(true);
    EXPECT_TRUE(testConnector->IsAbilityConnected());
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_IsAbilityConnected_001 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: IsAbilityConnected
 * FunctionPoints: The parameter of function IsAbilityConnected.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function IsAbilityConnected register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_IsAbilityConnected_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_IsAbilityConnected_002 start.";
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    testConnector->isConnected_.store(false);
    EXPECT_FALSE(testConnector->IsAbilityConnected());
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_IsAbilityConnected_002 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: Unregister
 * FunctionPoints: The parameter of function Unregister.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function Unregister register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_Unregister_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Unregister_001 start.";
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    constexpr int32_t registerToken = 100;
    EXPECT_FALSE(testConnector->Unregister(registerToken));
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Unregister_001 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: Unregister
 * FunctionPoints: The parameter of function Unregister.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function Unregister register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_Unregister_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Unregister_002 start.";
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    constexpr int32_t registerToken = 100;
    object->unregister_ = false;
    testConnector->remoteRegisterService_ = object;
    EXPECT_TRUE(testConnector->remoteRegisterService_ != nullptr);
    EXPECT_FALSE(testConnector->Unregister(registerToken));
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Unregister_002 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: Unregister
 * FunctionPoints: The parameter of function Unregister.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function Unregister register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_Unregister_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Unregister_003 start.";
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    constexpr int32_t registerToken = 100;
    object->unregister_ = true;
    testConnector->remoteRegisterService_ = object;
    EXPECT_TRUE(testConnector->remoteRegisterService_ != nullptr);
    EXPECT_TRUE(testConnector->Unregister(registerToken));
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Unregister_003 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: UpdateConnectStatus
 * FunctionPoints: The parameter of function UpdateConnectStatus.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function UpdateConnectStatus register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_UpdateConnectStatus_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_UpdateConnectStatus_001 start.";
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    constexpr int32_t registerToken = 100;
    constexpr int32_t stage = 1;
    const std::string deviceId = "7001005458323933328a592135733900";
    EXPECT_TRUE(testConnector->remoteRegisterService_ == nullptr);
    EXPECT_FALSE(testConnector->UpdateConnectStatus(registerToken, deviceId, stage));
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_UpdateConnectStatus_001 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: UpdateConnectStatus
 * FunctionPoints: The parameter of function UpdateConnectStatus.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function UpdateConnectStatus register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_UpdateConnectStatus_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_UpdateConnectStatus_002 start.";
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    constexpr int32_t registerToken = 100;
    constexpr int32_t stage = 1;
    const std::string deviceId = "7001005458323933328a592135733900";
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    object->updateConnectStatus_ = false;
    testConnector->remoteRegisterService_ = object;
    EXPECT_TRUE(testConnector->remoteRegisterService_ != nullptr);
    EXPECT_FALSE(testConnector->UpdateConnectStatus(registerToken, deviceId, stage));
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_UpdateConnectStatus_002 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: UpdateConnectStatus
 * FunctionPoints: The parameter of function UpdateConnectStatus.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function UpdateConnectStatus register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_UpdateConnectStatus_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_UpdateConnectStatus_003 start.";
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    constexpr int32_t registerToken = 100;
    constexpr int32_t stage = 1;
    const std::string deviceId = "7001005458323933328a592135733900";
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    object->updateConnectStatus_ = true;
    testConnector->remoteRegisterService_ = object;
    EXPECT_TRUE(testConnector->remoteRegisterService_ != nullptr);
    EXPECT_TRUE(testConnector->UpdateConnectStatus(registerToken, deviceId, stage));
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_UpdateConnectStatus_003 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: ShowDeviceList
 * FunctionPoints: The parameter of function ShowDeviceList.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function ShowDeviceList register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_ShowDeviceList_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_ShowDeviceList_001 start.";
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    constexpr int32_t registerToken = 100;
    const ExtraParams extra = {};
    EXPECT_TRUE(testConnector->remoteRegisterService_ == nullptr);
    EXPECT_FALSE(testConnector->ShowDeviceList(registerToken, extra));
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_ShowDeviceList_001 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: ShowDeviceList
 * FunctionPoints: The parameter of function ShowDeviceList.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function ShowDeviceList register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_ShowDeviceList_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_ShowDeviceList_002 start.";
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    constexpr int32_t registerToken = 100;
    const ExtraParams extra = {};
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    object->showDeviceList_ = false;
    testConnector->remoteRegisterService_ = object;
    EXPECT_TRUE(testConnector->remoteRegisterService_ != nullptr);
    EXPECT_FALSE(testConnector->ShowDeviceList(registerToken, extra));
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_ShowDeviceList_002 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: ShowDeviceList
 * FunctionPoints: The parameter of function ShowDeviceList.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function ShowDeviceList register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_ShowDeviceList_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_ShowDeviceList_003 start.";
    std::shared_ptr<Ability> ability = nullptr;
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    constexpr int32_t registerToken = 100;
    const ExtraParams extra = {};
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    object->showDeviceList_ = true;
    testConnector->remoteRegisterService_ = object;
    EXPECT_TRUE(testConnector->remoteRegisterService_ != nullptr);
    EXPECT_TRUE(testConnector->ShowDeviceList(registerToken, extra));
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_ShowDeviceList_003 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: Register
 * FunctionPoints: The parameter of function Register.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function Register register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_Register_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Register_001 start.";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    EXPECT_TRUE(ability != nullptr);
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    // constexpr int32_t registerToken = 100;
    const std::string bundleName = "ABC";
    const ExtraParams extra = {};
    std::shared_ptr<IContinuationDeviceCallback> callback = nullptr;
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    ability->token_ = object;
    testConnector->remoteRegisterService_ = object;
    EXPECT_TRUE(testConnector->remoteRegisterService_ != nullptr);
    std::weak_ptr<Context> context = ability;
    EXPECT_EQ(testConnector->Register(context, bundleName, extra, callback), ERR_NONE);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Register_001 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: Register
 * FunctionPoints: The parameter of function Register.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function Register register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_Register_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Register_002 start.";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    EXPECT_TRUE(ability != nullptr);
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    // constexpr int32_t registerToken = 100;
    const std::string bundleName = "ABC";
    const ExtraParams extra = {};
    std::shared_ptr<IContinuationDeviceCallback> callback = nullptr;
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    ability->token_ = object;
    object->register_ = ERR_NONE - 1;
    testConnector->remoteRegisterService_ = object;
    EXPECT_TRUE(testConnector->remoteRegisterService_ != nullptr);
    std::weak_ptr<Context> context = ability;
    EXPECT_EQ(testConnector->Register(context, bundleName, extra, callback), ERR_NONE - 1);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Register_002 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: Register
 * FunctionPoints: The parameter of function Register.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function Register register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_Register_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Register_003 start.";
    std::shared_ptr<Ability> ability = nullptr;
    EXPECT_TRUE(ability == nullptr);
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    const std::string bundleName = "ABC";
    const ExtraParams extra = {};
    std::shared_ptr<IContinuationDeviceCallback> callback = nullptr;
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    ability->token_ = object;
    EXPECT_TRUE(ability->token_ != nullptr);
    testConnector->remoteRegisterService_ = object;
    EXPECT_TRUE(testConnector->remoteRegisterService_ != nullptr);
    std::weak_ptr<Context> context = ability;
    EXPECT_EQ(testConnector->Register(context, bundleName, extra, callback), -1);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Register_003 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: Register
 * FunctionPoints: The parameter of function Register.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function Register register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_Register_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Register_003 start.";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    EXPECT_TRUE(ability != nullptr);
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    const std::string bundleName = "ABC";
    const ExtraParams extra = {};
    std::shared_ptr<IContinuationDeviceCallback> callback = nullptr;
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    ability->token_ = object;
    EXPECT_TRUE(ability->token_ != nullptr);
    testConnector->remoteRegisterService_ = nullptr;
    EXPECT_TRUE(testConnector->remoteRegisterService_ == nullptr);
    std::weak_ptr<Context> context = ability;
    EXPECT_EQ(testConnector->Register(context, bundleName, extra, callback), -1);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Register_004 end.";
}

/*
 * Feature: AbilityManager
 * Function: ContinuationConnector
 * SubFunction: Register
 * FunctionPoints: The parameter of function Register.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function Register register parameter data
 */
HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_Register_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Register_004 start.";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    EXPECT_TRUE(ability != nullptr);
    auto testConnector = std::make_shared<ContinuationConnector>(ability);
    EXPECT_TRUE(testConnector != nullptr);
    const std::string bundleName = "ABC";
    const ExtraParams extra = {};
    std::shared_ptr<IContinuationDeviceCallback> callback = nullptr;
    sptr<MockRegisterService> object = new (std::nothrow) MockRegisterService();
    EXPECT_TRUE(object != nullptr);
    EXPECT_TRUE(ability->token_ == nullptr);
    testConnector->remoteRegisterService_ = object;
    EXPECT_TRUE(testConnector->remoteRegisterService_ == nullptr);
    std::weak_ptr<Context> context = ability;
    EXPECT_EQ(testConnector->Register(context, bundleName, extra, callback), -1);
    GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_Register_005 end.";
}

// /*
//  * Feature: AbilityManager
//  * Function: ContinuationConnector
//  * SubFunction: BindRemoteRegisterAbility
//  * FunctionPoints: The parameter of function BindRemoteRegisterAbility.
//  * EnvConditions: Can run ohos test framework
//  * CaseDescription: Verify function BindRemoteRegisterAbility register parameter data
//  */
// HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_005, TestSize.Level1)
// {
//     GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_005 start.";
//     std::shared_ptr<Ability> ability = std::make_shared<Ability>();
//     EXPECT_TRUE(ability != nullptr);
//     auto testConnector = std::make_shared<ContinuationConnector>(ability);
//     EXPECT_TRUE(testConnector != nullptr);
//     testConnector->BindRemoteRegisterAbility();
//     EXPECT_TRUE(testConnector->context_.lock() != nullptr);
//     GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_005 end.";
// }

// /*
//  * Feature: AbilityManager
//  * Function: ContinuationConnector
//  * SubFunction: BindRemoteRegisterAbility
//  * FunctionPoints: The parameter of function BindRemoteRegisterAbility.
//  * EnvConditions: Can run ohos test framework
//  * CaseDescription: Verify function BindRemoteRegisterAbility register parameter data
//  */
// HWTEST_F(ContinuationConnectorTest, AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_006, TestSize.Level1)
// {
//     GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_002 start.";
//     std::shared_ptr<Ability> ability = nullptr;
//     EXPECT_TRUE(ability != nullptr);
//     auto testConnector = std::make_shared<ContinuationConnector>(ability);
//     EXPECT_TRUE(testConnector != nullptr);
//     testConnector->BindRemoteRegisterAbility();
//     EXPECT_TRUE(testConnector->context_.lock() == nullptr);
//     GTEST_LOG_(INFO) << "AppExecFwk_ContinuationConnector_BindRemoteRegisterAbility_006 end.";
// }
}   // namespace AppExecFwk
}   // namespace OHOS