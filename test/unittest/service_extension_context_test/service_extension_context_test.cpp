/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#define private public
#include "ability_manager_client.h"
#include "service_extension_context.h"
#undef private

#include "ability_connection.h"
#include "ability_manager_stub_mock.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AbilityRuntime {
class ServiceExtensionContextTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ServiceExtensionContextTest::SetUpTestCase(void)
{}
void ServiceExtensionContextTest::TearDownTestCase(void)
{}
void ServiceExtensionContextTest::SetUp(void)
{}
void ServiceExtensionContextTest::TearDown(void)
{}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest startAbility
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_startAbility_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    Want want;
    ErrCode result = serviceExtensionContextTest.StartAbility(want);
    EXPECT_NE(ERR_OK, result);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest startAbility
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_startAbility_002, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    Want want;
    StartOptions startOptions;
    ErrCode result = serviceExtensionContextTest.StartAbility(want, startOptions);
    EXPECT_NE(ERR_OK, result);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest StartAbilityAsCaller
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_StartAbilityAsCaller_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    Want want;
    ErrCode result = serviceExtensionContextTest.StartAbilityAsCaller(want);
    GTEST_LOG_(INFO) << result;
    EXPECT_NE(ERR_OK, result);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest StartAbilityAsCaller
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_StartAbilityAsCaller_002, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    Want want;
    StartOptions startOptions;
    ErrCode result = serviceExtensionContextTest.StartAbilityAsCaller(want, startOptions);
    GTEST_LOG_(INFO) << result;
    EXPECT_NE(ERR_OK, result);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest startAbility
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_StartAbilityByCall_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    Want want;
    std::shared_ptr<CallerCallBack> callback = std::make_shared<CallerCallBack>();
    ErrCode result = serviceExtensionContextTest.StartAbilityByCall(want, callback);
    EXPECT_EQ(ERR_INVALID_VALUE, result);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest startAbility
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_ReleaseCall_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    std::shared_ptr<CallerCallBack> callback = std::make_shared<CallerCallBack>();
    ErrCode result = serviceExtensionContextTest.ReleaseCall(callback);
    EXPECT_EQ(ERR_INVALID_VALUE, result);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest startAbility
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_ConnectAbility_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    Want want;
    sptr<AbilityConnectCallback> connectCallback;
    ErrCode result = serviceExtensionContextTest.ConnectAbility(want, connectCallback);
    EXPECT_EQ(AAFwk::ERR_INVALID_CALLER, result);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest startAbility
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_StartAbilityWithAccount_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    Want want;
    int accountId = 1;
    ErrCode result = serviceExtensionContextTest.StartAbilityWithAccount(want, accountId);
    EXPECT_EQ(CHECK_PERMISSION_FAILED, result);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest startAbility
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_StartAbilityWithAccount_002, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    Want want;
    int accountId = 1;
    StartOptions startOptions;
    ErrCode result = serviceExtensionContextTest.StartAbilityWithAccount(want, accountId, startOptions);
    EXPECT_EQ(CHECK_PERMISSION_FAILED, result);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest StartUIAbilities
 * EnvConditions: NA
 * CaseDescription: Verify StartUIAbilities
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_StartUIAbilities_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    std::vector<AAFwk::Want> wantList(5);
    std::string requestKey = "123";
    ErrCode result = serviceExtensionContextTest.StartUIAbilities(wantList, requestKey);
    EXPECT_NE(result, ERR_OK);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest StartServiceExtensionAbility
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_StartServiceExtensionAbility_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    Want want;
    int32_t accountId = 1;
    StartOptions startOptions;
    ErrCode result = serviceExtensionContextTest.StartServiceExtensionAbility(want, accountId);
    EXPECT_EQ(CHECK_PERMISSION_FAILED, result);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest StopServiceExtensionAbility
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_StopServiceExtensionAbility_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    Want want;
    int32_t accountId = 1;
    StartOptions startOptions;
    ErrCode result = serviceExtensionContextTest.StopServiceExtensionAbility(want, accountId);
    EXPECT_EQ(CHECK_PERMISSION_FAILED, result);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest ConnectAbilityWithAccount
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_ConnectAbilityWithAccount_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    Want want;
    int32_t accountId = 1;
    sptr<AbilityConnectCallback> connectCallback;
    ErrCode result = serviceExtensionContextTest.ConnectAbilityWithAccount(want, accountId, connectCallback);
    EXPECT_EQ(AAFwk::ERR_INVALID_CALLER, result);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest ConnectAbilityWithAccount
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_DisconnectAbility_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    Want want;
    int32_t accountId = 1;
    sptr<AbilityConnectCallback> connectCallback;
    ErrCode result = serviceExtensionContextTest.DisconnectAbility(want, connectCallback, accountId);
    GTEST_LOG_(INFO) <<result;
    EXPECT_EQ(AAFwk::ERR_INVALID_CALLER, result);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest TerminateAbility
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_TerminateAbility_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    ErrCode result = serviceExtensionContextTest.TerminateAbility();
    EXPECT_EQ(ERR_INVALID_VALUE, result);
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest RequestModalUIExtension
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_RequestModalUIExtension_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    Want want;
    ErrCode result = serviceExtensionContextTest.RequestModalUIExtension(want);
    EXPECT_EQ(serviceExtensionContextTest.localCallContainer_, nullptr);
    GTEST_LOG_(INFO) <<result;
}

/*
 * Feature: ServiceExtensionContext
 * Function: startAbility
 * SubFunction: NA
 * FunctionPoints: ServiceExtensionContextTest GetAbilityInfoType
 * EnvConditions: NA
 * CaseDescription: Verify startAbility
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_GetAbilityInfoType_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    EXPECT_EQ(AppExecFwk::AbilityType::UNKNOWN, serviceExtensionContextTest.GetAbilityInfoType());
}

/**
 * @tc.number: service_extension_context_startAbility_003
 * @tc.name: StartAbility
 * @tc.desc: Start ability success
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_startAbility_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "service_extension_context_startAbility_003 start";
    ServiceExtensionContext serviceExtensionContextTest;
    sptr<AAFwk::AbilityManagerStubTestMock> mock = new AAFwk::AbilityManagerStubTestMock();
    AAFwk::AbilityManagerClient::GetInstance()->proxy_ = mock;

    AAFwk::Want want;
    AppExecFwk::ElementName element("device", "com.ix.hiMusic", "MusicAbility");
    want.SetElement(element);
    auto ret = serviceExtensionContextTest.StartAbility(want);
    EXPECT_EQ(ret, ERR_OK);
    AAFwk::AbilityManagerClient::GetInstance()->proxy_ = nullptr;
    GTEST_LOG_(INFO) << "service_extension_context_startAbility_003 end";
}

/**
 * @tc.number: service_extension_context_StartAbilityWithAccount_003
 * @tc.name: StartAbility
 * @tc.desc: Start ability with Account success
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_StartAbilityWithAccount_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "service_extension_context_StartAbilityWithAccount_003 start";
    ServiceExtensionContext serviceExtensionContextTest;
    sptr<AAFwk::AbilityManagerStubTestMock> mock = new AAFwk::AbilityManagerStubTestMock();
    AAFwk::AbilityManagerClient::GetInstance()->proxy_ = mock;

    AAFwk::Want want;
    AppExecFwk::ElementName element("device", "com.ix.hiMusic", "MusicAbility");
    want.SetElement(element);
    int32_t accountId = 1;

    auto ret = serviceExtensionContextTest.StartAbilityWithAccount(want, accountId);
    EXPECT_EQ(ret, ERR_OK);
    AAFwk::AbilityManagerClient::GetInstance()->proxy_ = nullptr;
    GTEST_LOG_(INFO) << "service_extension_context_StartAbilityWithAccount_003 end";
}

/**
 * @tc.number: service_extension_context_StartServiceExtensionAbility_002
 * @tc.name: StartAbility
 * @tc.desc: Start service extension ability success
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_StartServiceExtensionAbility_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "service_extension_context_StartServiceExtensionAbility_002 start";
    ServiceExtensionContext serviceExtensionContextTest;
    sptr<AAFwk::AbilityManagerStubTestMock> mock = new AAFwk::AbilityManagerStubTestMock();
    AAFwk::AbilityManagerClient::GetInstance()->proxy_ = mock;

    AAFwk::Want want;
    AppExecFwk::ElementName element("device", "com.ix.hiMusic", "MusicAbility");
    want.SetElement(element);
    int32_t accountId = 1;

    auto ret = serviceExtensionContextTest.StartServiceExtensionAbility(want, accountId);
    EXPECT_EQ(ret, ERR_OK);
    AAFwk::AbilityManagerClient::GetInstance()->proxy_ = nullptr;
    GTEST_LOG_(INFO) << "service_extension_context_StartServiceExtensionAbility_002 end";
}

/**
 * @tc.number: service_extension_context_StopServiceExtensionAbility_002
 * @tc.name: StopServiceExtensionAbility
 * @tc.desc: Stop service extension ability success
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_StopServiceExtensionAbility_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "service_extension_context_StopServiceExtensionAbility_002 start";
    ServiceExtensionContext serviceExtensionContextTest;
    sptr<AAFwk::AbilityManagerStubTestMock> mock = new AAFwk::AbilityManagerStubTestMock();
    AAFwk::AbilityManagerClient::GetInstance()->proxy_ = mock;

    AAFwk::Want want;
    AppExecFwk::ElementName element("device", "com.ix.hiMusic", "MusicAbility");
    want.SetElement(element);
    int32_t accountId = 1;

    auto ret = serviceExtensionContextTest.StopServiceExtensionAbility(want, accountId);
    EXPECT_EQ(ret, ERR_OK);
    AAFwk::AbilityManagerClient::GetInstance()->proxy_ = nullptr;
    GTEST_LOG_(INFO) << "service_extension_context_StopServiceExtensionAbility_002 end";
}

/**
 * @tc.number: service_extension_context_TerminateAbility_002
 * @tc.name: TerminateAbility
 * @tc.desc: Terminate ability success
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_TerminateAbility_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "service_extension_context_TerminateAbility_002 start";
    ServiceExtensionContext serviceExtensionContextTest;
    sptr<AAFwk::AbilityManagerStubTestMock> mock = new AAFwk::AbilityManagerStubTestMock();
    AAFwk::AbilityManagerClient::GetInstance()->proxy_ = mock;

    auto ret = serviceExtensionContextTest.TerminateAbility();
    EXPECT_EQ(ret, ERR_OK);
    AAFwk::AbilityManagerClient::GetInstance()->proxy_ = nullptr;
    GTEST_LOG_(INFO) << "service_extension_context_TerminateAbility_002 end";
}

/**
 * @tc.number: service_extension_context_ClearFailedCallConnection_001
 * @tc.name: ClearFailedCallConnection
 * @tc.desc: clear failed call connection execute normally
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_ClearFailedCallConnection_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "service_extension_context_ClearFailedCallConnection_001 start";
    ServiceExtensionContext serviceExtensionContextTest;
    serviceExtensionContextTest.ClearFailedCallConnection(nullptr);
    EXPECT_EQ(serviceExtensionContextTest.localCallContainer_, nullptr);
    serviceExtensionContextTest.localCallContainer_ = std::make_shared<LocalCallContainer>();
    serviceExtensionContextTest.ClearFailedCallConnection(nullptr);
    EXPECT_NE(serviceExtensionContextTest.localCallContainer_, nullptr);
    GTEST_LOG_(INFO) << "service_extension_context_ClearFailedCallConnection_001 end";
}

/**
 * @tc.number: service_extension_context_StartUIServiceExtensionAbility_001
 * @tc.name: StartUIServiceExtensionAbility
 * @tc.desc: Start ui service extension ability success
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_StartUIServiceExtensionAbility_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    Want want;
    int32_t accountId = 1;
    StartOptions startOptions;
    ErrCode result = serviceExtensionContextTest.StartUIServiceExtensionAbility(want, accountId);
    EXPECT_NE(ERR_OK, result);
}

/**
 * @tc.number: service_extension_context_StartUIServiceExtensionAbility_002
 * @tc.name: StartUIServiceExtensionAbility
 * @tc.desc: Start ui service extension ability success
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_StartUIServiceExtensionAbility_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "service_extension_context_StartUIServiceExtensionAbility_002 start";
    ServiceExtensionContext serviceExtensionContextTest;
    sptr<AAFwk::AbilityManagerStubTestMock> mock = new AAFwk::AbilityManagerStubTestMock();
    AAFwk::AbilityManagerClient::GetInstance()->proxy_ = mock;

    AAFwk::Want want;
    AppExecFwk::ElementName element("device", "com.ix.hiMusic", "MusicAbility");
    want.SetElement(element);
    int32_t accountId = 1;

    auto ret = serviceExtensionContextTest.StartUIServiceExtensionAbility(want, accountId);
    EXPECT_EQ(ret, ERR_OK);
    AAFwk::AbilityManagerClient::GetInstance()->proxy_ = nullptr;
    GTEST_LOG_(INFO) << "service_extension_context_StartUIServiceExtensionAbility_002 end";
}

/**
 * @tc.number: service_extension_context_ReleaseCall_002
 * @tc.name: ReleaseCall
 * @tc.desc: Start ui service extension ability success
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_ReleaseCall_002, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    serviceExtensionContextTest.localCallContainer_ = std::make_shared<LocalCallContainer>();

    auto result = serviceExtensionContextTest.ReleaseCall(nullptr);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/**
 * @tc.number: service_extension_context_GetAbilityInfoType_002
 * @tc.name: GetAbilityInfoType
 * @tc.desc: Start ui service extension ability success
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_GetAbilityInfoType_002, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    serviceExtensionContextTest.abilityInfo_ = std::make_shared<OHOS::AppExecFwk::AbilityInfo>();
    serviceExtensionContextTest.abilityInfo_->type = AppExecFwk::AbilityType::SERVICE;

    auto result = serviceExtensionContextTest.GetAbilityInfoType();
    EXPECT_EQ(result, AppExecFwk::AbilityType::SERVICE);
}

/**
 * @tc.number: service_extension_context_AddFreeInstallObserver_002
 * @tc.name: AddFreeInstallObserver
 * @tc.desc: Start ui service extension ability success
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_AddFreeInstallObserver_002, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    MessageParcel data;
    sptr<AbilityRuntime::IFreeInstallObserver> observer =
        iface_cast<AbilityRuntime::IFreeInstallObserver>(data.ReadRemoteObject());

    auto result = serviceExtensionContextTest.AddFreeInstallObserver(nullptr);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: service_extension_context_PreStartMission_001
 * @tc.name: PreStartMission
 * @tc.desc: Start ui service extension ability success
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_PreStartMission_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;

    auto result = serviceExtensionContextTest.PreStartMission("", "", "", "");
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: service_extension_context_OpenAtomicService_001
 * @tc.name: OpenAtomicService
 * @tc.desc: Start ui service extension ability success
 */
HWTEST_F(ServiceExtensionContextTest, service_extension_context_OpenAtomicService_001, TestSize.Level1)
{
    ServiceExtensionContext serviceExtensionContextTest;
    AAFwk::Want want;
    AAFwk::StartOptions options;

    auto result = serviceExtensionContextTest.OpenAtomicService(want, options);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: AddCompletionHandlerForAtomicService_0100
 * @tc.name: AddCompletionHandlerForAtomicService
 * @tc.desc: Verify that function AddCompletionHandlerForAtomicService.
 */
HWTEST_F(ServiceExtensionContextTest, AddCompletionHandlerForAtomicService_100, Function | MediumTest | Level1)
{
    std::string requestId = "1234567890";
    std::string appId = "atomic";
    OnAtomicRequestSuccess onRequestSucc = nullptr;
    OnAtomicRequestFailure onRequestFail = nullptr;
    ServiceExtensionContext serviceExtensionContextTest;
    auto result = serviceExtensionContextTest.AddCompletionHandlerForAtomicService(
        requestId, onRequestSucc, onRequestFail, appId);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    EXPECT_EQ(serviceExtensionContextTest.onAtomicRequestResults_.empty(), true);
}

/**
 * @tc.number: AddCompletionHandlerForAtomicService_0200
 * @tc.name: AddCompletionHandlerForAtomicService
 * @tc.desc: Verify that function AddCompletionHandlerForAtomicService.
 */
HWTEST_F(ServiceExtensionContextTest, AddCompletionHandlerForAtomicService_0200, Function | MediumTest | Level1)
{
    std::string requestId = "1234567890";
    std::string appId = "atomic";
    OnAtomicRequestSuccess onRequestSucc = [](const std::string&) {};
    OnAtomicRequestFailure onRequestFail = nullptr;
    ServiceExtensionContext serviceExtensionContextTest;
    auto result = serviceExtensionContextTest.AddCompletionHandlerForAtomicService(
        requestId, onRequestSucc, onRequestFail, appId);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    EXPECT_EQ(serviceExtensionContextTest.onAtomicRequestResults_.empty(), true);
}

/**
 * @tc.number: AddCompletionHandlerForAtomicService_0300
 * @tc.name: AddCompletionHandlerForAtomicService
 * @tc.desc: Verify that function AddCompletionHandlerForAtomicService.
 */
HWTEST_F(ServiceExtensionContextTest, AddCompletionHandlerForAtomicService_0300, Function | MediumTest | Level1)
{
    std::string requestId = "1234567890";
    std::string appId = "atomic";
    OnAtomicRequestSuccess onRequestSucc = [](const std::string&) {};
    OnAtomicRequestFailure onRequestFail = [](const std::string&, int32_t, const std::string&) {};
    ServiceExtensionContext serviceExtensionContextTest;
    auto result = serviceExtensionContextTest.AddCompletionHandlerForAtomicService(
        requestId, onRequestSucc, onRequestFail, appId);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(serviceExtensionContextTest.onAtomicRequestResults_.empty(), false);
    serviceExtensionContextTest.onAtomicRequestResults_.clear();
}

/**
 * @tc.number: AddCompletionHandlerForAtomicService_0400
 * @tc.name: AddCompletionHandlerForAtomicService
 * @tc.desc: Verify that function AddCompletionHandlerForAtomicService.
 */
HWTEST_F(ServiceExtensionContextTest, AddCompletionHandlerForAtomicService_0400, Function | MediumTest | Level1)
{
    std::string requestId = "1234567890";
    std::string appId = "atomic";
    OnAtomicRequestSuccess onRequestSucc = [](const std::string&) {};
    OnAtomicRequestFailure onRequestFail = [](const std::string&, int32_t, const std::string&) {};
    ServiceExtensionContext serviceExtensionContextTest;
    std::string norequestId = "test";
    serviceExtensionContextTest.onAtomicRequestResults_.clear();
    serviceExtensionContextTest.onAtomicRequestResults_.emplace_back(
        std::make_shared<OnAtomicRequestResult>(requestId, appId, onRequestSucc, onRequestFail));
    auto result = serviceExtensionContextTest.AddCompletionHandlerForAtomicService(
        requestId, onRequestSucc, onRequestFail, appId);
    EXPECT_EQ(result, ERR_OK);
    result = serviceExtensionContextTest.AddCompletionHandlerForAtomicService(
        norequestId, onRequestSucc, onRequestFail, appId);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(serviceExtensionContextTest.onAtomicRequestResults_.size(), 2);
    serviceExtensionContextTest.onAtomicRequestResults_.clear();
}

/**
 * @tc.number: OnRequestSuccess_0100
 * @tc.name: OnRequestSuccess
 * @tc.desc: Verify that function OnRequestSuccess.
 */
HWTEST_F(ServiceExtensionContextTest, OnRequestSuccess_0100, Function | MediumTest | Level1)
{
    std::string requestId = "1234567890";
    std::string appId = "atomic";
    OnAtomicRequestSuccess onRequestSucc = [](const std::string&) {};
    OnAtomicRequestFailure onRequestFail = [](const std::string&, int32_t, const std::string&) {};
    ServiceExtensionContext serviceExtensionContextTest;
    auto result = serviceExtensionContextTest.AddCompletionHandlerForAtomicService(
        requestId, onRequestSucc, onRequestFail, appId);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(serviceExtensionContextTest.onAtomicRequestResults_.empty(), false);
    AppExecFwk::ElementName element("", "com.example.com", "MainAbility");
    serviceExtensionContextTest.OnRequestSuccess(requestId, element, "success");
    EXPECT_EQ(serviceExtensionContextTest.onAtomicRequestResults_.empty(), true);
}

/**
 * @tc.number: OnRequestSuccess_0200
 * @tc.name: OnRequestSuccess
 * @tc.desc: Verify that function OnRequestSuccess.
 */
HWTEST_F(ServiceExtensionContextTest, OnRequestSuccess_0200, Function | MediumTest | Level1)
{
    std::string requestId = "1234567890";
    ServiceExtensionContext serviceExtensionContextTest;
    EXPECT_EQ(serviceExtensionContextTest.onAtomicRequestResults_.empty(), true);
    AppExecFwk::ElementName element("", "com.example.com", "MainAbility");
    serviceExtensionContextTest.OnRequestSuccess(requestId, element, "success");
    EXPECT_EQ(serviceExtensionContextTest.onAtomicRequestResults_.empty(), true);
}

/**
 * @tc.number: OnRequestSuccess_0300
 * @tc.name: OnRequestSuccess
 * @tc.desc: Verify that function OnRequestSuccess.
 */
HWTEST_F(ServiceExtensionContextTest, OnRequestSuccess_0300, Function | MediumTest | Level1)
{
    std::string requestId = "1234567890";
    std::string appId = "atomic";
    OnAtomicRequestSuccess onRequestSucc = [](const std::string&) {};
    OnAtomicRequestFailure onRequestFail = [](const std::string&, int32_t, const std::string&) {};
    ServiceExtensionContext serviceExtensionContextTest;
    auto result = serviceExtensionContextTest.AddCompletionHandlerForAtomicService(
        requestId, onRequestSucc, onRequestFail, appId);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(serviceExtensionContextTest.onAtomicRequestResults_.empty(), false);
    AppExecFwk::ElementName element("", "com.example.com", "MainAbility");
    std::string norequestId = "test";
    serviceExtensionContextTest.OnRequestSuccess(norequestId, element, "success");
    EXPECT_EQ(serviceExtensionContextTest.onAtomicRequestResults_.empty(), false);
    serviceExtensionContextTest.onAtomicRequestResults_.clear();
}

/**
 * @tc.number: OnRequestFailure_0100
 * @tc.name: OnRequestFailure
 * @tc.desc: Verify that function OnRequestFailure.
 */
HWTEST_F(ServiceExtensionContextTest, OnRequestFailure_0100, Function | MediumTest | Level1)
{
    std::string requestId = "1234567890";
    std::string appId = "atomic";
    OnAtomicRequestSuccess onRequestSucc = [](const std::string&) {};
    OnAtomicRequestFailure onRequestFail = [](const std::string&, int32_t, const std::string&) {};
    ServiceExtensionContext serviceExtensionContextTest;
    auto result = serviceExtensionContextTest.AddCompletionHandlerForAtomicService(
        requestId, onRequestSucc, onRequestFail, appId);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(serviceExtensionContextTest.onAtomicRequestResults_.empty(), false);
    AppExecFwk::ElementName element("", "com.example.com", "MainAbility");
    serviceExtensionContextTest.OnRequestFailure(requestId, element, "failure");
    EXPECT_EQ(serviceExtensionContextTest.onAtomicRequestResults_.empty(), true);
    serviceExtensionContextTest.onAtomicRequestResults_.clear();
}

/**
 * @tc.number: OnRequestFailure_0200
 * @tc.name: OnRequestFailure
 * @tc.desc: Verify that function OnRequestFailure.
 */
HWTEST_F(ServiceExtensionContextTest, OnRequestFailure_0200, Function | MediumTest | Level1)
{
    std::string requestId = "1234567890";
    ServiceExtensionContext serviceExtensionContextTest;
    EXPECT_EQ(serviceExtensionContextTest.onAtomicRequestResults_.empty(), true);
    AppExecFwk::ElementName element("", "com.example.com", "MainAbility");
    serviceExtensionContextTest.OnRequestFailure(requestId, element, "failure");
    EXPECT_EQ(serviceExtensionContextTest.onAtomicRequestResults_.empty(), true);
}

/**
 * @tc.number: OnRequestFailure_0300
 * @tc.name: OnRequestFailure
 * @tc.desc: Verify that function OnRequestFailure.
 */
HWTEST_F(ServiceExtensionContextTest, OnRequestFailure_0300, Function | MediumTest | Level1)
{
    std::string requestId = "1234567890";
    std::string appId = "atomic";
    OnAtomicRequestSuccess onRequestSucc = [](const std::string&) {};
    OnAtomicRequestFailure onRequestFail = [](const std::string&, int32_t, const std::string&) {};
    ServiceExtensionContext contextTest;
    auto result = contextTest.AddCompletionHandlerForAtomicService(requestId, onRequestSucc, onRequestFail, appId);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(contextTest.onAtomicRequestResults_.empty(), false);
    AppExecFwk::ElementName element("", "com.example.com", "MainAbility");
    std::string norequestId = "test";
    contextTest.OnRequestFailure(norequestId, element, "failure");
    EXPECT_EQ(contextTest.onAtomicRequestResults_.empty(), false);
    contextTest.onAtomicRequestResults_.clear();
}

/**
 * @tc.number: GetFailureInfoByMessage_0100
 * @tc.name: GetFailureInfoByMessage
 * @tc.desc: Verify that function GetFailureInfoByMessage.
 */
HWTEST_F(ServiceExtensionContextTest, GetFailureInfoByMessage_0100, Function | MediumTest | Level1)
{
    std::string message = "User refused redirection";
    int32_t faileCode = 0;
    std::string failReason;
    ServiceExtensionContext contextTest;
    int32_t resultCode = USER_CANCEL;
    contextTest.GetFailureInfoByMessage(message, faileCode, failReason, resultCode);
    EXPECT_EQ(faileCode, 1);
    EXPECT_EQ(failReason, "User cancelled redirection");
    resultCode = 0;
    contextTest.GetFailureInfoByMessage(message, faileCode, failReason, resultCode);
    EXPECT_EQ(faileCode, 2);
    EXPECT_EQ(failReason, "User refused redirection");
    message = "test";
    contextTest.GetFailureInfoByMessage(message, faileCode, failReason, resultCode);
    EXPECT_EQ(faileCode, 0);
    EXPECT_EQ(failReason, "failed to open atomicservice");
}
}
}
