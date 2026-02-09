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

#include <gtest/gtest.h>

#define private public
#include "foreground_app_connection_manager.h"
#undef private
#include "connection_observer_errors.h"
#include "hilog_tag_wrapper.h"

using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
namespace {
    const int32_t TEST_TARGET_PID = 10001;
    const int32_t TEST_TARGET_UID = 10002;
    const std::string TEST_TARGET_BUNDLE_NAME = "com.ohos.connectionTarget.test";
    const int32_t TEST_CALLER_PID = 10003;
    const int32_t TEST_CALLER_UID = 10004;
    const std::string TEST_CALLER_BUNDLE_NAME = "com.ohos.connnectionCaller.test";
}
class ForegroundAppConnectionManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ForegroundAppConnectionManagerTest::SetUpTestCase(void)
{}
void ForegroundAppConnectionManagerTest::TearDownTestCase(void)
{}
void ForegroundAppConnectionManagerTest::SetUp(void)
{}
void ForegroundAppConnectionManagerTest::TearDown(void)
{}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: RegisterObserver
 * SubFunction: NA
 * FunctionPoints: ForegroundAppConnectionManager RegisterObserver
 * EnvConditions: NA
 * CaseDescription: Verify RegisterObserver
 */
HWTEST_F(ForegroundAppConnectionManagerTest, RegisterObserver_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "RegisterObserver_001 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    sptr<AbilityRuntime::IForegroundAppConnection> observer = nullptr;
    auto res = foregroundAppConnectionManager->RegisterObserver(observer);
    EXPECT_EQ(res, ERR_NULL_OBJECT);
    TAG_LOGI(AAFwkTag::TEST, "RegisterObserver_001 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: UnregisterObserver
 * SubFunction: NA
 * FunctionPoints: ForegroundAppConnectionManager UnregisterObserver
 * EnvConditions: NA
 * CaseDescription: Verify UnregisterObserver
 */
HWTEST_F(ForegroundAppConnectionManagerTest, UnregisterObserver_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "UnregisterObserver_001 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    sptr<AbilityRuntime::IForegroundAppConnection> observer = nullptr;
    foregroundAppConnectionManager->UnregisterObserver(observer);
    TAG_LOGI(AAFwkTag::TEST, "UnregisterObserver_001 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: OnConnected
 * SubFunction: NA
 * FunctionPoints: ForegroundAppConnectionManager OnConnected
 * EnvConditions: NA
 * CaseDescription: Verify OnConnected
 */
HWTEST_F(ForegroundAppConnectionManagerTest, OnConnected_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnConnected_001 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    AbilityRuntime::ForegroundAppConnectionData data;
    foregroundAppConnectionManager->OnConnected(data);
    TAG_LOGI(AAFwkTag::TEST, "OnConnected_001 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: OnConnected
 * SubFunction: NA
 * FunctionPoints: ForegroundAppConnectionManager OnConnected
 * EnvConditions: NA
 * CaseDescription: Verify OnConnected
 */
HWTEST_F(ForegroundAppConnectionManagerTest, OnConnected_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnConnected_002 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    AbilityRuntime::ForegroundAppConnectionData data;
    sptr<AbilityRuntime::IForegroundAppConnection> observer = nullptr;
    foregroundAppConnectionManager->observerList_.emplace_back(observer);
    foregroundAppConnectionManager->OnConnected(data);
    TAG_LOGI(AAFwkTag::TEST, "OnConnected_002 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: OnDisconnected_001
 * SubFunction: NA
 * FunctionPoints: ForegroundAppConnectionManager OnDisconnected
 * EnvConditions: NA
 * CaseDescription: Verify OnDisconnected
 */
HWTEST_F(ForegroundAppConnectionManagerTest, OnDisconnected_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnDisconnected_001 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    AbilityRuntime::ForegroundAppConnectionData data;
    foregroundAppConnectionManager->OnDisconnected(data);
    TAG_LOGI(AAFwkTag::TEST, "OnDisconnected_001 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: OnDisconnected_002
 * SubFunction: NA
 * FunctionPoints: ForegroundAppConnectionManager OnDisconnected
 * EnvConditions: NA
 * CaseDescription: Verify OnDisconnected
 */
HWTEST_F(ForegroundAppConnectionManagerTest, OnDisconnected_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnDisconnected_002 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    AbilityRuntime::ForegroundAppConnectionData data;
    sptr<AbilityRuntime::IForegroundAppConnection> observer = nullptr;
    foregroundAppConnectionManager->observerList_.emplace_back(observer);
    foregroundAppConnectionManager->OnDisconnected(data);
    TAG_LOGI(AAFwkTag::TEST, "OnDisconnected_002 End");
}


/*
 * Feature: ForegroundAppConnectionManager
 * Function: OnCallerStarted
 * SubFunction: NA
 * FunctionPoints: ForegroundAppConnectionManager OnCallerStarted
 * EnvConditions: NA
 * CaseDescription: Verify OnCallerStarted
 */
HWTEST_F(ForegroundAppConnectionManagerTest, OnCallerStarted_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnCallerStarted_001 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    int32_t callerPid = 0;
    int32_t callerUid = 0;
    std::string bundleName = "bundleName";

    foregroundAppConnectionManager->OnCallerStarted(callerPid, callerUid, bundleName);
    TAG_LOGI(AAFwkTag::TEST, "OnCallerStarted_001 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: OnCallerStarted
 * SubFunction: NA
 * FunctionPoints: ForegroundAppConnectionManager OnCallerStarted
 * EnvConditions: NA
 * CaseDescription: Verify OnCallerStarted
 */
HWTEST_F(ForegroundAppConnectionManagerTest, OnCallerStarted_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnCallerStarted_002 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    int32_t callerPid = 0;
    int32_t callerUid = 0;
    std::string bundleName = "bundleName";
    sptr<AbilityRuntime::IForegroundAppConnection> observer = nullptr;
    foregroundAppConnectionManager->observerList_.emplace_back(observer);

    foregroundAppConnectionManager->OnCallerStarted(callerPid, callerUid, bundleName);
    TAG_LOGI(AAFwkTag::TEST, "OnCallerStarted_002 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: AbilityAddPidConnection_001
 * FunctionPoints: callerPid invalid; targetPid invalid;
 */
HWTEST_F(ForegroundAppConnectionManagerTest, AbilityAddPidConnection_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityAddPidConnection_001 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    ForegroundAppConnectionInfo info(-1, -1, TEST_CALLER_UID, TEST_TARGET_UID,
        TEST_CALLER_BUNDLE_NAME, TEST_TARGET_BUNDLE_NAME);
    int32_t abilityRecordId = 0;
    foregroundAppConnectionManager->AbilityAddPidConnection(info, abilityRecordId);
    EXPECT_EQ(foregroundAppConnectionManager->pidMap_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "AbilityAddPidConnection_001 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: AbilityAddPidConnection_002
 * FunctionPoints: callerPid ok; targetPid invalid;
 */
HWTEST_F(ForegroundAppConnectionManagerTest, AbilityAddPidConnection_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityAddPidConnection_002 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    ForegroundAppConnectionInfo info(1, -1, TEST_CALLER_UID, TEST_TARGET_UID,
        TEST_CALLER_BUNDLE_NAME, TEST_TARGET_BUNDLE_NAME);
    int32_t abilityRecordId = 0;
    foregroundAppConnectionManager->AbilityAddPidConnection(info, abilityRecordId);
    EXPECT_EQ(foregroundAppConnectionManager->pidMap_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "AbilityAddPidConnection_002 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: AbilityAddPidConnection_003
 * FunctionPoints: callerPid invalid; targetPid ok;
 */
HWTEST_F(ForegroundAppConnectionManagerTest, AbilityAddPidConnection_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityAddPidConnection_003 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    ForegroundAppConnectionInfo info(-1, 1, TEST_CALLER_UID, TEST_TARGET_UID,
        TEST_CALLER_BUNDLE_NAME, TEST_TARGET_BUNDLE_NAME);
    int32_t abilityRecordId = 0;
    foregroundAppConnectionManager->AbilityAddPidConnection(info, abilityRecordId);
    EXPECT_EQ(foregroundAppConnectionManager->pidMap_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "AbilityAddPidConnection_003 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: AbilityAddPidConnection_004
 * FunctionPoints: callerPid ok; targetPid ok;
 */
HWTEST_F(ForegroundAppConnectionManagerTest, AbilityAddPidConnection_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityAddPidConnection_004 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    ForegroundAppConnectionInfo info(TEST_CALLER_PID, TEST_TARGET_PID, TEST_CALLER_UID, TEST_TARGET_UID,
        TEST_CALLER_BUNDLE_NAME, TEST_TARGET_BUNDLE_NAME);
    int32_t abilityRecordId = 0;
    foregroundAppConnectionManager->AbilityAddPidConnection(info, abilityRecordId);
    EXPECT_EQ(foregroundAppConnectionManager->pidMap_.size(), 1);
    TAG_LOGI(AAFwkTag::TEST, "AbilityAddPidConnection_004 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: AbilityAddPidConnection_005
 * FunctionPoints: pidConnection exists
 */
HWTEST_F(ForegroundAppConnectionManagerTest, AbilityAddPidConnection_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityAddPidConnection_005 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    ForegroundAppConnectionInfo info(TEST_CALLER_PID, TEST_TARGET_PID, TEST_CALLER_UID, TEST_TARGET_UID,
        TEST_CALLER_BUNDLE_NAME, TEST_TARGET_BUNDLE_NAME);
    int32_t abilityRecordId = 0;
    foregroundAppConnectionManager->AbilityAddPidConnection(info, abilityRecordId);
    int32_t abilityRecordId2 = 1;
    foregroundAppConnectionManager->AbilityAddPidConnection(info, abilityRecordId2);
    EXPECT_EQ(foregroundAppConnectionManager->pidMap_.size(), 1);
    TAG_LOGI(AAFwkTag::TEST, "AbilityAddPidConnection_005 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: AbilityAddPidConnection_006
 * FunctionPoints: pidConnection exists; abilityRecordId exists;
 */
HWTEST_F(ForegroundAppConnectionManagerTest, AbilityAddPidConnection_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityAddPidConnection_006 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    ForegroundAppConnectionInfo info(TEST_CALLER_PID, TEST_TARGET_PID, TEST_CALLER_UID, TEST_TARGET_UID,
        TEST_CALLER_BUNDLE_NAME, TEST_TARGET_BUNDLE_NAME);
    int32_t abilityRecordId = 0;
    foregroundAppConnectionManager->AbilityAddPidConnection(info, abilityRecordId);
    int32_t abilityRecordId2 = 0;
    foregroundAppConnectionManager->AbilityAddPidConnection(info, abilityRecordId2);
    EXPECT_EQ(foregroundAppConnectionManager->pidMap_.size(), 1);
    TAG_LOGI(AAFwkTag::TEST, "AbilityAddPidConnection_006 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: AbilityAddPidConnection
 * FunctionPoints: AbilityAddPidConnection trigger OnConnected
 * EnvConditions: NA
 * CaseDescription: Verify AbilityAddPidConnection call OnConnected success
 */
HWTEST_F(ForegroundAppConnectionManagerTest, AbilityAddPidConnection_007, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityAddPidConnection_007 Start");
    auto manager = std::make_shared<ForegroundAppConnectionManager>();
    ForegroundAppConnectionInfo info(100, 200, 100, 200, "caller", "target");

    manager->AbilityAddPidConnection(info, 0);
    EXPECT_EQ(manager->pidMap_.size(), 1);
    TAG_LOGI(AAFwkTag::TEST, "AbilityAddPidConnection_007 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: AbilityRemovePidConnection_001
 * FunctionPoints: pidConnection not exists
 */
HWTEST_F(ForegroundAppConnectionManagerTest, AbilityRemovePidConnection_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityRemovePidConnection_001 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    ForegroundAppConnectionInfo info(TEST_CALLER_PID, TEST_TARGET_PID, TEST_CALLER_UID, TEST_TARGET_UID,
        TEST_CALLER_BUNDLE_NAME, TEST_TARGET_BUNDLE_NAME);
    int32_t abilityRecordId = 0;
    foregroundAppConnectionManager->AbilityRemovePidConnection(TEST_CALLER_PID, TEST_TARGET_PID, abilityRecordId);
    EXPECT_EQ(foregroundAppConnectionManager->pidMap_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "AbilityRemovePidConnection_001 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: AbilityRemovePidConnection_002
 * FunctionPoints: pidConnection exists; abilityRecordIds not empty;
 */
HWTEST_F(ForegroundAppConnectionManagerTest, AbilityRemovePidConnection_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityRemovePidConnection_002 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    ForegroundAppConnectionInfo info(TEST_CALLER_PID, TEST_TARGET_PID, TEST_CALLER_UID, TEST_TARGET_UID,
        TEST_CALLER_BUNDLE_NAME, TEST_TARGET_BUNDLE_NAME);
    int32_t abilityRecordId = 0;
    foregroundAppConnectionManager->AbilityAddPidConnection(info, abilityRecordId);
    int32_t abilityRecordId2 = 1;
    foregroundAppConnectionManager->AbilityRemovePidConnection(TEST_CALLER_PID, TEST_TARGET_PID, abilityRecordId2);
    EXPECT_EQ(foregroundAppConnectionManager->pidMap_.size(), 1);
    TAG_LOGI(AAFwkTag::TEST, "AbilityRemovePidConnection_002 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: AbilityRemovePidConnection_003
 * FunctionPoints: pidConnection exists; abilityRecordIds empty;
 */
HWTEST_F(ForegroundAppConnectionManagerTest, AbilityRemovePidConnection_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityRemovePidConnection_003 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    ForegroundAppConnectionInfo info(TEST_CALLER_PID, TEST_TARGET_PID, TEST_CALLER_UID, TEST_TARGET_UID,
        TEST_CALLER_BUNDLE_NAME, TEST_TARGET_BUNDLE_NAME);
    int32_t abilityRecordId = 0;
    foregroundAppConnectionManager->AbilityAddPidConnection(info, abilityRecordId);
    foregroundAppConnectionManager->AbilityRemovePidConnection(TEST_CALLER_PID, TEST_TARGET_PID, abilityRecordId);
    EXPECT_EQ(foregroundAppConnectionManager->pidMap_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "AbilityRemovePidConnection_003 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: ProcessRemovePidConnection_001
 * FunctionPoints: TEST_CALLER_PID != diedPid; TEST_TARGET_PID != diedPid;
 */
HWTEST_F(ForegroundAppConnectionManagerTest, ProcessRemovePidConnection_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ProcessRemovePidConnection_001 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    ForegroundAppConnectionInfo info(TEST_CALLER_PID, TEST_TARGET_PID, TEST_CALLER_UID, TEST_TARGET_UID,
        TEST_CALLER_BUNDLE_NAME, TEST_TARGET_BUNDLE_NAME);
    int32_t abilityRecordId = 0;
    foregroundAppConnectionManager->AbilityAddPidConnection(info, abilityRecordId);
    int32_t diedPid = 12345;
    foregroundAppConnectionManager->ProcessRemovePidConnection(diedPid);
    EXPECT_EQ(foregroundAppConnectionManager->pidMap_.size(), 1);
    TAG_LOGI(AAFwkTag::TEST, "ProcessRemovePidConnection_001 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: ProcessRemovePidConnection_002
 * FunctionPoints: TEST_CALLER_PID = diedPid;
 */
HWTEST_F(ForegroundAppConnectionManagerTest, ProcessRemovePidConnection_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ProcessRemovePidConnection_002 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    ForegroundAppConnectionInfo info(TEST_CALLER_PID, TEST_TARGET_PID, TEST_CALLER_UID, TEST_TARGET_UID,
        TEST_CALLER_BUNDLE_NAME, TEST_TARGET_BUNDLE_NAME);
    int32_t abilityRecordId = 0;
    foregroundAppConnectionManager->AbilityAddPidConnection(info, abilityRecordId);
    int32_t diedPid = TEST_CALLER_PID;
    foregroundAppConnectionManager->ProcessRemovePidConnection(diedPid);
    EXPECT_EQ(foregroundAppConnectionManager->pidMap_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "ProcessRemovePidConnection_002 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: ProcessRemovePidConnection_003
 * FunctionPoints: TEST_TARGET_PID = diedPid;
 */
HWTEST_F(ForegroundAppConnectionManagerTest, ProcessRemovePidConnection_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ProcessRemovePidConnection_003 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    ForegroundAppConnectionInfo info(TEST_CALLER_PID, TEST_TARGET_PID, TEST_CALLER_UID, TEST_TARGET_UID,
        TEST_CALLER_BUNDLE_NAME, TEST_TARGET_BUNDLE_NAME);
    int32_t abilityRecordId = 0;
    foregroundAppConnectionManager->AbilityAddPidConnection(info, abilityRecordId);
    int32_t diedPid = TEST_TARGET_PID;
    foregroundAppConnectionManager->ProcessRemovePidConnection(diedPid);
    EXPECT_EQ(foregroundAppConnectionManager->pidMap_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "ProcessRemovePidConnection_003 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: ProcessRemovePidConnection_004
 * FunctionPoints: TEST_TARGET_PID = TEST_CALLER_PID = diedPid;
 */
HWTEST_F(ForegroundAppConnectionManagerTest, ProcessRemovePidConnection_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ProcessRemovePidConnection_004 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    ForegroundAppConnectionInfo info(TEST_TARGET_PID, TEST_TARGET_PID, TEST_CALLER_UID, TEST_TARGET_UID,
        TEST_CALLER_BUNDLE_NAME, TEST_TARGET_BUNDLE_NAME);
    int32_t abilityRecordId = 0;
    foregroundAppConnectionManager->AbilityAddPidConnection(info, abilityRecordId);
    int32_t diedPid = TEST_TARGET_PID;
    foregroundAppConnectionManager->ProcessRemovePidConnection(diedPid);
    EXPECT_EQ(foregroundAppConnectionManager->pidMap_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "ProcessRemovePidConnection_004 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: ProcessRemovePidConnection
 * SubFunction: NA
 * FunctionPoints: ProcessRemovePidConnection with invalid diedPid
 * EnvConditions: NA
 * CaseDescription: Verify ProcessRemovePidConnection ignore invalid pid
 */
HWTEST_F(ForegroundAppConnectionManagerTest, ProcessRemovePidConnection_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ProcessRemovePidConnection_005 Start");
    auto manager = std::make_shared<ForegroundAppConnectionManager>();
    ForegroundAppConnectionInfo info(100, 200, 100, 200, "caller", "target");
    manager->AbilityAddPidConnection(info, 0);

    manager->ProcessRemovePidConnection(-1);
    EXPECT_EQ(manager->pidMap_.size(), 1);
    TAG_LOGI(AAFwkTag::TEST, "ProcessRemovePidConnection_005 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: HandleRemoteDied_001
 * FunctionPoints: ForegroundAppConnectionManager HandleRemoteDied
 */
HWTEST_F(ForegroundAppConnectionManagerTest, HandleRemoteDied_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleRemoteDied_001 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    wptr<IRemoteObject> remote;
    foregroundAppConnectionManager->HandleRemoteDied(remote);
    TAG_LOGI(AAFwkTag::TEST, "HandleRemoteDied_001 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: GenerateConnectionData_001
 * FunctionPoints: GenerateConnectionData
 */
HWTEST_F(ForegroundAppConnectionManagerTest, GenerateConnectionData_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GenerateConnectionData_001 Start");
    auto foregroundAppConnectionManager = std::make_shared<ForegroundAppConnectionManager>();
    EXPECT_NE(foregroundAppConnectionManager, nullptr);
    ForegroundAppConnectionInfo info(TEST_TARGET_PID, TEST_TARGET_PID, TEST_CALLER_UID, TEST_TARGET_UID,
        TEST_CALLER_BUNDLE_NAME, TEST_TARGET_BUNDLE_NAME);
    AbilityRuntime::ForegroundAppConnectionData data;
    foregroundAppConnectionManager->GenerateConnectionData(info, data);
    EXPECT_EQ(info.callerPid_, data.callerPid_);
    EXPECT_EQ(info.targetPid_, data.targetPid_);
    EXPECT_EQ(info.callerUid_, data.callerUid_);
    EXPECT_EQ(info.targetUid_, data.targetUid_);
    EXPECT_EQ(info.callerBundleName_, data.callerBundleName_);
    EXPECT_EQ(info.targetBundleName_, data.targetBundleName_);
    TAG_LOGI(AAFwkTag::TEST, "GenerateConnectionData_001 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: IsForegroundAppConnection_001
 * FunctionPoints: abilityRecord is nullptr
 */
HWTEST_F(ForegroundAppConnectionManagerTest, IsForegroundAppConnection_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_001 Start");
    AppExecFwk::AbilityInfo abilityInfo;
    std::shared_ptr<AbilityRecord> abilityRecord = nullptr;
    bool result = ForegroundAppConnectionManager::IsForegroundAppConnection(abilityInfo, abilityRecord);
    EXPECT_EQ(result, false);
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_001 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: IsForegroundAppConnection_002
 * FunctionPoints: target true true
 */
HWTEST_F(ForegroundAppConnectionManagerTest, IsForegroundAppConnection_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_002 Start");
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    abilityInfo.applicationInfo.isSystemApp = true;
    abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SYSDIALOG_COMMON;
    AbilityRequest callerAbilityRequest;
    callerAbilityRequest.appInfo.bundleName = "com.test.demo";
    callerAbilityRequest.abilityInfo.name = "MainAbility";
    callerAbilityRequest.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> callerAbilityRecord = AbilityRecord::CreateAbilityRecord(callerAbilityRequest);

    bool result = ForegroundAppConnectionManager::IsForegroundAppConnection(abilityInfo, callerAbilityRecord);
    EXPECT_EQ(result, true);
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_002 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: IsForegroundAppConnection_003
 * FunctionPoints: target true false
 */
HWTEST_F(ForegroundAppConnectionManagerTest, IsForegroundAppConnection_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_003 Start");
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    abilityInfo.applicationInfo.isSystemApp = true;
    abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::BACKUP;
    AbilityRequest callerAbilityRequest;
    callerAbilityRequest.appInfo.bundleName = "com.test.demo";
    callerAbilityRequest.abilityInfo.name = "MainAbility";
    callerAbilityRequest.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> callerAbilityRecord = AbilityRecord::CreateAbilityRecord(callerAbilityRequest);

    bool result = ForegroundAppConnectionManager::IsForegroundAppConnection(abilityInfo, callerAbilityRecord);
    EXPECT_EQ(result, true);
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_003 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: IsForegroundAppConnection_004
 * FunctionPoints: target false true
 */
HWTEST_F(ForegroundAppConnectionManagerTest, IsForegroundAppConnection_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_004 Start");
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::DATA;
    abilityInfo.applicationInfo.isSystemApp = true;
    abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SYSDIALOG_COMMON;
    AbilityRequest callerAbilityRequest;
    callerAbilityRequest.appInfo.bundleName = "com.test.demo";
    callerAbilityRequest.abilityInfo.name = "MainAbility";
    callerAbilityRequest.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> callerAbilityRecord = AbilityRecord::CreateAbilityRecord(callerAbilityRequest);

    bool result = ForegroundAppConnectionManager::IsForegroundAppConnection(abilityInfo, callerAbilityRecord);
    EXPECT_EQ(result, true);
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_004 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: IsForegroundAppConnection_005
 * FunctionPoints: target false false
 */
HWTEST_F(ForegroundAppConnectionManagerTest, IsForegroundAppConnection_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_005 Start");
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::DATA;
    abilityInfo.applicationInfo.isSystemApp = true;
    abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::BACKUP;
    AbilityRequest callerAbilityRequest;
    callerAbilityRequest.appInfo.bundleName = "com.test.demo";
    callerAbilityRequest.abilityInfo.name = "MainAbility";
    callerAbilityRequest.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> callerAbilityRecord = AbilityRecord::CreateAbilityRecord(callerAbilityRequest);

    bool result = ForegroundAppConnectionManager::IsForegroundAppConnection(abilityInfo, callerAbilityRecord);
    EXPECT_EQ(result, false);
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_005 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: IsForegroundAppConnection_006
 * FunctionPoints: caller true true
 */
HWTEST_F(ForegroundAppConnectionManagerTest, IsForegroundAppConnection_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_006 Start");
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    abilityInfo.applicationInfo.isSystemApp = true;
    abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::BACKUP;
    AbilityRequest callerAbilityRequest;
    callerAbilityRequest.appInfo.bundleName = "com.test.demo";
    callerAbilityRequest.abilityInfo.name = "MainAbility";
    callerAbilityRequest.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    callerAbilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SYSDIALOG_COMMON;
    std::shared_ptr<AbilityRecord> callerAbilityRecord = AbilityRecord::CreateAbilityRecord(callerAbilityRequest);

    bool result = ForegroundAppConnectionManager::IsForegroundAppConnection(abilityInfo, callerAbilityRecord);
    EXPECT_EQ(result, true);
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_006 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: IsForegroundAppConnection_007
 * FunctionPoints: caller true false
 */
HWTEST_F(ForegroundAppConnectionManagerTest, IsForegroundAppConnection_007, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_007 Start");
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    abilityInfo.applicationInfo.isSystemApp = true;
    abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::BACKUP;
    AbilityRequest callerAbilityRequest;
    callerAbilityRequest.appInfo.bundleName = "com.test.demo";
    callerAbilityRequest.abilityInfo.name = "MainAbility";
    callerAbilityRequest.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    callerAbilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::BACKUP;
    std::shared_ptr<AbilityRecord> callerAbilityRecord = AbilityRecord::CreateAbilityRecord(callerAbilityRequest);

    bool result = ForegroundAppConnectionManager::IsForegroundAppConnection(abilityInfo, callerAbilityRecord);
    EXPECT_EQ(result, true);
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_007 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: IsForegroundAppConnection_008
 * FunctionPoints: caller false true
 */
HWTEST_F(ForegroundAppConnectionManagerTest, IsForegroundAppConnection_008, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_008 Start");
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    abilityInfo.applicationInfo.isSystemApp = true;
    abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::BACKUP;
    AbilityRequest callerAbilityRequest;
    callerAbilityRequest.appInfo.bundleName = "com.test.demo";
    callerAbilityRequest.abilityInfo.name = "MainAbility";
    callerAbilityRequest.abilityInfo.type = AppExecFwk::AbilityType::DATA;
    callerAbilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SYSDIALOG_COMMON;
    std::shared_ptr<AbilityRecord> callerAbilityRecord = AbilityRecord::CreateAbilityRecord(callerAbilityRequest);

    bool result = ForegroundAppConnectionManager::IsForegroundAppConnection(abilityInfo, callerAbilityRecord);
    EXPECT_EQ(result, true);
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_008 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: IsForegroundAppConnection_009
 * FunctionPoints: caller false false
 */
HWTEST_F(ForegroundAppConnectionManagerTest, IsForegroundAppConnection_009, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_009 Start");
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    abilityInfo.applicationInfo.isSystemApp = true;
    abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::BACKUP;
    AbilityRequest callerAbilityRequest;
    callerAbilityRequest.appInfo.bundleName = "com.test.demo";
    callerAbilityRequest.abilityInfo.name = "MainAbility";
    callerAbilityRequest.abilityInfo.type = AppExecFwk::AbilityType::DATA;
    callerAbilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::BACKUP;
    std::shared_ptr<AbilityRecord> callerAbilityRecord = AbilityRecord::CreateAbilityRecord(callerAbilityRequest);

    bool result = ForegroundAppConnectionManager::IsForegroundAppConnection(abilityInfo, callerAbilityRecord);
    EXPECT_EQ(result, false);
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_009 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: IsForegroundAppConnection_010
 * FunctionPoints: all true
 */
HWTEST_F(ForegroundAppConnectionManagerTest, IsForegroundAppConnection_010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_010 Start");
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    abilityInfo.applicationInfo.isSystemApp = true;
    abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SYSDIALOG_COMMON;
    AbilityRequest callerAbilityRequest;
    callerAbilityRequest.appInfo.bundleName = "com.test.demo";
    callerAbilityRequest.abilityInfo.name = "MainAbility";
    callerAbilityRequest.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    callerAbilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SYSDIALOG_COMMON;
    std::shared_ptr<AbilityRecord> callerAbilityRecord = AbilityRecord::CreateAbilityRecord(callerAbilityRequest);

    bool result = ForegroundAppConnectionManager::IsForegroundAppConnection(abilityInfo, callerAbilityRecord);
    EXPECT_EQ(result, true);
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_010 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: IsForegroundAppConnection_011
 * FunctionPoints: target not systemApp
 */
HWTEST_F(ForegroundAppConnectionManagerTest, IsForegroundAppConnection_011, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_011 Start");
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    abilityInfo.applicationInfo.isSystemApp = false;
    abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::BACKUP;
    AbilityRequest callerAbilityRequest;
    callerAbilityRequest.appInfo.bundleName = "com.test.demo";
    callerAbilityRequest.abilityInfo.name = "MainAbility";
    callerAbilityRequest.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    callerAbilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SYSDIALOG_COMMON;
    std::shared_ptr<AbilityRecord> callerAbilityRecord = AbilityRecord::CreateAbilityRecord(callerAbilityRequest);

    bool result = ForegroundAppConnectionManager::IsForegroundAppConnection(abilityInfo, callerAbilityRecord);
    EXPECT_EQ(result, false);
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_011 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: IsForegroundAppConnection
 * FunctionPoints: target is UIExtension
 * EnvConditions: NA
 * CaseDescription: Verify IsForegroundAppConnection return true when target is UIExtension
 */
HWTEST_F(ForegroundAppConnectionManagerTest, IsForegroundAppConnection_012, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_012 Start");
    AppExecFwk::AbilityInfo targetInfo;
    targetInfo.type = AppExecFwk::AbilityType::SERVICE;
    targetInfo.applicationInfo.isSystemApp = false;
    targetInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SYS_COMMON_UI;

    AbilityRequest callerReq;
    callerReq.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    auto callerRecord = AbilityRecord::CreateAbilityRecord(callerReq);

    bool result = ForegroundAppConnectionManager::IsForegroundAppConnection(targetInfo, callerRecord);
    EXPECT_EQ(result, true);
    TAG_LOGI(AAFwkTag::TEST, "IsForegroundAppConnection_012 End");
}

/*
 * Feature: ForegroundAppConnectionInfo
 * Function: AddAbilityRecordId
 * SubFunction: NA
 * FunctionPoints: AddAbilityRecordId with duplicate id
 * EnvConditions: NA
 * CaseDescription: Verify AddAbilityRecordId ignore duplicate id
 */
HWTEST_F(ForegroundAppConnectionManagerTest, AddAbilityRecordId_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AddAbilityRecordId_001 Start");
    ForegroundAppConnectionInfo info(100, 200, 100, 200, "caller", "target");
    info.abilityRecordIds_.emplace_back(1); // 先添加id=1

    info.AddAbilityRecordId(1); // 重复添加
    EXPECT_EQ(info.abilityRecordIds_.size(), 1); // 数量不变
    TAG_LOGI(AAFwkTag::TEST, "AddAbilityRecordId_001 End");
}

/*
 * Feature: ForegroundAppConnectionInfo
 * Function: RemoveAbilityRecordId
 * SubFunction: NA
 * FunctionPoints: RemoveAbilityRecordId with non-exist id
 * EnvConditions: NA
 * CaseDescription: Verify RemoveAbilityRecordId ignore non-exist id
 */
HWTEST_F(ForegroundAppConnectionManagerTest, RemoveAbilityRecordId_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "RemoveAbilityRecordId_001 Start");
    ForegroundAppConnectionInfo info(100, 200, 100, 200, "caller", "target");
    info.abilityRecordIds_.emplace_back(1);

    info.RemoveAbilityRecordId(2); // 移除不存在的id
    EXPECT_EQ(info.abilityRecordIds_.size(), 1); // 数量不变
    TAG_LOGI(AAFwkTag::TEST, "RemoveAbilityRecordId_001 End");
}

/*
 * Feature: ForegroundAppConnectionManager
 * Function: ConnectionDeathRecipient
 * FunctionPoints: OnRemoteDied call death handler
 * EnvConditions: NA
 * CaseDescription: Verify ConnectionDeathRecipient trigger handler success
 */
HWTEST_F(ForegroundAppConnectionManagerTest, ConnectionDeathRecipient_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ConnectionDeathRecipient_001 Start");
    bool isCalled = false;
    auto handler = [&isCalled](const wptr<IRemoteObject>&) { isCalled = true; };
    
    ForegroundAppConnectionManager::ConnectionDeathRecipient recipient(handler);
    recipient.OnRemoteDied(nullptr);
    
    EXPECT_EQ(isCalled, true);
    TAG_LOGI(AAFwkTag::TEST, "ConnectionDeathRecipient_001 End");
}
}  // namespace AAFwk
}  // namespace OHOS
