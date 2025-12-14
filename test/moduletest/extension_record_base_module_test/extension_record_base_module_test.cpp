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

#include <string_view>
#include <vector>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "abs_shared_result_set.h"
#include "data_ability_predicates.h"
#include "param.h"
#include "values_bucket.h"

#include "want.h"

#define private public
#include "app_scheduler.h"
#include "base_extension_record.h"
#include "connection_record.h"
#include "mock_app_mgr_client.h"
#include "mock_ability_scheduler_stub.h"
#undef private

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::iface_cast;
using OHOS::sptr;
using testing::_;
using testing::Invoke;
using testing::Return;

namespace {
constexpr int COUNT = 1000;
}  // namespace

namespace OHOS::AppExecFwk {
bool operator==(const AbilityInfo& a, const AbilityInfo& b)
{
    if (&a != &b) {
        return a.package == b.package && a.name == b.name && a.label == b.label && a.description == b.description &&
            a.iconPath == b.iconPath && a.visible == b.visible && a.kind == b.kind &&
            a.permissions == b.permissions && a.bundleName == b.bundleName &&
            a.applicationName == b.applicationName && a.deviceId == b.deviceId && a.codePath == b.codePath &&
            a.resourcePath == b.resourcePath && a.libPath == b.libPath;
    }

    return true;
}

bool operator!=(const AbilityInfo& a, const AbilityInfo& b)
{
    return !(a == b);
}

bool operator==(const ApplicationInfo& a, const ApplicationInfo& b)
{
    if (&a != &b) {
        return a.name == b.name && a.bundleName == b.bundleName && a.deviceId == b.deviceId &&
            a.signatureKey == b.signatureKey;
    }

    return true;
}

bool operator!=(const ApplicationInfo& a, const ApplicationInfo& b)
{
    return !(a == b);
}
}  // namespace OHOS::AppExecFwk

namespace OHOS::AAFwk {
bool operator==(const Want& a, const Want& b)
{
    if (&a != &b) {
        return a.GetAction() == b.GetAction() && a.GetEntities() == b.GetEntities();
    }

    return true;
}

bool operator!=(const Want& a, const Want& b)
{
    return !(a == b);
}
}  // namespace OHOS::AAFwk

namespace OHOS {
namespace AAFwk {
class ExtensionRecordBaseModuleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    static const AbilityRequest& MakeDefaultAbilityRequest();
    static const AbilityRequest& MakeHomeAbilityRequest();

private:
    inline static AbilityRequest testAbilityRequest_;
};

void ExtensionRecordBaseModuleTest::SetUpTestCase()
{
    int testCode = 123;
    testAbilityRequest_.requestCode = testCode;

    testAbilityRequest_.abilityInfo.package = "test";
    testAbilityRequest_.abilityInfo.name = "test";
    testAbilityRequest_.abilityInfo.label = "test";
    testAbilityRequest_.abilityInfo.description = "test";
    testAbilityRequest_.abilityInfo.iconPath = "/test";
    testAbilityRequest_.abilityInfo.visible = false;
    testAbilityRequest_.abilityInfo.kind = "page";
    testAbilityRequest_.abilityInfo.permissions = {};
    testAbilityRequest_.abilityInfo.bundleName = "test";
    testAbilityRequest_.abilityInfo.applicationName = "test";
    testAbilityRequest_.abilityInfo.deviceId = "test";
    testAbilityRequest_.abilityInfo.codePath = "/test";
    testAbilityRequest_.abilityInfo.resourcePath = "/test";
    testAbilityRequest_.abilityInfo.libPath = "/test";

    testAbilityRequest_.appInfo.name = "test";
    testAbilityRequest_.appInfo.bundleName = "test";
    testAbilityRequest_.appInfo.deviceId = "test";
    testAbilityRequest_.appInfo.signatureKey = "test";
}

void ExtensionRecordBaseModuleTest::TearDownTestCase()
{}

void ExtensionRecordBaseModuleTest::SetUp()
{}

void ExtensionRecordBaseModuleTest::TearDown()
{}

const AbilityRequest& ExtensionRecordBaseModuleTest::MakeDefaultAbilityRequest()
{
    Want::ClearWant(&testAbilityRequest_.want);
    testAbilityRequest_.want.SetAction("test");
    testAbilityRequest_.want.AddEntity("test");

    return testAbilityRequest_;
}

const AbilityRequest& ExtensionRecordBaseModuleTest::MakeHomeAbilityRequest()
{
    Want::ClearWant(&testAbilityRequest_.want);
    testAbilityRequest_.want.SetAction(Want::ACTION_HOME);
    testAbilityRequest_.want.AddEntity(Want::ENTITY_HOME);
    testAbilityRequest_.appInfo.isLauncherApp = true;

    return testAbilityRequest_;
}

/*
 * Feature: BaseExtensionRecord
 * Function: ConnectionRecord
 * SubFunction: AddConnectRecordToList/GetConnectRecordList/GetConnectingRecord/GetDisconnectingRecord
 * FunctionPoints: Ability connect record getter and setter
 * CaseDescription: Check ability connect record getter and setter.
 */
HWTEST_F(ExtensionRecordBaseModuleTest, ConnectionRecord_001, TestSize.Level2)
{
    auto& abilityRequest = MakeDefaultAbilityRequest();

    auto abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest);
    EXPECT_TRUE(abilityRecord);
    EXPECT_TRUE(abilityRecord->IsConnectListEmpty());

    auto connectionRecord = ConnectionRecord::CreateConnectionRecord(nullptr, nullptr, nullptr, nullptr);
    EXPECT_TRUE(connectionRecord);

    for (int i = 0; i < COUNT; ++i) {
        abilityRecord->AddConnectRecordToList(connectionRecord);
        EXPECT_FALSE(abilityRecord->IsConnectListEmpty());
        auto connectionRecordList = abilityRecord->GetConnectRecordList();
        auto it = std::find(connectionRecordList.begin(), connectionRecordList.end(), connectionRecord);
        EXPECT_TRUE(it != connectionRecordList.end());

        EXPECT_FALSE(abilityRecord->GetConnectingRecord());
        connectionRecord->SetConnectState(ConnectionState::CONNECTING);
        EXPECT_TRUE(abilityRecord->GetConnectingRecord());

        EXPECT_FALSE(abilityRecord->GetDisconnectingRecord());
        connectionRecord->SetConnectState(ConnectionState::DISCONNECTING);
        EXPECT_TRUE(abilityRecord->GetDisconnectingRecord());

        abilityRecord->RemoveConnectRecordFromList(connectionRecord);
        EXPECT_TRUE(abilityRecord->IsConnectListEmpty());
        connectionRecordList = abilityRecord->GetConnectRecordList();
        it = std::find(connectionRecordList.begin(), connectionRecordList.end(), connectionRecord);
        EXPECT_TRUE(it == connectionRecordList.end());
    }
}

/*
 * Feature: BaseExtensionRecord
 * Function: Scheduler
 * SubFunction: Activate/Inactivate/Terminate/ConnectAbility/DisconnectAbility/SendResult
 * FunctionPoints: Check scheduler work flow.
 * CaseDescription: Change ability state and check if the work flow reachs the 'AbilityScheduler' mocker.
 */
HWTEST_F(ExtensionRecordBaseModuleTest, AbilityScheduler_001, TestSize.Level3)
{
    auto& abilityRequest = MakeDefaultAbilityRequest();
    auto abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest);
    EXPECT_TRUE(abilityRecord);

    sptr<MockAbilitySchedulerStub> mockAbilityScheduerStub(new MockAbilitySchedulerStub);
    EXPECT_TRUE(mockAbilityScheduerStub);

    bool testResult = false;
    abilityRecord->SetScheduler(mockAbilityScheduerStub);
    EXPECT_TRUE(abilityRecord->IsReady());

    for (int i = 0; i < COUNT; ++i) {
        // Activate
        auto mockActivateHandler = [&](const Want& want, const LifeCycleStateInfo& lifeCycleStateInfo,
            sptr<SessionInfo> sessionInfo) {
            testResult = (lifeCycleStateInfo.state == AbilityLifeCycleState::ABILITY_STATE_ACTIVE);
        };
        testResult = false;
        EXPECT_CALL(*mockAbilityScheduerStub, ScheduleAbilityTransaction(_, _, _))
            .Times(1)
            .WillOnce(testing::DoAll(Invoke(mockActivateHandler), testing::Return(true)));

        abilityRecord->Activate();
        EXPECT_TRUE(testResult);
        EXPECT_EQ(abilityRecord->GetAbilityState(), ACTIVATING);

        // Inactivate
        testResult = false;
        auto mockInactivateHandler = [&](const Want& want, const LifeCycleStateInfo& lifeCycleStateInfo,
            sptr<SessionInfo> sessionInfo) {
            testResult = (lifeCycleStateInfo.state == AbilityLifeCycleState::ABILITY_STATE_INACTIVE);
        };
        EXPECT_CALL(*mockAbilityScheduerStub, ScheduleAbilityTransaction(_, _, _))
            .Times(1)
            .WillOnce(testing::DoAll(Invoke(mockInactivateHandler), testing::Return(true)));

        abilityRecord->Inactivate();
        EXPECT_TRUE(testResult);
        EXPECT_EQ(abilityRecord->GetAbilityState(), INACTIVATING);

        testResult = false;

        // Terminate
        EXPECT_CALL(*mockAbilityScheduerStub, ScheduleAbilityTransaction(_, _, _)).Times(1);
        abilityRecord->Terminate([] {});
        EXPECT_EQ(abilityRecord->GetAbilityState(), TERMINATING);

        // Connect
        testResult = false;
        auto mockConnectHandler = [&](const Want& want) { testResult = want == abilityRequest.want; };
        EXPECT_CALL(*mockAbilityScheduerStub, ScheduleConnectAbility(_)).Times(1).WillOnce(Invoke(mockConnectHandler));
        abilityRecord->ConnectAbility();
        EXPECT_TRUE(testResult);

        // Disconnect
        testResult = false;
        auto mockDisconnectHandler = [&](const Want& want) { testResult = want == abilityRequest.want; };
        EXPECT_CALL(*mockAbilityScheduerStub, ScheduleDisconnectAbility(_))
            .Times(1)
            .WillOnce(Invoke(mockDisconnectHandler));
        abilityRecord->DisconnectAbility();
        EXPECT_TRUE(testResult);

        // SendResult
        testResult = false;
        int testResultCode = 123;
        auto mockSendResultHandler = [&](int requestCode, int resultCode, const Want& want) {
            testResult = requestCode == abilityRequest.requestCode && resultCode == testResultCode &&
                want == abilityRequest.want;
        };
        EXPECT_CALL(*mockAbilityScheduerStub, SendResult(_, _, _)).Times(1).WillOnce(Invoke(mockSendResultHandler));
        auto abilityResult =
            std::make_shared<AbilityResult>(abilityRequest.requestCode, testResultCode, abilityRequest.want);
        EXPECT_TRUE(abilityResult);
        abilityRecord->SetResult(abilityResult);
        abilityRecord->SendResult(0, 0);
        EXPECT_TRUE(testResult);
    }

    abilityRecord->SetScheduler(nullptr);
}
}  // namespace AAFwk
}  // namespace OHOS