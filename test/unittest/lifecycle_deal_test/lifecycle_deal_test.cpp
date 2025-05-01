/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "app_process_data.h"
#include "lifecycle_deal.h"
#include "ability_scheduler_mock.h"
#include "session_info.h"

using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class LifecycleDealTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<LifecycleDeal> lifecycleDeal_{ nullptr };
    sptr<AbilitySchedulerMock> abilityScheduler_{ nullptr };
};

void LifecycleDealTest::SetUpTestCase(void)
{}
void LifecycleDealTest::TearDownTestCase(void)
{}
void LifecycleDealTest::TearDown()
{}

void LifecycleDealTest::SetUp()
{
    lifecycleDeal_ = std::make_shared<LifecycleDeal>();
    abilityScheduler_ = new AbilitySchedulerMock();
}

/*
 * Feature: LifecycleDeal
 * Function: Activate
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal Activate
 * EnvConditions:NA
 * CaseDescription: Verify activate operation and call mock once
 */
HWTEST_F(LifecycleDealTest, LifecycleDeal_oprator_001, TestSize.Level1)
{
    LifeCycleStateInfo val;
    EXPECT_CALL(*abilityScheduler_, ScheduleAbilityTransaction(::testing::_, ::testing::_, ::testing::_))
        .Times(1)
        .WillOnce(testing::DoAll(testing::SaveArg<1>(&val), testing::Return(true)));

    const Want want;
    CallerInfo caller;
    caller.deviceId = "device";
    caller.bundleName = "bundle";
    caller.abilityName = "LifecycleDealTest";

    LifeCycleStateInfo info;
    info.caller = caller;
    lifecycleDeal_->Activate(want, info);
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->Activate(want, info);

    EXPECT_EQ(val.caller.deviceId, caller.deviceId);
    EXPECT_EQ(val.caller.bundleName, caller.bundleName);
    EXPECT_EQ(val.caller.abilityName, caller.abilityName);
}

/*
 * Feature: LifecycleDeal
 * Function: Inactivate
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal Inactivate
 * EnvConditions:NA
 * CaseDescription: Verify Inactivate operation and call mock once
 */
HWTEST_F(LifecycleDealTest, LifecycleDeal_oprator_002, TestSize.Level1)
{
    LifeCycleStateInfo val;
    EXPECT_CALL(*abilityScheduler_, ScheduleAbilityTransaction(::testing::_, ::testing::_, ::testing::_))
        .Times(1)
        .WillOnce(testing::DoAll(testing::SaveArg<1>(&val), testing::Return(true)));

    const Want want;
    CallerInfo caller;
    caller.deviceId = "device";
    caller.bundleName = "bundle";
    caller.abilityName = "LifecycleDealTest";

    LifeCycleStateInfo info;
    info.caller = caller;
    lifecycleDeal_->Inactivate(want, info);
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->Inactivate(want, info);

    EXPECT_EQ(val.caller.deviceId, caller.deviceId);
    EXPECT_EQ(val.caller.bundleName, caller.bundleName);
    EXPECT_EQ(val.caller.abilityName, caller.abilityName);
}

/*
 * Feature: LifecycleDeal
 * Function: MoveToBackground
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal MoveToBackground
 * EnvConditions:NA
 * CaseDescription: Verify MoveToBackground operation and call mock once
 */
HWTEST_F(LifecycleDealTest, LifecycleDeal_oprator_003, TestSize.Level1)
{
    LifeCycleStateInfo val;
    EXPECT_CALL(*abilityScheduler_, ScheduleAbilityTransaction(::testing::_, ::testing::_, ::testing::_))
        .Times(1)
        .WillOnce(testing::DoAll(testing::SaveArg<1>(&val), testing::Return(true)));

    const Want want;
    CallerInfo caller;
    caller.deviceId = "device";
    caller.bundleName = "bundle";
    caller.abilityName = "LifecycleDealTest";

    LifeCycleStateInfo info;
    info.caller = caller;
    lifecycleDeal_->MoveToBackground(want, info);
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->MoveToBackground(want, info);

    EXPECT_EQ(val.caller.deviceId, caller.deviceId);
    EXPECT_EQ(val.caller.bundleName, caller.bundleName);
    EXPECT_EQ(val.caller.abilityName, caller.abilityName);
}

/*
 * Feature: LifecycleDeal
 * Function: ConnectAbility
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal ConnectAbility
 * EnvConditions:NA
 * CaseDescription: Verify ConnectAbility operation and call mock once
 */
HWTEST_F(LifecycleDealTest, LifecycleDeal_oprator_004, TestSize.Level1)
{
    EXPECT_CALL(*abilityScheduler_, ScheduleConnectAbility(::testing::_)).Times(1);
    const Want want;
    lifecycleDeal_->ConnectAbility(want);
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->ConnectAbility(want);
}

/*
 * Feature: LifecycleDeal
 * Function: DisconnectAbility
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal DisconnectAbility
 * EnvConditions:NA
 * CaseDescription: Verify DisconnectAbility operation and call mock once
 */
HWTEST_F(LifecycleDealTest, LifecycleDeal_oprator_005, TestSize.Level1)
{
    EXPECT_CALL(*abilityScheduler_, ScheduleDisconnectAbility(::testing::_)).Times(1);

    const Want want;
    lifecycleDeal_->DisconnectAbility(want);
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->DisconnectAbility(want);
}

/*
 * Feature: LifecycleDeal
 * Function: Terminate
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal Terminate
 * EnvConditions:NA
 * CaseDescription: Verify Terminate operation and call mock once
 */
HWTEST_F(LifecycleDealTest, LifecycleDeal_oprator_006, TestSize.Level1)
{
    EXPECT_CALL(*abilityScheduler_, ScheduleAbilityTransaction(::testing::_, ::testing::_, ::testing::_))
        .Times(1);

    const Want want;
    CallerInfo caller;
    caller.deviceId = "device";
    caller.bundleName = "bundle";
    caller.abilityName = "LifecycleDealTest";

    LifeCycleStateInfo info;
    info.caller = caller;
    lifecycleDeal_->Activate(want, info);
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->Activate(want, info);
}

/*
 * Feature: LifecycleDeal
 * Function: CommandAbility
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal CommandAbility
 * EnvConditions:NA
 * CaseDescription: Verify CommandAbility operation and call mock once
 */
HWTEST_F(LifecycleDealTest, LifecycleDeal_oprator_007, TestSize.Level1)
{
    EXPECT_CALL(*abilityScheduler_, ScheduleCommandAbility(::testing::_, ::testing::_, ::testing::_)).Times(1);
    const Want want;
    LifeCycleStateInfo info;
    lifecycleDeal_->CommandAbility(want, false, 1);
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->CommandAbility(want, false, 1);
}

/*
 * Feature: LifecycleDeal
 * Function: CommandAbilityWindow
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal CommandAbilityWindow
 * EnvConditions:NA
 * CaseDescription: Verify CommandAbilityWindow operation and call mock once
 * @tc.require: AR000I8B26
 */
HWTEST_F(LifecycleDealTest, LifecycleDeal_oprator_008, TestSize.Level1)
{
    EXPECT_CALL(*abilityScheduler_, ScheduleCommandAbilityWindow(::testing::_, ::testing::_, ::testing::_)).Times(1);
    sptr<SessionInfo> sessionInfo = new (std::nothrow) SessionInfo();
    EXPECT_NE(sessionInfo, nullptr);
    const Want want;
    lifecycleDeal_->CommandAbilityWindow(want, sessionInfo, AAFwk::WIN_CMD_FOREGROUND);
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->CommandAbilityWindow(want, sessionInfo, AAFwk::WIN_CMD_FOREGROUND);
}

/*
 * Feature: LifecycleDeal
 * Function: SaveAbilityState
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal SaveAbilityState
 * EnvConditions:NA
 * CaseDescription: Verify SaveAbilityState operation and call mock once
 * @tc.require: AR000I8B26
 */
HWTEST_F(LifecycleDealTest, SaveAbilityStateTest_001, TestSize.Level1)
{
    EXPECT_CALL(*abilityScheduler_, ScheduleSaveAbilityState()).Times(1);
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->SaveAbilityState();
}

/*
 * Feature: LifecycleDeal
 * Function: RestoreAbilityState
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal RestoreAbilityState
 * EnvConditions:NA
 * CaseDescription: Verify RestoreAbilityState operation and call mock once
 * @tc.require: AR000I8B26
 */
HWTEST_F(LifecycleDealTest, RestoreAbilityState_001, TestSize.Level1)
{
    EXPECT_CALL(*abilityScheduler_, ScheduleRestoreAbilityState(::testing::_)).Times(1);
    PacMap inState;
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->RestoreAbilityState(inState);
}

/*
 * Feature: LifecycleDeal
 * Function: ForegroundNew
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal ForegroundNew
 * EnvConditions:NA
 * CaseDescription: Verify ForegroundNew operation and call mock once
 * @tc.require: AR000I8B26
 */
HWTEST_F(LifecycleDealTest, ForegroundNew_001, TestSize.Level1)
{
    EXPECT_CALL(*abilityScheduler_, ScheduleAbilityTransaction(::testing::_, ::testing::_, ::testing::_)).Times(1);
    Want want;
    LifeCycleStateInfo stateInfo;
    sptr<SessionInfo> sessionInfo;
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->ForegroundNew(want, stateInfo, sessionInfo);
}

/*
 * Feature: LifecycleDeal
 * Function: BackgroundNew
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal BackgroundNew
 * EnvConditions:NA
 * CaseDescription: Verify BackgroundNew operation and call mock once
 * @tc.require: AR000I8B26
 */
HWTEST_F(LifecycleDealTest, BackgroundNew_001, TestSize.Level1)
{
    EXPECT_CALL(*abilityScheduler_, ScheduleAbilityTransaction(::testing::_, ::testing::_, ::testing::_)).Times(1);
    Want want;
    LifeCycleStateInfo stateInfo;
    sptr<SessionInfo> sessionInfo;
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->BackgroundNew(want, stateInfo, sessionInfo);
}

/*
 * Feature: LifecycleDeal
 * Function: ContinueAbility
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal ContinueAbility
 * EnvConditions:NA
 * CaseDescription: Verify ContinueAbility operation and call mock once
 * @tc.require: AR000I8B26
 */
HWTEST_F(LifecycleDealTest, ContinueAbility_001, TestSize.Level1)
{
    EXPECT_CALL(*abilityScheduler_, ContinueAbility(::testing::_, ::testing::_)).Times(1);
    std::string deviceId = "101";
    uint32_t versionCode = 1;
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->ContinueAbility(deviceId, versionCode);
}

/*
 * Feature: LifecycleDeal
 * Function: NotifyContinuationResult
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal NotifyContinuationResult
 * EnvConditions:NA
 * CaseDescription: Verify NotifyContinuationResult operation and call mock once
 * @tc.require: AR000I8B26
 */
HWTEST_F(LifecycleDealTest, NotifyContinuationResult_001, TestSize.Level1)
{
    EXPECT_CALL(*abilityScheduler_, NotifyContinuationResult(::testing::_)).Times(1);
    int32_t result = 1;
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->NotifyContinuationResult(result);
}

/*
 * Feature: LifecycleDeal
 * Function: ShareData
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal ShareData
 * EnvConditions:NA
 * CaseDescription: Verify ShareData operation and call mock once
 * @tc.require: AR000I8B26
 */
HWTEST_F(LifecycleDealTest, ShareData_001, TestSize.Level1)
{
    EXPECT_CALL(*abilityScheduler_, ScheduleShareData(::testing::_)).Times(1);
    int32_t result = 1;
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    lifecycleDeal_->ShareData(result);
}

/*
 * Feature: LifecycleDeal
 * Function: PrepareTerminateAbility
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal PrepareTerminateAbility
 * EnvConditions:NA
 * CaseDescription: Verify PrepareTerminateAbility operation and call mock once
 * @tc.require: AR000I8B26
 */
HWTEST_F(LifecycleDealTest, PrepareTerminateAbility_001, TestSize.Level1)
{
    bool result = lifecycleDeal_->PrepareTerminateAbility();
    EXPECT_FALSE(result);
}

/*
 * Feature: LifecycleDeal
 * Function: PrepareTerminateAbility
 * SubFunction: NA
 * FunctionPoints: LifecycleDeal PrepareTerminateAbility
 * EnvConditions:NA
 * CaseDescription: Verify PrepareTerminateAbility operation and call mock once
 * @tc.require: AR000I8B26
 */
HWTEST_F(LifecycleDealTest, PrepareTerminateAbility_002, TestSize.Level1)
{
    EXPECT_CALL(*abilityScheduler_, SchedulePrepareTerminateAbility()).Times(1);
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    EXPECT_FALSE(lifecycleDeal_->PrepareTerminateAbility());
}

/*
 * Feature: UpdateSessionToken
 * Function: ShareData
 * SubFunction: NA
 * FunctionPoints: UpdateSessionToken ShareData
 * EnvConditions:NA
 * CaseDescription: Verify UpdateSessionToken operation and call mock once
 * @tc.require: AR000I8B26
 */
HWTEST_F(LifecycleDealTest, UpdateSessionToken_001, TestSize.Level1)
{
    sptr<IRemoteObject> sessionToken = nullptr;
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    EXPECT_EQ(abilityScheduler_->code_, 0);
    lifecycleDeal_->UpdateSessionToken(sessionToken);
    EXPECT_EQ(abilityScheduler_->code_, ABILITY_SCHEDULER_MOCK_VALUE);
}

/*
 * Feature: ScheduleCollaborate
 * Function: ShareData
 * SubFunction: NA
 * FunctionPoints: ScheduleCollaborate ShareData
 * EnvConditions:NA
 * CaseDescription: Verify ScheduleCollaborate operation and call mock once
 * @tc.require: AR000I8B26
 */
HWTEST_F(LifecycleDealTest, ScheduleCollaborate_001, TestSize.Level1)
{
    sptr<IRemoteObject> sessionToken = nullptr;
    Want want;
    lifecycleDeal_->SetScheduler(abilityScheduler_);
    EXPECT_EQ(abilityScheduler_->code_, 0);
    lifecycleDeal_->ScheduleCollaborate(want);
    EXPECT_EQ(abilityScheduler_->code_, ABILITY_SCHEDULER_MOCK_VALUE);
}
}  // namespace AAFwk
}  // namespace OHOS
