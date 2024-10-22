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
#define private public
#define protected public
#include "ability_record.h"
#include "hilog_tag_wrapper.h"
#include "mission.h"
#include "mission_list_manager.h"
#include "ability_manager_service.h"
#include "task_handler_wrap.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
class MissionListManagerSecondTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<AbilityRecord> InitAbilityRecord();
};

void MissionListManagerSecondTest::SetUpTestCase(void)
{}
void MissionListManagerSecondTest::TearDownTestCase(void)
{}
void MissionListManagerSecondTest::SetUp(void)
{}
void MissionListManagerSecondTest::TearDown(void)
{}

std::shared_ptr<AbilityRecord> MissionListManagerSecondTest::InitAbilityRecord()
{
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    return abilityRecord;
}

/*
 * Feature: MissionListManager
 * Function: PrepareClearMissionLocked
 * SubFunction: NA
 * FunctionPoints: MissionListManager PrepareClearMissionLocked
 * EnvConditions: NA
 * CaseDescription: Verify PrepareClearMissionLocked
 */
HWTEST_F(MissionListManagerSecondTest, PrepareClearMissionLocked_001, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    int missionId = 1;
    std::string missionName = "missionName";
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    std::shared_ptr<Mission> mission;

    auto result = missionListManager->PrepareClearMissionLocked(missionId, mission);
    EXPECT_EQ(ERR_OK, result);

    mission = std::make_shared<Mission>(missionId, nullptr, missionName);
    result = missionListManager->PrepareClearMissionLocked(missionId, mission);
    EXPECT_EQ(ERR_OK, result);
    abilityRecord->SetTerminatingState();
    mission = std::make_shared<Mission>(missionId, abilityRecord, missionName);
    result = missionListManager->PrepareClearMissionLocked(missionId, mission);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * Feature: MissionListManager
 * Function: CheckPrepareTerminateEnable
 * SubFunction: NA
 * FunctionPoints: MissionListManager CheckPrepareTerminateEnable
 * EnvConditions: NA
 * CaseDescription: Verify CheckPrepareTerminateEnable
 */
HWTEST_F(MissionListManagerSecondTest, CheckPrepareTerminateEnable_001, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    int missionId = 1;
    std::string missionName = "missionName";
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    std::shared_ptr<Mission> mission;
    auto result = missionListManager->CheckPrepareTerminateEnable(mission);
    EXPECT_EQ(false, result);
    missionListManager->isPrepareTerminateEnable_ = true;
    result = missionListManager->CheckPrepareTerminateEnable(mission);
    EXPECT_EQ(false, result);
    mission = std::make_shared<Mission>(missionId, nullptr, missionName);
    result = missionListManager->CheckPrepareTerminateEnable(mission);
    EXPECT_EQ(false, result);

    mission = std::make_shared<Mission>(missionId, abilityRecord, missionName);
    abilityRecord->SetTerminatingState();
    result = missionListManager->CheckPrepareTerminateEnable(mission);
    EXPECT_EQ(false, result);

    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::PAGE;
    abilityRequest.abilityInfo.isStageBasedModel = false;
    abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    mission = std::make_shared<Mission>(missionId, abilityRecord, missionName);
    result = missionListManager->CheckPrepareTerminateEnable(mission);
    EXPECT_EQ(false, result);
    abilityRequest.abilityInfo.isStageBasedModel = true;
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::UNKNOWN;
    abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    mission = std::make_shared<Mission>(missionId, abilityRecord, missionName);
    result = missionListManager->CheckPrepareTerminateEnable(mission);
    EXPECT_EQ(false, result);

    abilityRequest.abilityInfo.isStageBasedModel = true;
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    mission = std::make_shared<Mission>(missionId, abilityRecord, missionName);
    result = missionListManager->CheckPrepareTerminateEnable(mission);
    EXPECT_EQ(false, result);
}

/*
 * Feature: MissionListManager
 * Function: SignRestartAppFlag
 * SubFunction: NA
 * FunctionPoints: MissionListManager SignRestartAppFlag
 * EnvConditions: NA
 * CaseDescription: Verify SignRestartAppFlag
 */
HWTEST_F(MissionListManagerSecondTest, SignRestartAppFlag_001, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    int32_t uid = 100;
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(1, abilityRecord, "missionName");
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    std::shared_ptr<MissionList> missionList2;
    missionList->missions_.push_front(mission);
    missionListManager->currentMissionLists_.push_front(missionList);
    missionListManager->currentMissionLists_.push_front(missionList2);
    missionListManager->SignRestartAppFlag(uid);
    auto result = missionListManager->currentMissionLists_.size();
    EXPECT_EQ(2, result);

    missionListManager->defaultStandardList_ = missionList;
    missionListManager->SignRestartAppFlag(uid);
    result = missionListManager->defaultStandardList_->missions_.size();
    EXPECT_EQ(0, result);

    missionListManager->defaultSingleList_ = missionList;
    missionListManager->SignRestartAppFlag(uid);
    result = missionListManager->defaultSingleList_->missions_.size();
    EXPECT_EQ(0, result);
}
}  // namespace AAFwk
}  // namespace OHOS
