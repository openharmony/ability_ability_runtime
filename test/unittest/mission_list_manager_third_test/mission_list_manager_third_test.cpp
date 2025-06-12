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
class MissionListManagerThirdTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<AbilityRecord> InitAbilityRecord();
    int32_t ERR_INVALID_VALUE = 22;
};

void MissionListManagerThirdTest::SetUpTestCase(void)
{}
void MissionListManagerThirdTest::TearDownTestCase(void)
{}
void MissionListManagerThirdTest::SetUp(void)
{}
void MissionListManagerThirdTest::TearDown(void)
{}

std::shared_ptr<AbilityRecord> MissionListManagerThirdTest::InitAbilityRecord()
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
 * Function: FindEarliestMission
 * SubFunction: NA
 * FunctionPoints: MissionListManager FindEarliestMission
 * EnvConditions: NA
 * CaseDescription: Verify FindEarliestMission
 */
HWTEST_F(MissionListManagerThirdTest, FindEarliestMission_001, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    auto ret = missionListManager->FindEarliestMission();
    EXPECT_EQ(ret, nullptr);
}

/*
 * Feature: MissionListManager
 * Function: FindEarliestMission
 * SubFunction: NA
 * FunctionPoints: MissionListManager FindEarliestMission
 * EnvConditions: NA
 * CaseDescription: Verify FindEarliestMission
 */
HWTEST_F(MissionListManagerThirdTest, FindEarliestMission_002, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    missionListManager->Init();
    auto ret = missionListManager->FindEarliestMission();
    EXPECT_EQ(ret, nullptr);
}

/*
 * Feature: MissionListManager
 * Function: MinimizeAbility
 * SubFunction: NA
 * FunctionPoints: MissionListManager MinimizeAbility
 * EnvConditions: NA
 * CaseDescription: Verify MinimizeAbility
 */
HWTEST_F(MissionListManagerThirdTest, MinimizeAbility_001, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    sptr<IRemoteObject> token = nullptr;
    auto ret = missionListManager->MinimizeAbility(token, true);
    EXPECT_EQ(ret, INNER_ERR);
}

/*
 * Feature: MissionListManager
 * Function: GetMissionInfo
 * SubFunction: NA
 * FunctionPoints: MissionListManager GetMissionInfo
 * EnvConditions: NA
 * CaseDescription: Verify GetMissionInfo
 */
HWTEST_F(MissionListManagerThirdTest, GetMissionInfo_001, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    MissionInfo missionInfo;
    auto ret = missionListManager->GetMissionInfo(0, missionInfo);
    EXPECT_EQ(ret, -1);
}

/*
 * Feature: MissionListManager
 * Function: GetReusedStandardMission
 * SubFunction: NA
 * FunctionPoints: MissionListManager GetReusedStandardMission
 * EnvConditions: NA
 * CaseDescription: Verify GetReusedStandardMission
 */
HWTEST_F(MissionListManagerThirdTest, GetReusedStandardMission_001, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.launchMode = AppExecFwk::LaunchMode::SINGLETON;
    auto ret = missionListManager->GetReusedStandardMission(abilityRequest);
    EXPECT_EQ(ret, nullptr);
}

/*
 * Feature: MissionListManager
 * Function: GetReusedStandardMission
 * SubFunction: NA
 * FunctionPoints: MissionListManager GetReusedStandardMission
 * EnvConditions: NA
 * CaseDescription: Verify GetReusedStandardMission
 */
HWTEST_F(MissionListManagerThirdTest, GetReusedStandardMission_002, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.launchMode = AppExecFwk::LaunchMode::STANDARD;
    abilityRequest.startRecent = false;
    abilityRequest.abilityInfo.applicationInfo.isLauncherApp = true;
    auto ret = missionListManager->GetReusedStandardMission(abilityRequest);
    EXPECT_EQ(ret, nullptr);
}

/*
 * Feature: MissionListManager
 * Function: GetReusedStandardMission
 * SubFunction: NA
 * FunctionPoints: MissionListManager GetReusedStandardMission
 * EnvConditions: NA
 * CaseDescription: Verify GetReusedStandardMission
 */
HWTEST_F(MissionListManagerThirdTest, GetReusedStandardMission_003, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.launchMode = AppExecFwk::LaunchMode::STANDARD;
    abilityRequest.startRecent = false;
    abilityRequest.abilityInfo.applicationInfo.isLauncherApp = true;
    missionListManager->Init();
    auto ret = missionListManager->GetReusedStandardMission(abilityRequest);
    EXPECT_EQ(ret, nullptr);
}

/*
 * Feature: MissionListManager
 * Function: MinimizeAbilityLocked
 * SubFunction: NA
 * FunctionPoints: MissionListManager MinimizeAbilityLocked
 * EnvConditions: NA
 * CaseDescription: Verify MinimizeAbilityLocked
 */
HWTEST_F(MissionListManagerThirdTest, MinimizeAbilityLocked_001, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    int ret = missionListManager->MinimizeAbilityLocked(abilityRecord, true);
    EXPECT_EQ(ret, ERR_OK);
}

/*
 * Feature: MissionListManager
 * Function: BackToCallerAbilityWithResult
 * SubFunction: NA
 * FunctionPoints: MissionListManager BackToCallerAbilityWithResult
 * EnvConditions: NA
 * CaseDescription: Verify BackToCallerAbilityWithResult
 */
HWTEST_F(MissionListManagerThirdTest, BackToCallerAbilityWithResult_001, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    std::shared_ptr<AbilityRecord> abilityRecord = nullptr;
    Want resultWant;
    int32_t ret = missionListManager->BackToCallerAbilityWithResult(abilityRecord, 0, &resultWant, 0);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/*
 * Feature: MissionListManager
 * Function: GetAbilityNumber
 * SubFunction: NA
 * FunctionPoints: MissionListManager GetAbilityNumber
 * EnvConditions: NA
 * CaseDescription: Verify GetAbilityNumber
 */
HWTEST_F(MissionListManagerThirdTest, GetAbilityNumber_001, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.deviceId = "id";
    abilityRequest.abilityInfo.bundleName = "bundle";
    abilityRequest.abilityInfo.name = "name";
    AppExecFwk::ElementName element(abilityRequest.abilityInfo.deviceId, abilityRequest.abilityInfo.bundleName,
        abilityRequest.abilityInfo.name, abilityRequest.abilityInfo.moduleName);
    int32_t ret = missionListManager->GetAbilityNumber(element);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: MissionListManager
 * Function: DoAbilityForeground
 * SubFunction: NA
 * FunctionPoints: MissionListManager DoAbilityForeground
 * EnvConditions: NA
 * CaseDescription: Verify DoAbilityForeground
 */
HWTEST_F(MissionListManagerThirdTest, DoAbilityForeground_001, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    int ret = missionListManager->DoAbilityForeground(abilityRecord, 0);
    EXPECT_EQ(ret, ERR_OK);
}

/*
 * Feature: MissionListManager
 * Function: DoAbilityForeground
 * SubFunction: NA
 * FunctionPoints: MissionListManager DoAbilityForeground
 * EnvConditions: NA
 * CaseDescription: Verify DoAbilityForeground
 */
HWTEST_F(MissionListManagerThirdTest, DoAbilityForeground_002, TestSize.Level1)
{
    int userId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    std::shared_ptr<AbilityRecord> abilityRecord = nullptr;
    int ret = missionListManager->DoAbilityForeground(abilityRecord, 0);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}
}  // namespace AAFwk
}  // namespace OHOS
