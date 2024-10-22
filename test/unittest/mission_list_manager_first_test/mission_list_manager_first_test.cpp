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
#include "ability_config.h"
#include "ability_info.h"
#include "ability_manager_errors.h"
#include "ability_manager_service.h"
#include "hilog_tag_wrapper.h"
#include "mission.h"
#include "mission_info_mgr.h"
#include "mission_list_manager.h"
#include "startup_util.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
namespace {
#ifdef WITH_DLP
const std::string DLP_INDEX = "ohos.dlp.params.index";
#endif // WITH_DLP
constexpr uint32_t INPUT_ZERO = 0;
constexpr uint32_t INPUT_ONE = 1;
constexpr uint32_t INPUT_TWO = 2;
constexpr uint32_t INPUT_FOUR = 4;
constexpr uint32_t INPUT_FIFTH = 5;
constexpr uint32_t INPUT_SIX = 6;
constexpr uint32_t INPUT_EIGHT = 8;
}
class MissionListManagerFirstTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void InitMockMission(std::shared_ptr<MissionListManager>& missionListManager,
        AbilityRequest& abilityRequest, Want& want, std::shared_ptr<AbilityRecord>& ability);
    std::shared_ptr<AbilityRecord> InitAbilityRecord();
};

void MissionListManagerFirstTest::SetUpTestCase(void)
{}
void MissionListManagerFirstTest::TearDownTestCase(void)
{}
void MissionListManagerFirstTest::SetUp(void)
{}
void MissionListManagerFirstTest::TearDown(void)
{}

void MissionListManagerFirstTest::InitMockMission(std::shared_ptr<MissionListManager>& missionListManager,
    AbilityRequest& abilityRequest, Want& want, std::shared_ptr<AbilityRecord>& ability)
{
    missionListManager->Init();

    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.launchMode = AppExecFwk::LaunchMode::SPECIFIED;
    AppExecFwk::ApplicationInfo applicationInfo;
    ability = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    auto mission = std::make_shared<Mission>(11, ability, "missionName");
    mission->abilityRecord_ = ability;
    ability->SetSpecifiedFlag("flag");
    ability->SetIsNewWant(false);

    abilityRequest.callerToken = ability->GetToken();
    missionListManager->EnqueueWaitingAbility(abilityRequest);
    missionListManager->defaultStandardList_->AddMissionToTop(mission);
}

bool g_notifyWindowTransitionCalled = false;
bool g_cancelStartingWindowCalled = false;

class MockWMSHandler : public IWindowManagerServiceHandler {
public:
    virtual void NotifyWindowTransition(sptr<AbilityTransitionInfo> fromInfo, sptr<AbilityTransitionInfo> toInfo,
        bool& animaEnabled)
    {
        g_notifyWindowTransitionCalled = true;
    }

    virtual int32_t GetFocusWindow(sptr<IRemoteObject>& abilityToken)
    {
        return 0;
    }

    virtual void StartingWindow(sptr<AbilityTransitionInfo> info,
        std::shared_ptr<Media::PixelMap> pixelMap, uint32_t bgColor) {}

    virtual void StartingWindow(sptr<AbilityTransitionInfo> info, std::shared_ptr<Media::PixelMap> pixelMap) {}

    virtual void CancelStartingWindow(sptr<IRemoteObject> abilityToken)
    {
        g_cancelStartingWindowCalled = true;
    }

    virtual int32_t MoveMissionsToForeground(const std::vector<int32_t>& missionIds, int32_t topMissionId)
    {
        return 0;
    }

    virtual int32_t MoveMissionsToBackground(const std::vector<int32_t>& missionIds, std::vector<int32_t>& result)
    {
        return 0;
    }

    virtual sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    }

    virtual void NotifyAnimationAbilityDied(sptr<AbilityTransitionInfo> info) {}
};

std::shared_ptr<AbilityRecord> MissionListManagerFirstTest::InitAbilityRecord()
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
 * Function: ClearAllMissions
 * SubFunction: NA
 * FunctionPoints: MissionListManager ClearAllMissions
 * EnvConditions: NA
 * CaseDescription: Verify ClearAllMissions
 */
HWTEST_F(MissionListManagerFirstTest, ClearAllMissions_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ClearAllMissions_001 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    missionListManager->Init();
    sptr<IMissionListener> listener;
    missionListManager->listenerController_ = nullptr;
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.launchMode = AppExecFwk::LaunchMode::SINGLETON;
    Want want;
    AppExecFwk::ApplicationInfo applicationInfo;
    auto ability = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    auto mission = std::make_shared<Mission>(11, ability, "missionName");
    mission->abilityRecord_ = ability;
    ability->SetSpecifiedFlag("flag");
    missionListManager->defaultSingleList_->AddMissionToTop(mission);
    missionListManager->defaultStandardList_->AddMissionToTop(mission);
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    abilityRecord->currentState_ = FOREGROUND;
    std::shared_ptr<Mission> missions = std::make_shared<Mission>(1, abilityRecord, "missionName");
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    missionList->missions_.push_front(missions);
    missionListManager->currentMissionLists_.push_front(missionList);
    auto result = missionListManager->ClearAllMissions();
    missionList = std::make_shared<MissionList>(MissionListType::LAUNCHER);
    missionList->missions_.push_front(missions);
    missionListManager->currentMissionLists_.push_front(missionList);
    result = missionListManager->ClearAllMissions();
    EXPECT_EQ(result, ERR_OK);
    missionListManager.reset();
    TAG_LOGI(AAFwkTag::TEST, "ClearAllMissions_001 end");
}

/*
 * Feature: MissionListManager
 * Function: ClearAllMissionsLocked
 * SubFunction: NA
 * FunctionPoints: MissionListManager ClearAllMissionsLocked
 * EnvConditions: NA
 * CaseDescription: Verify ClearAllMissionsLocked
 */
HWTEST_F(MissionListManagerFirstTest, ClearAllMissionsLocked_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ClearAllMissionsLocked_001 start");
    int userId = 3; // 3 means user id
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    EXPECT_NE(missionListManager, nullptr);
    missionListManager->Init();
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    abilityRecord->currentState_ = FOREGROUND;
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(1, abilityRecord, "missionName");
    mission->SetLockedState(true);
    std::list<std::shared_ptr<Mission>> foregroundAbilities;
    std::list<std::shared_ptr<Mission>> missionList;
    missionList.push_front(mission);
    bool searchActive = true;
    missionListManager->ClearAllMissionsLocked(missionList, foregroundAbilities, searchActive);
    EXPECT_FALSE(missionList.empty()); // locked mission not be cleared.
    std::shared_ptr<Mission> missions = nullptr;
    std::list<std::shared_ptr<Mission>> missionLists;
    missionLists.push_front(missions);
    missionListManager->ClearAllMissionsLocked(missionLists, foregroundAbilities, searchActive);
    EXPECT_FALSE(missionList.empty()); // nullptr mission can't be cleared.
    TAG_LOGI(AAFwkTag::TEST, "ClearAllMissionsLocked_001 end");
}

/*
 * Feature: MissionListManager
 * Function: ClearAllMissionsLocked
 * SubFunction: NA
 * FunctionPoints: MissionListManager ClearAllMissionsLocked
 * EnvConditions: NA
 * CaseDescription: Verify ClearAllMissionsLocked
 */
HWTEST_F(MissionListManagerFirstTest, ClearAllMissionsLocked_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ClearAllMissionsLocked_002 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    EXPECT_NE(missionListManager, nullptr);
    missionListManager->Init();
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    abilityRecord->SetUid(userId);
    std::shared_ptr<Mission> missions = std::make_shared<Mission>(1, abilityRecord, "missionName");
    missions->SetLockedState(false);
    missions->SetUnclearable(true);
    std::list<std::shared_ptr<Mission>> foregroundAbilities;
    std::list<std::shared_ptr<Mission>> missionLists;
    missionLists.push_front(missions);
    bool searchActive = true;
    missionListManager->ClearAllMissionsLocked(missionLists, foregroundAbilities, searchActive);
    std::shared_ptr<Mission> mission1 = std::make_shared<Mission>(1, abilityRecord, "missionName");
    mission1->SetLockedState(false);
    mission1->SetUnclearable(false);
    std::list<std::shared_ptr<Mission>> missionList1;
    missionList1.push_front(mission1);
    missionListManager->ClearAllMissionsLocked(missionList1, foregroundAbilities, searchActive);
    EXPECT_FALSE(foregroundAbilities.empty()); // get foreground ability
    TAG_LOGI(AAFwkTag::TEST, "ClearAllMissionsLocked_002 end");
}

/*
 * Feature: MissionListManager
 * Function: ClearAllMissionsLocked
 * SubFunction: NA
 * FunctionPoints: MissionListManager ClearAllMissionsLocked
 * EnvConditions: NA
 * CaseDescription: Verify ClearAllMissionsLocked
 */
HWTEST_F(MissionListManagerFirstTest, ClearAllMissionsLocked_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ClearAllMissionsLocked_003 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    EXPECT_NE(missionListManager, nullptr);
    missionListManager->Init();
    missionListManager->isPrepareTerminateEnable_ = true;
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    abilityRecord->currentState_ = FOREGROUND;
    abilityRecord->SetUid(userId);
    std::shared_ptr<Mission> missions = std::make_shared<Mission>(1, abilityRecord, "missionName");
    missions->SetLockedState(false);
    missions->SetUnclearable(false);
    std::list<std::shared_ptr<Mission>> foregroundAbilities;
    std::list<std::shared_ptr<Mission>> missionLists;
    missionLists.push_front(missions);
    bool searchActive = true;
    missionListManager->ClearAllMissionsLocked(missionLists, foregroundAbilities, searchActive);
    EXPECT_FALSE(foregroundAbilities.empty()); // get forground ability record
    foregroundAbilities.clear();
    searchActive = false;
    int32_t int32Param = 3;
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(int32Param, abilityRecord);
    mission->SetLockedState(false);
    mission->SetUnclearable(false);
    std::list<std::shared_ptr<Mission>> missionList1;
    missionList1.push_front(mission);
    missionListManager->ClearAllMissionsLocked(missionList1, foregroundAbilities, searchActive);
    EXPECT_TRUE(foregroundAbilities.empty()); // searchActive false, get no Foreground Ability
    TAG_LOGI(AAFwkTag::TEST, "ClearAllMissionsLocked_003 end");
}

/*
 * Feature: MissionListManager
 * Function: ClearAllMissionsLocked
 * SubFunction: NA
 * FunctionPoints: MissionListManager ClearAllMissionsLocked
 * EnvConditions: NA
 * CaseDescription: Verify ClearAllMissionsLocked
 */
HWTEST_F(MissionListManagerFirstTest, ClearAllMissionsLocked_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ClearAllMissionsLocked_004 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    EXPECT_NE(missionListManager, nullptr);
    missionListManager->Init();
    missionListManager->isPrepareTerminateEnable_ = true;
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    abilityRecord->currentState_ = FOREGROUND;
    abilityRecord->SetUid(userId);
    abilityRecord->abilityInfo_.isStageBasedModel = true;
    std::shared_ptr<Mission> missions = std::make_shared<Mission>(1, abilityRecord, "missionName");
    missions->SetLockedState(false);
    missions->SetUnclearable(false);
    std::list<std::shared_ptr<Mission>> foregroundAbilities;
    std::list<std::shared_ptr<Mission>> missionLists;
    missionLists.push_front(missions);
    bool searchActive = true;
    missionListManager->ClearAllMissionsLocked(missionLists, foregroundAbilities, searchActive);
    EXPECT_FALSE(foregroundAbilities.empty()); // get Foreground Ability
    foregroundAbilities.clear();
    searchActive = false;
    int32_t int32Param = 3;
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(int32Param, abilityRecord);
    mission->SetLockedState(false);
    mission->SetUnclearable(false);
    std::list<std::shared_ptr<Mission>> missionList1;
    missionList1.push_front(mission);
    missionListManager->ClearAllMissionsLocked(missionList1, foregroundAbilities, searchActive);
    EXPECT_TRUE(foregroundAbilities.empty()); // searchActive false, get no Foreground Ability
    TAG_LOGI(AAFwkTag::TEST, "ClearAllMissionsLocked_004 end");
}

/*
 * Feature: MissionListManager
 * Function: UpdateSnapShot
 * SubFunction: NA
 * FunctionPoints: MissionListManager UpdateSnapShot
 * EnvConditions: NA
 * CaseDescription: Verify UpdateSnapShot
 */
HWTEST_F(MissionListManagerFirstTest, UpdateSnapShot_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "UpdateSnapShot_001 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    missionListManager->Init();
    sptr<IRemoteObject> token = nullptr;
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    missionListManager->UpdateSnapShot(token, pixelMap);
    EXPECT_NE(missionListManager, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "UpdateSnapShot_001 end");
}

/*
 * Feature: MissionListManager
 * Function: UpdateSnapShot
 * SubFunction: NA
 * FunctionPoints: MissionListManager UpdateSnapShot
 * EnvConditions: NA
 * CaseDescription: Verify UpdateSnapShot
 */
HWTEST_F(MissionListManagerFirstTest, UpdateSnapShot_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "UpdateSnapShot_002 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    EXPECT_NE(missionListManager, nullptr);
    missionListManager->Init();
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    abilityRecord->abilityInfo_.excludeFromMissions = true;
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(1, abilityRecord, "missionName");
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    missionList->missions_.push_back(mission);
    missionListManager->terminateAbilityList_.clear();
    missionListManager->currentMissionLists_.clear();
    missionListManager->defaultSingleList_ = missionList;
    auto res = missionListManager->GetAbilityRecordByToken(token);
    EXPECT_NE(res, nullptr);
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    missionListManager->UpdateSnapShot(token, pixelMap);
    TAG_LOGI(AAFwkTag::TEST, "UpdateSnapShot_002 end");
}

/*
 * Feature: MissionListManager
 * Function: UpdateSnapShot
 * SubFunction: NA
 * FunctionPoints: MissionListManager UpdateSnapShot
 * EnvConditions: NA
 * CaseDescription: Verify UpdateSnapShot
 */
HWTEST_F(MissionListManagerFirstTest, UpdateSnapShot_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "UpdateSnapShot_003 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    EXPECT_NE(missionListManager, nullptr);
    missionListManager->Init();
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    abilityRecord->abilityInfo_.excludeFromMissions = false;
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(1, abilityRecord, "missionName");
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    missionList->missions_.push_back(mission);
    missionListManager->terminateAbilityList_.clear();
    missionListManager->currentMissionLists_.clear();
    missionListManager->defaultSingleList_ = missionList;
    auto res = missionListManager->GetAbilityRecordByToken(token);
    EXPECT_NE(res, nullptr);
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    missionListManager->listenerController_ = std::make_shared<MissionListenerController>();
    EXPECT_NE(missionListManager->listenerController_, nullptr);
    missionListManager->UpdateSnapShot(token, pixelMap);
    TAG_LOGI(AAFwkTag::TEST, "UpdateSnapShot_003 end");
}

/*
 * Feature: MissionListManager
 * Function: GetContentAndTypeId
 * SubFunction: NA
 * FunctionPoints: MissionListManager GetContentAndTypeId
 * EnvConditions: NA
 * CaseDescription: Verify GetContentAndTypeId
 */
HWTEST_F(MissionListManagerFirstTest, GetContentAndTypeId_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetContentAndTypeId_001 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    EXPECT_NE(missionListManager, nullptr);
    missionListManager->Init();
    uint32_t msgId = INPUT_ZERO;
    std::string msgContent = "msgContent";
    int typeId = 0;
    auto ret = missionListManager->GetContentAndTypeId(msgId, msgContent, typeId);
    msgId = INPUT_ONE;
    ret = missionListManager->GetContentAndTypeId(msgId, msgContent, typeId);
    msgId = INPUT_TWO;
    ret = missionListManager->GetContentAndTypeId(msgId, msgContent, typeId);
    msgId = INPUT_FIFTH;
    ret = missionListManager->GetContentAndTypeId(msgId, msgContent, typeId);
    msgId = INPUT_SIX;
    ret = missionListManager->GetContentAndTypeId(msgId, msgContent, typeId);
    msgId = INPUT_FOUR;
    ret = missionListManager->GetContentAndTypeId(msgId, msgContent, typeId);
    EXPECT_TRUE(ret);
    msgId = INPUT_EIGHT;
    ret = missionListManager->GetContentAndTypeId(msgId, msgContent, typeId);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "GetContentAndTypeId_001 end");
}

/**
 * @tc.name: MissionListManager_DoAbilityForeground_001
 * @tc.desc: Test DoAbilityForeground
 * @tc.type: FUNC
 */
HWTEST_F(MissionListManagerFirstTest, MissionListManager_DoAbilityForeground_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MissionListManager_DoAbilityForeground_001 begin";
    std::shared_ptr<MissionListManager> missionListManager = std::make_shared<MissionListManager>(0);
    std::shared_ptr<AbilityRecord> abilityRecord = nullptr;
    uint32_t flag = 0;

    int32_t ret = missionListManager->DoAbilityForeground(abilityRecord, flag);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo applicationInfo;
    abilityRecord = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);

    ret = missionListManager->DoAbilityForeground(abilityRecord, flag);
    EXPECT_EQ(ret, ERR_OK);
    ret = missionListManager->DoAbilityForeground(abilityRecord, flag);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "MissionListManager_DoAbilityForeground_001 end";
}

/**
 * @tc.name: MissionListManager_GetActiveAbilityList_001
 * @tc.desc: Test GetActiveAbilityList
 * @tc.type: FUNC
 */
HWTEST_F(MissionListManagerFirstTest, MissionListManager_GetActiveAbilityList_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MissionListManager_GetActiveAbilityList_001 begin";
    int32_t uid = 100;
    int32_t pid = 101;
    std::vector<std::string> abilityList;
    std::shared_ptr<MissionListManager> missionListManager = std::make_shared<MissionListManager>(0);
    missionListManager->GetActiveAbilityList(uid, abilityList, pid);

    std::shared_ptr<MissionList> missionListNull = nullptr;
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    missionListManager->currentMissionLists_.push_back(missionListNull);
    missionListManager->currentMissionLists_.push_back(missionList);
    missionListManager->defaultStandardList_ = missionList;
    missionListManager->defaultSingleList_ = missionList;
    missionListManager->GetActiveAbilityList(uid, abilityList, pid);
    EXPECT_EQ(abilityList.size(), 0);

    uid = -1;
    pid = NO_PID;
    Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> abilityRecord = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    abilityRecord->abilityInfo_.name = "abilityName";
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(0, abilityRecord, "");
    missionList->missions_.push_back(mission);
    missionListManager->currentMissionLists_.push_back(missionList);
    missionListManager->defaultStandardList_ = missionList;
    missionListManager->defaultSingleList_ = missionList;
    missionListManager->GetActiveAbilityList(uid, abilityList, pid);
    EXPECT_EQ(abilityList.size(), 1);
    GTEST_LOG_(INFO) << "MissionListManager_GetActiveAbilityList_001 end";
}

/**
 * @tc.name: MissionListManager_IsAppLastAbility_001
 * @tc.desc: Test IsAppLastAbility
 * @tc.type: FUNC
 */
HWTEST_F(MissionListManagerFirstTest, MissionListManager_IsAppLastAbility_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MissionListManager_IsAppLastAbility_001 begin";
    std::shared_ptr<AbilityRecord> abilityRecord = nullptr;
    std::shared_ptr<MissionListManager> missionListManager = std::make_shared<MissionListManager>(0);
    bool ret = missionListManager->IsAppLastAbility(abilityRecord);
    EXPECT_FALSE(ret);

    Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo applicationInfo;
    abilityRecord = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    ret = missionListManager->IsAppLastAbility(abilityRecord);
    EXPECT_FALSE(ret);

    std::shared_ptr<MissionList> missionListNull = nullptr;
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    missionListManager->currentMissionLists_.push_back(missionListNull);
    missionListManager->currentMissionLists_.push_back(missionList);
    ret = missionListManager->IsAppLastAbility(abilityRecord);
    EXPECT_FALSE(ret);
    missionListManager->currentMissionLists_.clear();

    abilityRecord->abilityInfo_.name = "abilityName";
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(0, abilityRecord, "");
    missionList->missions_.push_back(mission);
    missionListManager->currentMissionLists_.push_back(missionList);
    ret = missionListManager->IsAppLastAbility(abilityRecord);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "MissionListManager_IsAppLastAbility_001 end";
}

/*
 * Feature: MissionListManager
 * Function: OnTimeOut
 * SubFunction: NA
 * FunctionPoints: MissionListManager OnTimeOut
 * EnvConditions: NA
 * CaseDescription: Verify OnTimeOut
 */
HWTEST_F(MissionListManagerFirstTest, OnTimeOut_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest OnTimeOut_001 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    uint32_t msgId = 0;
    int64_t eventId = 0;
    missionListManager->currentMissionLists_.clear();
    missionListManager->defaultSingleList_ = missionList;
    missionListManager->defaultStandardList_ = missionList;
    missionListManager->OnTimeOut(msgId, eventId);
    EXPECT_NE(missionListManager, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest OnTimeOut_001 end");
}

/*
 * Feature: MissionListManager
 * Function: OnTimeOut
 * SubFunction: NA
 * FunctionPoints: MissionListManager OnTimeOut
 * EnvConditions: NA
 * CaseDescription: Verify OnTimeOut
 */
HWTEST_F(MissionListManagerFirstTest, OnTimeOut_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest OnTimeOut_002 start");
    int userId = 3;
    uint32_t msgId = 0;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    int64_t abilityRecordId = 0;
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    abilityRecord->missionId_ = abilityRecordId;
    abilityRecord->SetStartingWindow(true);
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    missionListManager->currentMissionLists_.clear();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(1, abilityRecord);
    mission->abilityRecord_ = abilityRecord;
    mission->missionId_ = abilityRecordId;
    missionList->missions_.push_back(mission);
    missionListManager->defaultSingleList_  = missionList;
    missionListManager->defaultStandardList_ = missionList;
    missionListManager->OnTimeOut(msgId, abilityRecordId);
    bool isHalf = true;
    missionListManager->OnTimeOut(msgId, abilityRecordId, isHalf);
    int i = 0;
    uint32_t msgIds[] = {
        AbilityManagerService::LOAD_TIMEOUT_MSG,
        AbilityManagerService::ACTIVE_TIMEOUT_MSG,
        AbilityManagerService::INACTIVE_TIMEOUT_MSG,
        AbilityManagerService::FOREGROUND_TIMEOUT_MSG
    };
    while (i < sizeof(msgIds) / sizeof(uint32_t)) {
        missionListManager->OnTimeOut(msgIds[i], abilityRecordId);
        i++;
    }
    missionListManager->OnTimeOut(msgId, abilityRecordId);
    #ifdef SUPPORT_SCREEN
    missionListManager->OnTimeOut(msgId, abilityRecordId);
    #endif
    EXPECT_TRUE(missionListManager != nullptr);
    missionListManager.reset();
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest OnTimeOut_002 end");
}

/*
 * Feature: MissionListManager
 * Function: HandleForegroundTimeout
 * SubFunction: NA
 * FunctionPoints: MissionListManager HandleForegroundTimeout
 * EnvConditions: NA
 * CaseDescription: Verify HandleForegroundTimeout
 */
HWTEST_F(MissionListManagerFirstTest, HandleForegroundTimeout_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest HandleForegroundTimeout_001 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    std::shared_ptr<AbilityRecord> ability;
    missionListManager->HandleForegroundTimeout(ability);
    ability = InitAbilityRecord();
    int64_t abilityRecordId = 0;
    ability->missionId_ = abilityRecordId;
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    missionListManager->currentMissionLists_.clear();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(1, ability);
    mission->abilityRecord_ = ability;
    mission->missionId_ = abilityRecordId;
    missionList->missions_.push_back(mission);
    missionListManager->defaultSingleList_  = missionList;
    missionListManager->HandleForegroundTimeout(ability);
    EXPECT_TRUE(missionListManager != nullptr);
    missionListManager.reset();
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest HandleForegroundTimeout_001 end");
}

/*
 * Feature: MissionListManager
 * Function: HandleForegroundTimeout
 * SubFunction: NA
 * FunctionPoints: MissionListManager HandleForegroundTimeout
 * EnvConditions: NA
 * CaseDescription: Verify HandleForegroundTimeout
 */
HWTEST_F(MissionListManagerFirstTest, HandleForegroundTimeout_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest HandleForegroundTimeout_002 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    std::shared_ptr<AbilityRecord> ability = InitAbilityRecord();
    ability->currentState_ = AbilityState::FOREGROUNDING;
    int64_t abilityRecordId = 0;
    ability->missionId_ = abilityRecordId;
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    missionListManager->currentMissionLists_.clear();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(1, ability);
    mission->abilityRecord_ = ability;
    mission->missionId_ = abilityRecordId;
    missionList->missions_.push_back(mission);
    missionListManager->defaultSingleList_  = missionList;
    missionListManager->HandleForegroundTimeout(ability);
    ability->isLauncherAbility_ = true;
    ability->isLauncherRoot_ = true;
    mission = std::make_shared<Mission>(1, ability);
    mission->abilityRecord_ = ability;
    missionListManager->HandleForegroundTimeout(ability);
    EXPECT_TRUE(missionListManager != nullptr);
    missionListManager.reset();
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest HandleForegroundTimeout_002 end");
}

/*
 * Feature: MissionListManager
 * Function: MoveToTerminateList
 * SubFunction: NA
 * FunctionPoints: MissionListManager MoveToTerminateList
 * EnvConditions: NA
 * CaseDescription: Verify MoveToTerminateList
 */
HWTEST_F(MissionListManagerFirstTest, MoveToTerminateList_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest MoveToTerminateList_001 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    std::shared_ptr<AbilityRecord> ability = InitAbilityRecord();
    missionListManager->MoveToTerminateList(nullptr);
    int64_t abilityRecordId = 0;
    ability->missionId_ = abilityRecordId;
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    std::shared_ptr<MissionList> missionList1 = std::make_shared<MissionList>();
    missionListManager->currentMissionLists_.clear();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(1, ability);
    mission->abilityRecord_ = ability;
    mission->missionId_ = abilityRecordId;
    mission->SetMissionList(nullptr);
    missionList->missions_.push_back(mission);
    missionListManager->defaultSingleList_  = missionList;
    missionListManager->MoveToTerminateList(ability);
    missionList->missions_.clear();
    mission->SetMissionList(missionList1);
    missionList->missions_.push_back(mission);
    missionList->type_ = MissionListType::CURRENT;
    missionListManager->defaultSingleList_  = missionList;
    missionListManager->MoveToTerminateList(ability);
    EXPECT_TRUE(missionListManager != nullptr);
    missionListManager.reset();
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest MoveToTerminateList_001 end");
}

/*
 * Feature: MissionListManager
 * Function: MoveToTerminateList
 * SubFunction: NA
 * FunctionPoints: MissionListManager MoveToTerminateList
 * EnvConditions: NA
 * CaseDescription: Verify MoveToTerminateList
 */
HWTEST_F(MissionListManagerFirstTest, MoveToTerminateList_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest MoveToTerminateList_002 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    std::shared_ptr<AbilityRecord> ability = InitAbilityRecord();
    int64_t abilityRecordId = 0;
    ability->missionId_ = abilityRecordId;
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    std::shared_ptr<MissionList> missionList1 = std::make_shared<MissionList>();
    missionListManager->currentMissionLists_.clear();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(1, ability);
    mission->abilityRecord_ = ability;
    mission->missionId_ = abilityRecordId;
    mission->SetMissionList(missionList1);
    missionList->missions_.push_back(mission);
    missionListManager->defaultSingleList_  = missionList;
    DelayedSingleton<MissionInfoMgr>::GetInstance()->missionIdMap_[abilityRecordId] = true;
    InnerMissionInfo info;
    info.missionInfo.id = 0;
    DelayedSingleton<MissionInfoMgr>::GetInstance()->taskDataPersistenceMgr_ =
        DelayedSingleton<TaskDataPersistenceMgr>::GetInstance();
    DelayedSingleton<MissionInfoMgr>::GetInstance()->missionInfoList_.push_back(info);
    missionListManager->MoveToTerminateList(ability);
    missionListManager->listenerController_ = std::make_shared<MissionListenerController>();
    EXPECT_TRUE(missionListManager != nullptr);
    missionListManager->MoveToTerminateList(ability);
    missionListManager.reset();
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest MoveToTerminateList_002 end");
}

/*
 * Feature: MissionListManager
 * Function: HandleLauncherDied
 * SubFunction: NA
 * FunctionPoints: MissionListManager HandleLauncherDied
 * EnvConditions: NA
 * CaseDescription: Verify HandleLauncherDied
 */
HWTEST_F(MissionListManagerFirstTest, HandleLauncherDied_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest HandleLauncherDied_001 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    std::shared_ptr<AbilityRecord> ability = InitAbilityRecord();
    int64_t abilityRecordId = 0;
    ability->missionId_ = abilityRecordId;
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    std::shared_ptr<MissionList> missionList1 = std::make_shared<MissionList>();
    missionListManager->currentMissionLists_.clear();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(1, ability);
    mission->abilityRecord_ = ability;
    mission->missionId_ = abilityRecordId;
    mission->SetMissionList(missionList1);
    missionList->missions_.push_back(mission);
    missionListManager->defaultSingleList_  = missionList;
    missionListManager->HandleLauncherDied(ability);
    missionListManager->launcherList_ = missionList1;
    missionListManager->HandleLauncherDied(ability);
    EXPECT_TRUE(missionListManager != nullptr);
    missionListManager.reset();
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest HandleLauncherDied_001 end");
}

/*
 * Feature: MissionListManager
 * Function: HandleLauncherDied
 * SubFunction: NA
 * FunctionPoints: MissionListManager HandleLauncherDied
 * EnvConditions: NA
 * CaseDescription: Verify HandleLauncherDied
 */
HWTEST_F(MissionListManagerFirstTest, HandleLauncherDied_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest HandleLauncherDied_002 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    std::shared_ptr<AbilityRecord> ability = InitAbilityRecord();
    int64_t abilityRecordId = 0;
    ability->missionId_ = abilityRecordId;
    ability->isLauncherRoot_ = true;
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    std::shared_ptr<MissionList> missionList1 = std::make_shared<MissionList>();
    missionListManager->currentMissionLists_.clear();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(1, ability);
    mission->abilityRecord_ = ability;
    mission->missionId_ = abilityRecordId;
    mission->SetMissionList(missionList1);
    missionList->missions_.push_back(mission);
    missionListManager->defaultSingleList_  = missionList;
    missionListManager->launcherList_ = missionList1;
    missionListManager->HandleLauncherDied(ability);
    EXPECT_TRUE(missionListManager != nullptr);
    missionListManager.reset();
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest HandleLauncherDied_002 end");
}

/*
 * Feature: MissionListManager
 * Function: HandleLauncherDied
 * SubFunction: NA
 * FunctionPoints: MissionListManager HandleLauncherDied
 * EnvConditions: NA
 * CaseDescription: Verify HandleLauncherDied
 */
HWTEST_F(MissionListManagerFirstTest, HandleLauncherDied_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest HandleLauncherDied_003 start");
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    std::shared_ptr<AbilityRecord> ability = InitAbilityRecord();
    int64_t abilityRecordId = 0;
    ability->missionId_ = abilityRecordId;
    ability->currentState_ = FOREGROUND;
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    std::shared_ptr<MissionList> missionList1 = std::make_shared<MissionList>();
    missionListManager->currentMissionLists_.clear();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(1, ability);
    mission->abilityRecord_ = ability;
    mission->missionId_ = abilityRecordId;
    mission->SetMissionList(missionList1);
    missionList->missions_.push_back(mission);
    missionListManager->defaultSingleList_  = missionList;
    missionListManager->launcherList_ = missionList1;
    missionListManager->HandleLauncherDied(ability);
    EXPECT_TRUE(missionListManager != nullptr);
    missionListManager.reset();
    TAG_LOGI(AAFwkTag::TEST, "MissionListManagerFirstTest HandleLauncherDied_003 end");
}

/*
 * @tc.name: MissionListManager_SetMissionIcon_001
 * @tc.desc: Test SetMissionIcon
 * @tc.type: FUNC
 */
HWTEST_F(MissionListManagerFirstTest, MissionListManager_SetMissionIcon_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MissionListManager_SetMissionIcon_001 start";
    int userId = 3;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    missionListManager->Init();
    std::shared_ptr<Media::PixelMap> icon;
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(1, abilityRecord);
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    EXPECT_NE(missionList, nullptr);
    missionList->missions_.push_back(nullptr);
    missionList->missions_.push_back(mission);
    missionListManager->defaultSingleList_ = missionList;
    abilityRecord->SetMissionId(mission->GetMissionId());
    abilityRecord->abilityInfo_.excludeFromMissions = false;
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    int res = missionListManager->SetMissionIcon(token, icon);
    EXPECT_EQ(res, 0);
    abilityRecord->abilityInfo_.excludeFromMissions = true;
    token = abilityRecord->GetToken();
    res = missionListManager->SetMissionIcon(token, icon);
    EXPECT_EQ(res, 0);
    missionListManager.reset();
    GTEST_LOG_(INFO) << "MissionListManager_SetMissionIcon_001 end";
}

/*
 * @tc.name: MissionListManager_UpdateAbilityRecordColdStartFlag_001
 * @tc.desc: Test UpdateAbilityRecordColdStartFlag
 * @tc.type: FUNC
 */
HWTEST_F(MissionListManagerFirstTest, MissionListManager_UpdateAbilityRecordColdStartFlag_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MissionListManager_UpdateAbilityRecordColdStartFlag_001 start";
    int userId = 2;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    std::shared_ptr<AbilityRecord> abilityRecord1 = InitAbilityRecord();
    std::shared_ptr<AbilityRecord> abilityRecord2 = InitAbilityRecord();
    std::string processName = "processName";
    abilityRecord1->abilityInfo_.process = processName;
    abilityRecord2->abilityInfo_.applicationInfo.bundleName = processName;
    std::shared_ptr<Mission> mission1 = std::make_shared<Mission>(1, abilityRecord1, "missionName");
    EXPECT_NE(mission1, nullptr);
    std::shared_ptr<Mission> mission2 = std::make_shared<Mission>(2, abilityRecord2, "missionName");
    EXPECT_NE(mission2, nullptr);
    std::shared_ptr<MissionList> missionList = std::make_shared<MissionList>();
    EXPECT_NE(missionList, nullptr);
    std::shared_ptr<MissionList> missionList2 = std::make_shared<MissionList>();
    EXPECT_NE(missionList2, nullptr);
    missionList->missions_.push_back(nullptr);
    missionList->missions_.push_back(mission1);
    missionList->missions_.push_back(mission2);
    AppInfo info;
    info.processName = processName;
    missionListManager->currentMissionLists_.push_back(missionList);
    missionListManager->currentMissionLists_.push_back(missionList2);
    missionListManager->defaultStandardList_ = missionList;
    missionListManager->defaultSingleList_ = missionList;
    missionListManager->UpdateAbilityRecordColdStartFlag(info, true);
    EXPECT_NE(missionListManager, nullptr);
    missionListManager.reset();
    GTEST_LOG_(INFO) << "MissionListManager_UpdateAbilityRecordColdStartFlag_001 end";
}

/*
 * @tc.name: MissionListManager_RemoveMissionLocked_001
 * @tc.desc: Test RemoveMissionLocked
 * @tc.type: FUNC
 */
HWTEST_F(MissionListManagerFirstTest, MissionListManager_RemoveMissionLocked_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MissionListManager_RemoveMissionLocked_001 start";
    int userId = 0;
    int32_t missionId = 1;
    auto missionListManager = std::make_shared<MissionListManager>(userId);
    missionListManager->RemoveMissionLocked(missionId, true);
    missionListManager->RemoveMissionLocked(missionId, false);
    EXPECT_NE(missionListManager, nullptr);
    missionListManager.reset();
    GTEST_LOG_(INFO) << "MissionListManager_RemoveMissionLocked_001 end";
}
}  // namespace AAFwk
}  // namespace OHOS
