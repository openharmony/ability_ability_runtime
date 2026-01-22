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

#include "ability_record.h"
#include "app_utils.h"

#include "ability_connect_callback_stub.h"
#include "ability_manager_service.h"
#include "ability_scheduler.h"
#include "ability_util.h"
#include "connection_record.h"
#include "constants.h"
#include "mock_ability_connect_callback.h"
#include "mock_bundle_manager.h"
#include "mock_my_flag.h"
#include "mock_permission_verification.h"
#include "parameters.h"
#include "process_options.h"
#include "sa_mgr_client.h"
#include "system_ability_definition.h"
#include "ui_extension_wrapper.h"
#include "int_wrapper.h"
#include "uri_utils.h"
#ifdef SUPPORT_SCREEN
#include "mission_info_mgr.h"
#include "pixel_map.h"
#endif //SUPPORT_SCREEN

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityBase::Constants;

namespace OHOS {
namespace AAFwk {
namespace {
const std::string DEBUG_APP = "debugApp";
}
class MissionAbilityRecordTest : public testing::TestWithParam<OHOS::AAFwk::AbilityState> {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    MissionAbilityRecordPtr GetAbilityRecord();
    AbilityRequest CreateValidAbilityRequest();

    MissionAbilityRecordPtr abilityRecord_{ nullptr };
};

void MissionAbilityRecordTest::SetUpTestCase(void)
{
    OHOS::DelayedSingleton<SaMgrClient>::GetInstance()->RegisterSystemAbility(
        OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, new BundleMgrService());
}
void MissionAbilityRecordTest::TearDownTestCase(void)
{
    OHOS::DelayedSingleton<SaMgrClient>::DestroyInstance();
}

void MissionAbilityRecordTest::SetUp(void)
{
    abilityRecord_ = MissionAbilityRecord::CreateAbilityRecord(CreateValidAbilityRequest());
}

void MissionAbilityRecordTest::TearDown(void)
{
    abilityRecord_.reset();
}

MissionAbilityRecordPtr MissionAbilityRecordTest::GetAbilityRecord()
{
    return MissionAbilityRecord::CreateAbilityRecord(CreateValidAbilityRequest());
}

AbilityRequest MissionAbilityRecordTest::CreateValidAbilityRequest()
{
    AbilityRequest request;
    request.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    request.abilityInfo.bundleName = "com.example.test";
    request.abilityInfo.name = "TestAbility";
    request.appInfo.name = "TestApp";
    return request;
}

/*
 * Feature: MissionAbilityRecord
 * Function: create MissionAbilityRecord
 * SubFunction: NA
 * FunctionPoints: SetAbilityState GetAbilityState
 * EnvConditions: NA
 * CaseDescription: SetAbilityState GetAbilityState UT.
 */
HWTEST_F(MissionAbilityRecordTest, AaFwk_AbilityMS_GetAbilityState, TestSize.Level1)
{
    abilityRecord_->SetAbilityForegroundingFlag();
    abilityRecord_->SetAbilityState(AbilityState::BACKGROUND);
    EXPECT_FALSE(abilityRecord_->GetAbilityForegroundingFlag());

    abilityRecord_->SetAbilityForegroundingFlag();
    abilityRecord_->SetAbilityState(AbilityState::FOREGROUND);
    EXPECT_TRUE(abilityRecord_->GetAbilityForegroundingFlag());
}

/*
 * Feature: MissionAbilityRecord
 * Function: ProcessForegroundAbility
 * SubFunction: ProcessForegroundAbility
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord ProcessForegroundAbility
 */
HWTEST_F(MissionAbilityRecordTest, AaFwk_AbilityMS_ProcessForegroundAbility_008, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    bool isRecent = false;
    AbilityRequest abilityRequest;
    std::shared_ptr<StartOptions> startOptions = nullptr ;
    MissionAbilityRecordPtr callerAbility;
    uint32_t sceneFlag = 1;
    abilityRecord->isReady_ = false;
    abilityRecord->ProcessForegroundAbility(isRecent, abilityRequest, startOptions, callerAbility, sceneFlag);
    EXPECT_TRUE(abilityRecord != nullptr);
}

/*
 * Feature: MissionAbilityRecord
 * Function: ProcessForegroundAbility
 * SubFunction: ProcessForegroundAbility
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord ProcessForegroundAbility
 */
HWTEST_F(MissionAbilityRecordTest, AaFwk_AbilityMS_ProcessForegroundAbility_004, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    auto callerAbility = GetAbilityRecord();
    uint32_t sceneFlag = 0;
    abilityRecord->currentState_ = AbilityState::FOREGROUND;
    abilityRecord->ProcessForegroundAbility(callerAbility, sceneFlag);
    EXPECT_TRUE(abilityRecord != nullptr);
}

/*
 * Feature: MissionAbilityRecord
 * Function: ForegroundAbility
 * SubFunction: ForegroundAbility
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord ForegroundAbility
 */
HWTEST_F(MissionAbilityRecordTest, AaFwk_AbilityMS_ForegroundAbility_001, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    uint32_t sceneFlag = 0;
    abilityRecord->lifecycleDeal_ = std::make_unique<LifecycleDeal>();
    abilityRecord->SetIsNewWant(true);
    abilityRecord->SetPreAbilityRecord(abilityRecord_);
    abilityRecord->ForegroundAbility(sceneFlag);
    EXPECT_TRUE(abilityRecord != nullptr);
}

/*
 * Feature: MissionAbilityRecord
 * Function: ForegroundAbility
 * SubFunction: ForegroundAbility
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord ForegroundAbility
 */
HWTEST_F(MissionAbilityRecordTest, AaFwk_AbilityMS_ForegroundAbility_002, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    uint32_t sceneFlag = 0;
    abilityRecord->lifecycleDeal_ = std::make_unique<LifecycleDeal>();
    abilityRecord->SetIsNewWant(true);
    abilityRecord->SetPreAbilityRecord(nullptr);
    abilityRecord->ForegroundAbility(sceneFlag);
    EXPECT_TRUE(abilityRecord != nullptr);
}

/*
 * Feature: MissionAbilityRecord
 * Function: Activate
 * SubFunction: Activate
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord Activate
 */
HWTEST_F(MissionAbilityRecordTest, AbilityRecord_Activate_001, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    abilityRecord->SetIsNewWant(true);
    abilityRecord->SetPreAbilityRecord(abilityRecord_);
    abilityRecord->Activate();
    EXPECT_TRUE(abilityRecord != nullptr);
}

/*
 * Feature: MissionAbilityRecord
 * Function: Activate
 * SubFunction: Activate
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord Activate
 */
HWTEST_F(MissionAbilityRecordTest, AbilityRecord_Activate_002, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    abilityRecord->SetIsNewWant(true);
    abilityRecord->SetPreAbilityRecord(nullptr);
    abilityRecord->Activate();
    EXPECT_TRUE(abilityRecord != nullptr);
}

/*
 * Feature: MissionAbilityRecord
 * Function: Activate
 * SubFunction: Activate
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord Activate
 */
HWTEST_F(MissionAbilityRecordTest, AbilityRecord_Activate_003, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    abilityRecord->SetIsNewWant(true);
    abilityRecord->SetPreAbilityRecord(abilityRecord);
    abilityRecord->Activate();
    EXPECT_NE(abilityRecord_, nullptr);
}

#ifdef SUPPORT_SCREEN
/*
 * Feature: MissionAbilityRecord
 * Function: AnimationTask
 * SubFunction: AnimationTask
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord AnimationTask
 */
HWTEST_F(MissionAbilityRecordTest, AaFwk_AbilityMS_AnimationTask_001, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    bool isRecent = true;
    AbilityRequest abilityRequest;
    std::shared_ptr<StartOptions> startOptions = nullptr ;
    MissionAbilityRecordPtr callerAbility;
    abilityRecord->AnimationTask(isRecent, abilityRequest, startOptions, callerAbility);
}

/*
 * Feature: MissionAbilityRecord
 * Function: NotifyAnimationFromStartingAbility
 * SubFunction: NotifyAnimationFromStartingAbility
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord NotifyAnimationFromStartingAbility
 */
HWTEST_F(MissionAbilityRecordTest, AaFwk_AbilityMS_NotifyAnimationFromStartingAbility_002, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    MissionAbilityRecordPtr callerAbility = nullptr;
    AbilityRequest abilityRequest;
    abilityRecord->NotifyAnimationFromStartingAbility(callerAbility, abilityRequest);
}

/*
 * Feature: MissionAbilityRecord
 * Function: StartingWindowTask
 * SubFunction: StartingWindowTask
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord StartingWindowTask
 */
HWTEST_F(MissionAbilityRecordTest, AaFwk_AbilityMS_StartingWindowTask_001, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    bool isRecent = true;
    AbilityRequest abilityRequest;
    std::shared_ptr<StartOptions> startOptions = std::make_shared<StartOptions>();
    abilityRecord->StartingWindowTask(isRecent, true, abilityRequest, startOptions);
    abilityRecord->StartingWindowTask(isRecent, false, abilityRequest, startOptions);
}

/*
 * Feature: MissionAbilityRecord
 * Function: PostCancelStartingWindowColdTask
 * SubFunction: PostCancelStartingWindowColdTask
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: PostCancelStartingWindowColdTask
 */
HWTEST_F(MissionAbilityRecordTest, AbilityRecord_PostCancelStartingWindowColdTask_001, TestSize.Level1)
{
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo applicationInfo;

    Want debugWant;
    debugWant.SetParam(DEBUG_APP, true);
    MissionAbilityRecord debugAbilityRecord(debugWant, abilityInfo, applicationInfo, 0);
    debugAbilityRecord.PostCancelStartingWindowColdTask();
    EXPECT_TRUE(debugAbilityRecord.GetWant().GetBoolParam(DEBUG_APP, false));

    Want noDebugWant;
    noDebugWant.SetParam(DEBUG_APP, false);
    MissionAbilityRecord noDebugAbilityRecord(noDebugWant, abilityInfo, applicationInfo, 0);
    noDebugAbilityRecord.PostCancelStartingWindowColdTask();
    EXPECT_FALSE(noDebugAbilityRecord.GetWant().GetBoolParam(DEBUG_APP, false));
}

/*
 * Feature: MissionAbilityRecord
 * Function: StartingWindowHot
 * SubFunction: StartingWindowHot
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord StartingWindowHot
 */
HWTEST_F(MissionAbilityRecordTest, AbilityRecord_StartingWindowHot_001, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    std::shared_ptr<StartOptions> startOptions = std::make_shared<StartOptions>();
    std::shared_ptr<Want> want = std::make_shared<Want>();
    AbilityRequest abilityRequest;
    abilityRecord->StartingWindowHot(startOptions, want, abilityRequest);
}

/*
 * Feature: MissionAbilityRecord
 * Function: GetLabel
 * SubFunction: GetLabel
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord GetLabel
 */
HWTEST_F(MissionAbilityRecordTest, AaFwk_AbilityMS_GetLabel_001, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    abilityRecord->abilityInfo_.applicationInfo.label = "label";
    abilityRecord->abilityInfo_.resourcePath = "resource";
    std::string res = abilityRecord->GetLabel();
    EXPECT_EQ(res, "label");
}

/*
 * Feature: MissionAbilityRecord
 * Function: CreateResourceManager
 * SubFunction: CreateResourceManager
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord CreateResourceManager
 */
HWTEST_F(MissionAbilityRecordTest, AaFwk_AbilityMS_CreateResourceManager_001, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    system::SetParameter(COMPRESS_PROPERTY, "1");
    abilityRecord->abilityInfo_.hapPath = "path";
    auto res = abilityRecord->CreateResourceManager();
    EXPECT_EQ(res, nullptr);
}

/*
 * Feature: MissionAbilityRecord
 * Function: CreateResourceManager
 * SubFunction: CreateResourceManager
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: CreateResourceManager
 */
HWTEST_F(MissionAbilityRecordTest, AbilityRecord_CreateResourceManager_001, TestSize.Level1)
{
    Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo applicationInfo;
    MissionAbilityRecord abilityRecord(want, abilityInfo, applicationInfo, 0);
    EXPECT_TRUE(abilityRecord.CreateResourceManager() == nullptr);

    abilityInfo.hapPath = "abc";
    EXPECT_TRUE(abilityRecord.CreateResourceManager() == nullptr);

    abilityInfo.resourcePath = "abc";
    abilityInfo.hapPath = "";
    EXPECT_TRUE(abilityRecord.CreateResourceManager() == nullptr);

    abilityInfo.hapPath = "abc";
    EXPECT_TRUE(abilityRecord.CreateResourceManager() == nullptr);
}

/*
 * Feature: MissionAbilityRecord
 * Function: GetPixelMap
 * SubFunction: GetPixelMap
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord GetPixelMap
 */
HWTEST_F(MissionAbilityRecordTest, AbilityRecord_GetPixelMap_001, TestSize.Level1)
{
    EXPECT_EQ(abilityRecord_->GetPixelMap(1, nullptr), nullptr);
    std::shared_ptr<Global::Resource::ResourceManager> resourceMgr(Global::Resource::CreateResourceManager());
    EXPECT_EQ(abilityRecord_->GetPixelMap(1, resourceMgr), nullptr);
}

/*
 * Feature: MissionAbilityRecord
 * Function: GetPixelMap
 * SubFunction: GetPixelMap
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord GetPixelMap
 */
HWTEST_F(MissionAbilityRecordTest, AbilityRecord_GetPixelMap_002, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    std::shared_ptr<Global::Resource::ResourceManager> resourceMgr(Global::Resource::CreateResourceManager());
    system::SetParameter(COMPRESS_PROPERTY, "1");
    abilityRecord->abilityInfo_.hapPath = "path";
    auto res = abilityRecord->GetPixelMap(1, resourceMgr);
    EXPECT_EQ(res, nullptr);
}

/*
 * Feature: MissionAbilityRecord
 * Function: GetColdStartingWindowResource
 * SubFunction: GetColdStartingWindowResource
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord GetColdStartingWindowResource
 */
HWTEST_F(MissionAbilityRecordTest, AbilityRecord_GetColdStartingWindowResource_001, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    std::shared_ptr<Media::PixelMap> bg;
    uint32_t bgColor = 0;
    abilityRecord->startingWindowBg_ = std::make_shared<Media::PixelMap>();
    abilityRecord->GetColdStartingWindowResource(bg, bgColor);
    abilityRecord->startingWindowBg_ = nullptr;
    abilityRecord->GetColdStartingWindowResource(bg, bgColor);
}

/*
 * Feature: MissionAbilityRecord
 * Function: InitColdStartingWindowResource
 * SubFunction: InitColdStartingWindowResource
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord InitColdStartingWindowResource
 */
HWTEST_F(MissionAbilityRecordTest, AbilityRecord_InitColdStartingWindowResource_001, TestSize.Level1)
{
    auto abilityRecord = GetAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    std::shared_ptr<Global::Resource::ResourceManager> resourceMgr(Global::Resource::CreateResourceManager());
    abilityRecord->InitColdStartingWindowResource(nullptr);
    abilityRecord->InitColdStartingWindowResource(resourceMgr);
}

/*
 * Feature: MissionAbilityRecord
 * Function: PostCancelStartingWindowHotTask
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: PostCancelStartingWindowHotTask
 */
HWTEST_F(MissionAbilityRecordTest, AbilityRecord_PostCancelStartingWindowHotTask_001, TestSize.Level1)
{
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo applicationInfo;

    Want debugWant;
    debugWant.SetParam(DEBUG_APP, true);
    MissionAbilityRecord debugAbilityRecord(debugWant, abilityInfo, applicationInfo, 0);
    debugAbilityRecord.PostCancelStartingWindowHotTask();
    EXPECT_TRUE(debugAbilityRecord.GetWant().GetBoolParam(DEBUG_APP, false));

    Want noDebugWant;
    noDebugWant.SetParam(DEBUG_APP, false);
    MissionAbilityRecord noDebugAbilityRecord(noDebugWant, abilityInfo, applicationInfo, 0);
    noDebugAbilityRecord.PostCancelStartingWindowHotTask();
    EXPECT_FALSE(noDebugAbilityRecord.GetWant().GetBoolParam(DEBUG_APP, false));
}
#endif
}  // namespace AAFwk
}  // namespace OHOS
