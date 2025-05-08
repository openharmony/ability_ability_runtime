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

#include "ability_manager_errors.h"
#include "ability_util.h"
#define private public
#define protected public
#include "ability_record.h"
#include "app_mgr_util.h"
#include "scene_board/ui_ability_lifecycle_manager.h"
#undef protected
#undef private
#include "ability_start_setting.h"
#include "app_scheduler.h"
#include "app_utils.h"
#include "app_mgr_client.h"
#include "mock_ability_info_callback_stub.h"
#include "process_options.h"
#include "session/host/include/session.h"
#include "session_info.h"
#include "startup_util.h"
#define private public
#define protected public
#include "ability_manager_service.h"
#undef protected
#undef private
#include "ability_scheduler_mock.h"
#include "hilog_tag_wrapper.h"
#include "mock_my_flag.h"
#include "mock_permission_verification.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
namespace {
#ifdef WITH_DLP
const std::string DLP_INDEX = "ohos.dlp.params.index";
#endif // WITH_DLP
constexpr int32_t TEST_UID = 20010001;
};
class UIAbilityLifecycleManagerSecondTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<AbilityRecord> InitAbilityRecord();
};

void UIAbilityLifecycleManagerSecondTest::SetUpTestCase() {}

void UIAbilityLifecycleManagerSecondTest::TearDownTestCase() {}

void UIAbilityLifecycleManagerSecondTest::SetUp() {}

void UIAbilityLifecycleManagerSecondTest::TearDown() {}

class UIAbilityLifcecycleManagerSecondTestStub : public IRemoteStub<IAbilityConnection> {
public:
    UIAbilityLifcecycleManagerSecondTestStub() {};
    virtual ~UIAbilityLifcecycleManagerSecondTestStub() {};

    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
    {
        return 0;
    };

    virtual void OnAbilityConnectDone(
        const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int resultCode) {};

    /**
     * OnAbilityDisconnectDone, AbilityMs notify caller ability the result of disconnect.
     *
     * @param element, service ability's ElementName.
     * @param resultCode, ERR_OK on success, others on failure.
     */
    virtual void OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode) {};
};

std::shared_ptr<AbilityRecord> UIAbilityLifecycleManagerSecondTest::InitAbilityRecord()
{
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    return abilityRecord;
}

/**
 * @tc.name: UIAbilityLifecycleManager_HandleLegacyAcceptWantDone_0100
 * @tc.desc: HandleLegacyAcceptWantDone
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, HandleLegacyAcceptWantDone_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleLegacyAcceptWantDone_001 begin.");
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    Want want;
    AbilityRequest abilityRequest;
    want.SetParam("ohos.anco.param.missionAffinity", false);
    abilityRequest.want = want;
    sptr<SessionInfo> sessionInfo(new SessionInfo());
    sessionInfo->persistentId = 100;
    abilityRequest.sessionInfo = sessionInfo;
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    abilityRecord->collaboratorType_ = CollaboratorType::RESERVE_TYPE;
    mgr->sessionAbilityMap_.emplace(sessionInfo->persistentId, abilityRecord);
    bool reuse = false;
    std::string flag = "";
    int32_t requestId = 1;
    mgr->HandleLegacyAcceptWantDone(abilityRequest, requestId, flag, want);
    EXPECT_EQ(abilityRequest.specifiedFlag, "");
    flag = "specified";
    mgr->HandleLegacyAcceptWantDone(abilityRequest, requestId, flag, want);
    EXPECT_EQ(abilityRequest.specifiedFlag, flag);
    TAG_LOGI(AAFwkTag::TEST, "HandleLegacyAcceptWantDone_001 end.");
}

/**
 * @tc.name: UIAbilityLifecycleManager_FindRecordFromSessionMap_001
 * @tc.desc: FindRecordFromSessionMap
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, FindRecordFromSessionMap_001, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(mgr, nullptr);

    AbilityRequest abilityRequest;
    int32_t appIndex = 0;
    const int32_t sessionId = 100;

    auto ret = mgr->FindRecordFromSessionMap(abilityRequest);
    EXPECT_EQ(ret, nullptr);

    (void)AbilityRuntime::StartupUtil::GetAppIndex(abilityRequest.want, appIndex);
    auto instanceKey = abilityRequest.want.GetStringParam(Want::APP_INSTANCE_KEY);
    std::unordered_map<int32_t, std::shared_ptr<AbilityRecord>> sessionAbilityMap_;

    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    mgr->sessionAbilityMap_[sessionId] = abilityRecord;

    const auto info = abilityRecord->GetAbilityInfo();

    ret = mgr->FindRecordFromSessionMap(abilityRequest);
    EXPECT_NE(ret, nullptr);
    EXPECT_EQ(ret, abilityRecord);
    EXPECT_EQ(info.bundleName, abilityRequest.abilityInfo.bundleName);
    EXPECT_EQ(info.moduleName, abilityRequest.abilityInfo.moduleName);
    EXPECT_EQ(appIndex, abilityRecord->GetAppIndex());
    EXPECT_EQ(instanceKey, abilityRecord->GetInstanceKey());
}

/**
 * @tc.name: UIAbilityLifecycleManager_IsSpecifiedModuleLoaded_0100
 * @tc.desc: IsSpecifiedModuleLoaded PrepareTerminateAppAndGetRemainingInner
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, IsSpecifiedModuleLoaded_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsSpecifiedModuleLoaded_001 begin.");
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    EXPECT_FALSE(mgr->IsSpecifiedModuleLoaded(abilityRequest));
    TAG_LOGI(AAFwkTag::TEST, "IsSpecifiedModuleLoaded_001 end.");
}

/**
 * @tc.name: UIAbilityLifecycleManager_PrepareTerminateAppAndGetRemainingInner_0100
 * @tc.desc: PrepareTerminateAppAndGetRemainingInner
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, PrepareTerminateAppAndGetRemainingInner_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    int32_t pid = 1;
    std::string moduleName = "testModuleName";
    std::vector<sptr<IRemoteObject>> tokens;
    std::vector<sptr<IRemoteObject>> remainingTokens;

    auto ret = uiAbilityLifecycleManager->PrepareTerminateAppAndGetRemainingInner(pid, moduleName, tokens);
    EXPECT_EQ(ret, remainingTokens);

    std::shared_ptr<UIAbilityLifecycleManager::PrepareTerminateByPidRecord> record =
        std::make_shared<UIAbilityLifecycleManager::PrepareTerminateByPidRecord>(
        pid, moduleName, false, 0, false);
    uiAbilityLifecycleManager->prepareTerminateByPidRecords_.push_back(record);
    ret = uiAbilityLifecycleManager->PrepareTerminateAppAndGetRemainingInner(pid, moduleName, tokens);
    EXPECT_EQ(ret, remainingTokens);
}

/**
 * @tc.name: UIAbilityLifecycleManager_PrepareTerminateAppAndGetRemaining_001
 * @tc.desc: PrepareTerminateAppAndGetRemaining
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, PrepareTerminateAppAndGetRemaining_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    int32_t pid = 1;
    std::vector<sptr<IRemoteObject>> tokens;
    std::vector<sptr<IRemoteObject>> remainingTokens;
    auto ret = uiAbilityLifecycleManager->PrepareTerminateAppAndGetRemaining(pid, tokens);
    EXPECT_EQ(ret, remainingTokens);

    AbilityRequest abilityRequest;
    abilityRequest.appInfo.accessTokenId = IPCSkeleton::GetCallingTokenID();
    abilityRequest.sessionInfo = nullptr;
    auto abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    abilityRecord->abilityInfo_.applicationInfo.accessTokenId = 1;
    uiAbilityLifecycleManager->sessionAbilityMap_.emplace(0, abilityRecord);
    sptr<IRemoteObject> token = abilityRecord->GetToken()->AsObject();
    tokens.push_back(token);
    AAFwk::MyFlag::flag_ = 1;
    AppUtils::isStartOptionsWithAnimation_ = true;
    ret = uiAbilityLifecycleManager->PrepareTerminateAppAndGetRemaining(pid, tokens);
    EXPECT_EQ(ret, remainingTokens);
}

/**
 * @tc.name: UIAbilityLifecycleManager_ProcessColdStartBranch_001
 * @tc.desc: ProcessColdStartBranch
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, ProcessColdStartBranch_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    bool isColdStart = false;
    auto abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    auto ret = uiAbilityLifecycleManager->ProcessColdStartBranch(abilityRequest, nullptr, abilityRecord, isColdStart);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: UIAbilityLifecycleManager_ProcessColdStartBranch_002
 * @tc.desc: ProcessColdStartBranch
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, ProcessColdStartBranch_002, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    sptr<SessionInfo> sessionInfo(new SessionInfo());
    sessionInfo->requestId = 100;
    auto abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    abilityRecord->SetIsHook(true);
    bool isColdStart = true;
    auto ret = uiAbilityLifecycleManager->ProcessColdStartBranch(abilityRequest, sessionInfo, abilityRecord,
        isColdStart);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: UIAbilityLifecycleManager_TryProcessHookModule_001
 * @tc.desc: TryProcessHookModule
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, TryProcessHookModule_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    auto specifiedRequest = std::make_shared<AAFwk::SpecifiedRequest>(0, abilityRequest);
    auto ret = uiAbilityLifecycleManager->TryProcessHookModule(*specifiedRequest, false);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: UIAbilityLifecycleManager_TryProcessHookModule_002
 * @tc.desc: TryProcessHookModule
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, TryProcessHookModule_002, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    int32_t appIndex = 0;
    const int32_t sessionId = 100;
    (void)AbilityRuntime::StartupUtil::GetAppIndex(abilityRequest.want, appIndex);
    auto instanceKey = abilityRequest.want.GetStringParam(Want::APP_INSTANCE_KEY);

    abilityRequest.appInfo.bundleName = "com.example.unittest";
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    abilityRecord->SetIsHook(true);
    abilityRecord->SetHookOff(true);
    uiAbilityLifecycleManager->sessionAbilityMap_[sessionId] = abilityRecord;

    auto specifiedRequest = std::make_shared<AAFwk::SpecifiedRequest>(0, abilityRequest);
    auto ret = uiAbilityLifecycleManager->TryProcessHookModule(*specifiedRequest, true);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: UIAbilityLifecycleManager_TryProcessHookModule_003
 * @tc.desc: TryProcessHookModule
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, TryProcessHookModule_003, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    int32_t appIndex = 0;
    const int32_t sessionId = 100;
    (void)AbilityRuntime::StartupUtil::GetAppIndex(abilityRequest.want, appIndex);
    auto instanceKey = abilityRequest.want.GetStringParam(Want::APP_INSTANCE_KEY);

    abilityRequest.appInfo.bundleName = "com.example.unittest";
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    abilityRecord->SetIsHook(true);
    uiAbilityLifecycleManager->sessionAbilityMap_[sessionId] = abilityRecord;
    auto specifiedRequest = std::make_shared<AAFwk::SpecifiedRequest>(100, abilityRequest);
    auto ret = uiAbilityLifecycleManager->TryProcessHookModule(*specifiedRequest, true);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: UIAbilityLifecycleManager_RevokeDelegator_001
 * @tc.desc: RevokeDelegator
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, RevokeDelegator_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    sptr<IRemoteObject> token = nullptr;
    auto ret = uiAbilityLifecycleManager->RevokeDelegator(token);
    EXPECT_EQ(ret, ERR_INVALID_CONTEXT);
}

/**
 * @tc.name: UIAbilityLifecycleManager_RevokeDelegator_002
 * @tc.desc: RevokeDelegator
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, RevokeDelegator_002, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    Rosen::SessionInfo info;
    sptr<Rosen::ISession> session = new Rosen::Session(info);
    EXPECT_NE(session, nullptr);
    auto ret = uiAbilityLifecycleManager->RevokeDelegator(session->AsObject());
    EXPECT_EQ(ret, ERR_INVALID_CONTEXT);
}

/**
 * @tc.name: UIAbilityLifecycleManager_RevokeDelegator_003
 * @tc.desc: RevokeDelegator
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, RevokeDelegator_003, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    auto abilityRecord = InitAbilityRecord();
    auto ret = uiAbilityLifecycleManager->RevokeDelegator(abilityRecord->GetToken());
    EXPECT_EQ(ret, ERR_INVALID_CONTEXT);
}

/**
 * @tc.name: UIAbilityLifecycleManager_RevokeDelegator_004
 * @tc.desc: RevokeDelegator
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, RevokeDelegator_004, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.accessTokenId = IPCSkeleton::GetCallingTokenID();
    auto abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    abilityRecord->currentState_ = AbilityState::BACKGROUND;
    abilityRecord->isAbilityForegrounding_ = false;
    auto ret = uiAbilityLifecycleManager->RevokeDelegator(abilityRecord->GetToken());
    EXPECT_EQ(ret, ERR_ABILITY_NOT_FOREGROUND);
}

/**
 * @tc.name: UIAbilityLifecycleManager_RevokeDelegator_005
 * @tc.desc: RevokeDelegator
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, RevokeDelegator_005, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.accessTokenId = IPCSkeleton::GetCallingTokenID();
    auto abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    abilityRecord->isAbilityForegrounding_ = true;
    auto ret = uiAbilityLifecycleManager->RevokeDelegator(abilityRecord->GetToken());
    EXPECT_EQ(ret, ERR_NOT_HOOK);
}

/**
 * @tc.name: UIAbilityLifecycleManager_RevokeDelegator_006
 * @tc.desc: RevokeDelegator
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, RevokeDelegator_006, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.accessTokenId = IPCSkeleton::GetCallingTokenID();
    auto abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    abilityRecord->isAbilityForegrounding_ = true;
    abilityRecord->isHook_ = true;
    abilityRecord->abilityInfo_.launchMode = AppExecFwk::LaunchMode::SPECIFIED;
    auto ret = uiAbilityLifecycleManager->RevokeDelegator(abilityRecord->GetToken());
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: UIAbilityLifecycleManager_RevokeDelegator_007
 * @tc.desc: RevokeDelegator
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, RevokeDelegator_007, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.accessTokenId = IPCSkeleton::GetCallingTokenID();
    auto abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    abilityRecord->isAbilityForegrounding_ = true;
    abilityRecord->isHook_ = true;
    auto ret = uiAbilityLifecycleManager->RevokeDelegator(abilityRecord->GetToken());
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: UIAbilityLifecycleManager_RevokeDelegator_008
 * @tc.desc: RevokeDelegator
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, RevokeDelegator_008, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    abilityRequest.sessionInfo = new SessionInfo();
    abilityRequest.appInfo.accessTokenId = IPCSkeleton::GetCallingTokenID();
    auto abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    abilityRecord->isAbilityForegrounding_ = true;
    abilityRecord->isHook_ = true;
    auto ret = uiAbilityLifecycleManager->RevokeDelegator(abilityRecord->GetToken());
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: UIAbilityLifecycleManager_RevokeDelegator_009
 * @tc.desc: RevokeDelegator
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, RevokeDelegator_009, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    abilityRequest.sessionInfo = new SessionInfo();
    abilityRequest.appInfo.accessTokenId = IPCSkeleton::GetCallingTokenID();
    auto abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    abilityRecord->isAbilityForegrounding_ = true;
    abilityRecord->isHook_ = true;
    abilityRecord->SetLaunchWant(std::make_shared<Want>());
    auto ret = uiAbilityLifecycleManager->RevokeDelegator(abilityRecord->GetToken());
    EXPECT_EQ(ret, ERR_FROM_WINDOW);
}

/**
 * @tc.name: UIAbilityLifecycleManager_CheckSpecified_0100
 * @tc.desc: CheckSpecified
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, CheckSpecified_001, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();
    mgr->specifiedFlagMap_.clear();
    mgr->specifiedFlagMap_.emplace(1, "2");
    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);

    mgr->CheckSpecified(1, abilityRecord);

    EXPECT_EQ(mgr->specifiedFlagMap_.size(), 0);
}

/**
 * @tc.name: UIAbilityLifecycleManager_AbilityWindowConfigTransactionDone_0100
 * @tc.desc: AbilityWindowConfigTransactionDone
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, AbilityWindowConfigTransactionDone_001, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();
    mgr->specifiedFlagMap_.emplace(1, "2");
    WindowConfig windowConfig;

    auto ret = mgr->AbilityWindowConfigTransactionDone(nullptr, windowConfig);

    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: UIAbilityLifecycleManager_AddStartCallerTimestamp_0100
 * @tc.desc: AddStartCallerTimestamp
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, AddStartCallerTimestamp_001, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();
    std::map<int32_t, std::vector<int64_t>> startUIAbilityCallerTimestamps;
    std::vector<int64_t> callerTimestamps = {};
    constexpr int32_t START_UI_ABILITY_PER_SECOND_UPPER_LIMIT = 20;
    auto curTimeNs = AbilityUtil::GetSysTimeNs();
    for (int i = 0; i < START_UI_ABILITY_PER_SECOND_UPPER_LIMIT + 2; i++) {
        callerTimestamps.emplace_back(curTimeNs);
    }
    startUIAbilityCallerTimestamps.emplace(2, callerTimestamps);
    mgr->startUIAbilityCallerTimestamps_ = startUIAbilityCallerTimestamps;

    auto ret = mgr->AddStartCallerTimestamp(2);

    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: UIAbilityLifecycleManager_AddStartCallerTimestamp_0200
 * @tc.desc: AddStartCallerTimestamp
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, AddStartCallerTimestamp_002, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();
    std::map<int32_t, std::vector<int64_t>> startUIAbilityCallerTimestamps_;
    constexpr int32_t START_UI_ABILITY_PER_SECOND_UPPER_LIMIT = 20;
    for (int i = 0; i < START_UI_ABILITY_PER_SECOND_UPPER_LIMIT - 3; i++) {
        startUIAbilityCallerTimestamps_.emplace(i, std::vector<int64_t>{1, 2});
    }

    auto ret = mgr->AddStartCallerTimestamp(2);

    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: UIAbilityLifecycleManager_NotifySCBToRecoveryAfterInterception_0100
 * @tc.desc: NotifySCBToRecoveryAfterInterception
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, NotifySCBToRecoveryAfterInterception_001, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest = {};

    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    abilityRequest.abilityInfo.isStageBasedModel = false;
    abilityRequest.abilityInfo.launchMode == AppExecFwk::LaunchMode::SPECIFIED;

    auto ret = mgr->NotifySCBToRecoveryAfterInterception(abilityRequest);

    EXPECT_EQ(ret, 22);
}

/**
 * @tc.name: UIAbilityLifecycleManager_NotifySCBToRecoveryAfterInterception_0200
 * @tc.desc: NotifySCBToRecoveryAfterInterception
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, NotifySCBToRecoveryAfterInterception_002, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest ={};
    bool isNewProcessMode = abilityRequest.processOptions &&
    ProcessOptions::IsNewProcessMode(abilityRequest.processOptions->processMode);
    abilityRequest.processOptions = nullptr;
    abilityRequest.abilityInfo.isolationProcess = true;
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    abilityRequest.abilityInfo.isStageBasedModel = true;
    AppUtils::GetInstance().isStartOptionsWithAnimation_ = true;

    auto ret = mgr->NotifySCBToRecoveryAfterInterception(abilityRequest);

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: UIAbilityLifecycleManager_DispatchBackground_0100
 * @tc.desc: DispatchBackground
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, DispatchBackground_001, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->currentState_ = AbilityState::INITIAL;

    auto ret = mgr->DispatchBackground(abilityRecord);

    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: UIAbilityLifecycleManager_PreCreateProcessName_0100
 * @tc.desc: PreCreateProcessName
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, PreCreateProcessName_001, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    abilityRequest.processOptions = std::make_shared<ProcessOptions>();
    abilityRequest.processOptions->processMode = ProcessMode::UNSPECIFIED;
    abilityRequest.processOptions->processName = "fffAAABBBCCCggg";

    mgr->PreCreateProcessName(abilityRequest);

    EXPECT_EQ(abilityRequest.processOptions->processName, "fffAAABBBCCCggg");
}

/**
 * @tc.name: UIAbilityLifecycleManager_PreCreateProcessName_0200
 * @tc.desc: PreCreateProcessName
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, PreCreateProcessName_002, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    abilityRequest.processOptions = std::make_shared<ProcessOptions>();
    abilityRequest.processOptions->processMode = ProcessMode::NEW_PROCESS_ATTACH_TO_PARENT;
    abilityRequest.processOptions->processName = "fffAAABBBCCCggg";
    abilityRequest.abilityInfo.bundleName = "BHi";
    abilityRequest.abilityInfo.moduleName = "MHi";
    abilityRequest.abilityInfo.name = "NHi";

    mgr->PreCreateProcessName(abilityRequest);

    auto processName = abilityRequest.processOptions->processName;
    auto processNameSub = processName.substr(0, processName.find_last_of(':'));
    EXPECT_EQ(processNameSub, "BHi:MHi:NHi");
}

/**
 * @tc.name: UIAbilityLifecycleManager_BackToCallerAbilityWithResult_0700
 * @tc.desc: BackToCallerAbilityWithResult
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, BackToCallerAbilityWithResult_007, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();

    auto ret = mgr->BackToCallerAbilityWithResult(nullptr, 1, nullptr, 0);

    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: UIAbilityLifecycleManager_BackToCallerAbilityWithResult_0800
 * @tc.desc: BackToCallerAbilityWithResult
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, BackToCallerAbilityWithResult_008, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();

    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.name = "TestAbility";
    abilityRequest.abilityInfo.applicationInfo.accessTokenId = 12345;
    auto abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);

    int64_t callerRequestCode = 123456789;
    CallerRequestInfo requestInfo;
    requestInfo.requestCode = 1;
    requestInfo.pid = 100;
    requestInfo.backFlag = false;

    auto ret = mgr->BackToCallerAbilityWithResult(abilityRecord, 0, nullptr, callerRequestCode);

    EXPECT_EQ(ret, ERR_CALLER_NOT_EXISTS);
}

/**
 * @tc.name: UIAbilityLifecycleManager_SetLastExitReason_0100
 * @tc.desc: SetLastExitReason
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, SetLastExitReason_001, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    abilityRecord->abilityInfo_.bundleName = "not empty";
    abilityRecord->sessionInfo_ = nullptr;

    mgr->SetLastExitReason(abilityRecord);

    EXPECT_NE(abilityRecord, nullptr);
    EXPECT_NE(abilityRecord->GetAbilityInfo().bundleName.empty(), true);
    EXPECT_EQ(abilityRecord->GetSessionInfo(), nullptr);
}

/**
 * @tc.name: UIAbilityLifecycleManager_UninstallApp_0100
 * @tc.desc: UninstallApp
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, UninstallApp_001, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    mgr->sessionAbilityMap_.clear();
    auto abilityRequest1 = std::make_shared<AbilityRequest>();
    abilityRequest1->appInfo.uid = 1;
    mgr->startAbilityCheckMap_.emplace(1, abilityRequest1);
    auto abilityRequest2 = std::make_shared<AbilityRequest>();
    abilityRequest2->appInfo.uid = 2;
    mgr->startAbilityCheckMap_.emplace(2, abilityRequest2);

    std::string bundleName = "HelloWorld";
    int32_t uid = 1;
    mgr->UninstallApp(bundleName, uid);

    auto mapSize = mgr->startAbilityCheckMap_.size();
    EXPECT_EQ(mapSize, 1);
}

/**
 * @tc.name: UIAbilityLifecycleManager_PrepareCloseUIAbility_0100
 * @tc.desc: PrepareCloseUIAbility
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, PrepareCloseUIAbility_001, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    mgr->terminateAbilityList_.clear();

    mgr->PrepareCloseUIAbility(nullptr, 0, nullptr, true);

    auto listSize = mgr->terminateAbilityList_.size();
    EXPECT_EQ(listSize, 0);
}

/**
 * @tc.name: UIAbilityLifecycleManager_NotifySCBToHandleAtomicServiceException_0100
 * @tc.desc: NotifySCBToHandleAtomicServiceException
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, NotifySCBToHandleAtomicServiceException_001, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    auto sessionInfo = sptr<SessionInfo>::MakeSptr();
    sessionInfo->sessionToken = nullptr;
    sessionInfo->errorCode = 0;
    std::string errorReason = "";

    mgr->NotifySCBToHandleAtomicServiceException(sessionInfo, 5, errorReason);

    EXPECT_EQ(sessionInfo->errorCode, 0);
}

/**
 * @tc.name: UIAbilityLifecycleManager_PrepareTerminateAbilityDone_0100
 * @tc.desc: PrepareTerminateAbilityDone
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, PrepareTerminateAbilityDone_001, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->isPrepareTerminate_ = true;

    mgr->PrepareTerminateAbilityDone(abilityRecord, false);
    EXPECT_EQ(abilityRecord->isPrepareTerminate_, true);
}

/**
 * @tc.name: UIAbilityLifecycleManager_PrepareTerminateAbilityDone_0200
 * @tc.desc: PrepareTerminateAbilityDone
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, PrepareTerminateAbilityDone_002, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->isPrepareTerminate_ = true;
    abilityRecord->isPrepareTerminateAbilityCalled_.store(true);

    mgr->PrepareTerminateAbilityDone(abilityRecord, false);
    EXPECT_EQ(abilityRecord->isPrepareTerminate_, false);
}

/**
 * @tc.name: UIAbilityLifecycleManager_CheckPrepareTerminateTokens_0100
 * @tc.desc: CheckPrepareTerminateTokens
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, CheckPrepareTerminateTokens_001, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    std::vector<sptr<IRemoteObject>> tokens = {};
    uint32_t tokenId = 0;
    std::map<std::string, std::vector<sptr<IRemoteObject>>> tokensPerModuleName = {};
    AppUtils::isStartOptionsWithAnimation_ = true;

    auto ret = mgr->CheckPrepareTerminateTokens(tokens, tokenId, tokensPerModuleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: UIAbilityLifecycleManager_CancelPrepareTerminate_0100
 * @tc.desc: CancelPrepareTerminate
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, CancelPrepareTerminate_001, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    auto prepareTerminateByPidRecords1 = std::make_shared<UIAbilityLifecycleManager::PrepareTerminateByPidRecord>(
        1,
        "HelloWorld",
        false,
        0,
        false
    );
    auto prepareTerminateByPidRecords2 = std::make_shared<UIAbilityLifecycleManager::PrepareTerminateByPidRecord>(
        2,
        "HiWorld",
        false,
        0,
        false
    );
    mgr->prepareTerminateByPidRecords_.emplace_back(prepareTerminateByPidRecords1);
    mgr->prepareTerminateByPidRecords_.emplace_back(prepareTerminateByPidRecords2);
    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->pid_ = 1;
    abilityRecord->abilityInfo_.moduleName = "HelloWorld";

    mgr->CancelPrepareTerminate(abilityRecord);
    auto recordSize = mgr->prepareTerminateByPidRecords_.size();
    EXPECT_EQ(recordSize, 1);
}

/**
 * @tc.name: UIAbilityLifecycleManager_CleanUIAbility_0100
 * @tc.desc: CleanUIAbility
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, CleanUIAbility_001, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();

    auto ret = mgr->CleanUIAbility(nullptr);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: UIAbilityLifecycleManager_TryProcessHookModule_0400
 * @tc.desc: TryProcessHookModule
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, TryProcessHookModule_004, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    AbilityRequest abilityRequest;
    auto specifiedRequest = std::make_shared<AAFwk::SpecifiedRequest>(100, abilityRequest);

    auto ret = mgr->TryProcessHookModule(*specifiedRequest, false);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: UIAbilityLifecycleManager_TryProcessHookModule_0500
 * @tc.desc: TryProcessHookModule
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, TryProcessHookModule_005, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    mgr->sessionAbilityMap_.clear();
    AbilityRequest abilityRequest;
    auto specifiedRequest = std::make_shared<AAFwk::SpecifiedRequest>(100, abilityRequest);

    auto ret = mgr->TryProcessHookModule(*specifiedRequest, true);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: UIAbilityLifecycleManager_TryProcessHookModule_0600
 * @tc.desc: TryProcessHookModule
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, TryProcessHookModule_006, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();

    int32_t appIndex = 0;
    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->SetIsHook(true);
    abilityRecord->SetHookOff(false);
    abilityRecord->abilityInfo_.bundleName = "HelloWorld";
    abilityRecord->abilityInfo_.moduleName = "HelloWorld";
    abilityRecord->SetInstanceKey("HelloWorld");

    mgr->sessionAbilityMap_.clear();
    mgr->sessionAbilityMap_.emplace(1, abilityRecord);
    
    AbilityRequest abilityRequest2;
    abilityRequest2.abilityInfo.bundleName = "HelloWorld";
    abilityRequest2.abilityInfo.moduleName = "HelloWorld";
    abilityRequest2.want.SetParam(Want::APP_INSTANCE_KEY, std::string("HelloWorld"));
    AbilityRuntime::StartupUtil::GetAppIndex(abilityRequest2.want, appIndex);
    abilityRecord->SetAppIndex(appIndex);

    auto specifiedRequest = std::make_shared<AAFwk::SpecifiedRequest>(100, abilityRequest2);

    auto ret = mgr->TryProcessHookModule(*specifiedRequest, true);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: UIAbilityLifecycleManager_RemoveAbilityRequest_0100
 * @tc.desc: RemoveAbilityRequest
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, RemoveAbilityRequest_001, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    mgr->startAbilityCheckMap_.clear();
    mgr->startAbilityCheckMap_.emplace(1, nullptr);
    mgr->startAbilityCheckMap_.emplace(3, nullptr);
    mgr->startAbilityCheckMap_.emplace(5, nullptr);

    mgr->RemoveAbilityRequest(5);
    EXPECT_EQ(mgr->startAbilityCheckMap_.size(), 2);
}

/**
 * @tc.name: UIAbilityLifecycleManager_AddSpecifiedRequest_0100
 * @tc.desc: AddSpecifiedRequest
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, AddSpecifiedRequest_001, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    mgr->specifiedRequestList_.clear();

    mgr->AddSpecifiedRequest(nullptr);
    EXPECT_EQ(mgr->specifiedRequestList_.size(), 0);
}

/**
 * @tc.name: UIAbilityLifecycleManager_AddSpecifiedRequest_0200
 * @tc.desc: AddSpecifiedRequest
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, AddSpecifiedRequest_002, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    mgr->specifiedRequestList_.clear();

    AbilityRequest abilityRequest;
    auto request = std::make_shared<SpecifiedRequest>(1, abilityRequest);

    mgr->AddSpecifiedRequest(request);
    EXPECT_EQ(mgr->specifiedRequestList_.size(), 1);
}

/**
 * @tc.name: UIAbilityLifecycleManager_IsSpecifiedModuleLoaded_0200
 * @tc.desc: IsSpecifiedModuleLoaded
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, IsSpecifiedModuleLoaded_002, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    AppMgrUtil::appMgr_= nullptr;
    AbilityRequest abilityRequest;

    auto ret = mgr->IsSpecifiedModuleLoaded(abilityRequest);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: UIAbilityLifecycleManager_HandleColdAcceptWantDone_0100
 * @tc.desc: HandleColdAcceptWantDone
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, HandleColdAcceptWantDone_001, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    AAFwk::Want want;
    std::string flag = "";
    AbilityRequest abilityRequest;
    SpecifiedRequest specifiedRequest(1, abilityRequest);

    mgr->sessionAbilityMap_.clear();

    auto ret = mgr->HandleColdAcceptWantDone(want, flag, specifiedRequest);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: UIAbilityLifecycleManager_HandleColdAcceptWantDone_0200
 * @tc.desc: HandleColdAcceptWantDone
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerSecondTest, HandleColdAcceptWantDone_002, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    AAFwk::Want want;
    std::string flag = "";
    AbilityRequest abilityRequest;
    SpecifiedRequest specifiedRequest(1, abilityRequest);
    specifiedRequest.persistentId = 1;

    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->specifiedFlag_ = "";

    mgr->sessionAbilityMap_.clear();
    mgr->sessionAbilityMap_.emplace(1, abilityRecord);

    auto ret = mgr->HandleColdAcceptWantDone(want, flag, specifiedRequest);
    EXPECT_EQ(ret, true);
}
}  // namespace AAFwk
}  // namespace OHOS