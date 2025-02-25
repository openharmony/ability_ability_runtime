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
#include "ability_record.h"
#include "ability_start_setting.h"
#include "app_scheduler.h"
#include "app_utils.h"
#include "scene_board/ui_ability_lifecycle_manager.h"
#include "app_mgr_client.h"
#include "mock_ability_info_callback_stub.h"
#include "process_options.h"
#include "session/host/include/session.h"
#include "session_info.h"
#include "startup_util.h"
#include "ability_manager_service.h"
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
}  // namespace AAFwk
}  // namespace OHOS
