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

#include "app_exit_reason_helper.h"
#include "task_handler_wrap.h"
#include "ability_event_handler.h"
#include "ability_manager_service.h"
#include "extension_record_manager.h"
#include "mission_list_manager.h"

using namespace testing;
using namespace testing::ext;


namespace OHOS {
using namespace OHOS::AAFwk;
namespace AbilityRuntime {

class AppExitReasonHelperThirdTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void AppExitReasonHelperThirdTest::SetUpTestCase(void)
{}

void AppExitReasonHelperThirdTest::TearDownTestCase(void)
{}

void AppExitReasonHelperThirdTest::SetUp()
{}

void AppExitReasonHelperThirdTest::TearDown()
{}

/**
 * @tc.name: RecordProcessExtensionExitReason_0100
 * @tc.desc: RecordProcessExtensionExitReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppExitReasonHelperThirdTest, RecordProcessExtensionExitReason_0100, TestSize.Level1)
{
    std::shared_ptr<AAFwk::TaskHandlerWrap> taskHandler_;
    taskHandler_ = AAFwk::TaskHandlerWrap::CreateQueueHandler(AAFwk::AbilityConfig::NAME_ABILITY_MGR_SERVICE);
    std::weak_ptr<AAFwk::AbilityManagerService> service;
    service = AAFwk::AbilityManagerService::GetPubInstance();
    std::shared_ptr<AAFwk::AbilityEventHandler> eventHandler_;
    eventHandler_ = std::make_shared<AAFwk::AbilityEventHandler>(taskHandler_, service);
    std::shared_ptr<AAFwk::SubManagersHelper> subManagersHelper_;
    subManagersHelper_ = std::make_shared<AAFwk::SubManagersHelper>(taskHandler_, eventHandler_);
    int userId = 1;
    subManagersHelper_->currentConnectManager_ = std::make_shared<AAFwk::AbilityConnectManager>(0);
    std::shared_ptr<AAFwk::AppExitReasonHelper> appExitReasonHelper_;
    appExitReasonHelper_ = std::make_shared<AAFwk::AppExitReasonHelper>(subManagersHelper_);
    std::string bundleName = "com.test.demo";
    AppExecFwk::RunningProcessInfo processInfo;
    bool withKillMsg = false;
    OHOS::AAFwk::ExitReason exitReason = {AAFwk::REASON_JS_ERROR, "Js Error."};
    int32_t pid = -2;
    appExitReasonHelper_->subManagersHelper_->currentConnectManager_ -> uiExtensionAbilityRecordMgr_ = nullptr;
    int32_t result = appExitReasonHelper_->RecordProcessExtensionExitReason(pid, bundleName, exitReason,
        processInfo, withKillMsg);
    EXPECT_EQ(result, AAFwk::ERR_GET_ACTIVE_EXTENSION_LIST_EMPTY);

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);
    auto extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    appExitReasonHelper_->subManagersHelper_->currentConnectManager_
        = std::make_shared<AAFwk::AbilityConnectManager>(0);
    appExitReasonHelper_->subManagersHelper_->currentConnectManager_
        ->uiExtensionAbilityRecordMgr_->extensionRecords_.clear();
    pid = 0;
    result = appExitReasonHelper_->RecordProcessExtensionExitReason(pid, bundleName, exitReason,
        processInfo, withKillMsg);
    EXPECT_EQ(result, AAFwk::ERR_GET_ACTIVE_EXTENSION_LIST_EMPTY);
    appExitReasonHelper_->subManagersHelper_->currentConnectManager_
        ->uiExtensionAbilityRecordMgr_->extensionRecords_.emplace(userId, extRecord);
    result = appExitReasonHelper_->RecordProcessExtensionExitReason(pid, bundleName, exitReason,
        processInfo, withKillMsg);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: GetActiveAbilityListWithPid_0100
 * @tc.desc: GetActiveAbilityListWithPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppExitReasonHelperThirdTest, GetActiveAbilityListWithPid_0100, TestSize.Level1)
{
    std::shared_ptr<AAFwk::TaskHandlerWrap> taskHandler_;
    taskHandler_ = AAFwk::TaskHandlerWrap::CreateQueueHandler(AAFwk::AbilityConfig::NAME_ABILITY_MGR_SERVICE);
    std::weak_ptr<AAFwk::AbilityManagerService> service;
    service = AAFwk::AbilityManagerService::GetPubInstance();
    std::shared_ptr<AAFwk::AbilityEventHandler> eventHandler_;
    eventHandler_ = std::make_shared<AAFwk::AbilityEventHandler>(taskHandler_, service);
    std::shared_ptr<AAFwk::SubManagersHelper> subManagersHelper_;
    subManagersHelper_ = std::make_shared<AAFwk::SubManagersHelper>(taskHandler_, eventHandler_);
    subManagersHelper_->currentUIAbilityManager_ = std::make_shared<AAFwk::UIAbilityLifecycleManager>();
    subManagersHelper_->currentMissionListManager_ = std::make_shared<AAFwk::MissionListManager>(0);
    std::shared_ptr<AAFwk::AppExitReasonHelper> appExitReasonHelper_;
    appExitReasonHelper_ = std::make_shared<AAFwk::AppExitReasonHelper>(subManagersHelper_);
    int32_t uid = 0;
    std::vector<std::string> abilityLists;
    int32_t pid = 0;

    int32_t result = appExitReasonHelper_->GetActiveAbilityListWithPid(uid, abilityLists, pid);
    EXPECT_EQ(result, ERR_OK);
}


/**
 * @tc.name: RecordUIAbilityExitReason_0100
 * @tc.desc: RecordUIAbilityExitReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppExitReasonHelperThirdTest, RecordUIAbilityExitReason_0100, TestSize.Level1)
{
    std::shared_ptr<AAFwk::TaskHandlerWrap> taskHandler_;
    taskHandler_ = AAFwk::TaskHandlerWrap::CreateQueueHandler(AAFwk::AbilityConfig::NAME_ABILITY_MGR_SERVICE);
    std::weak_ptr<AAFwk::AbilityManagerService> service;
    service = AAFwk::AbilityManagerService::GetPubInstance();
    std::shared_ptr<AAFwk::AbilityEventHandler> eventHandler_;
    eventHandler_ = std::make_shared<AAFwk::AbilityEventHandler>(taskHandler_, service);
    std::shared_ptr<AAFwk::SubManagersHelper> subManagersHelper_;
    subManagersHelper_ = std::make_shared<AAFwk::SubManagersHelper>(taskHandler_, eventHandler_);
    std::shared_ptr<AAFwk::AppExitReasonHelper> appExitReasonHelper_;
    appExitReasonHelper_ = std::make_shared<AAFwk::AppExitReasonHelper>(subManagersHelper_);

    int32_t pid = -1;
    AAFwk::ExitReason exitReason;
    std::string bundleName("bundleNameTest");

    int32_t result = appExitReasonHelper_->RecordUIAbilityExitReason(pid, bundleName, exitReason);
    EXPECT_EQ(result, -1);

    pid = 1;
    result = appExitReasonHelper_->RecordUIAbilityExitReason(pid, "", exitReason);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
