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
#include "app_exit_reason_helper.h"
#include "task_handler_wrap.h"
#include "ability_event_handler.h"
#include "ability_manager_service.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
namespace {
}  // namespace
class AppExitReasonHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AppExitReasonHelperTest::SetUpTestCase(void)
{}

void AppExitReasonHelperTest::TearDownTestCase(void)
{}

void AppExitReasonHelperTest::SetUp()
{}

void AppExitReasonHelperTest::TearDown()
{}

/**
 * @tc.name: RecordAppExitReason_0100
 * @tc.desc: RecordAppExitReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppExitReasonHelperTest, RecordAppExitReason_0100, TestSize.Level1)
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
    AAFwk::ExitReason exitReason(AAFwk::REASON_MAX, "");
    int32_t result = appExitReasonHelper_->RecordAppExitReason(exitReason);
    EXPECT_NE(result, ERR_INVALID_VALUE);

    AAFwk::ExitReason exitReason2;
    result = appExitReasonHelper_->RecordAppExitReason(exitReason2);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: RecordProcessExitReason_0100
 * @tc.desc: RecordProcessExitReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppExitReasonHelperTest, RecordProcessExitReason_0100, TestSize.Level1)
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

    int32_t pid = 0;
    AAFwk::ExitReason exitReason;
    int32_t result = appExitReasonHelper_->RecordProcessExitReason(pid, exitReason);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: RecordAppExitReason_0200
 * @tc.desc: RecordAppExitReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppExitReasonHelperTest, RecordAppExitReason_0200, TestSize.Level1)
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

    int32_t uid = 0;
    AAFwk::ExitReason exitReason;
    std::string bundleName("bundleNameTest");
    int32_t appIndex = 0;
    int32_t result = appExitReasonHelper_->RecordAppExitReason(bundleName, uid, appIndex, exitReason);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: RecordProcessExitReason_0200
 * @tc.desc: RecordProcessExitReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppExitReasonHelperTest, RecordProcessExitReason_0200, TestSize.Level1)
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

    int32_t pid = 0;
    std::string bundleName("test");
    int32_t uid = 0;
    uint32_t accessTokenId = 0;
    AAFwk::ExitReason exitReason;
    int32_t result = appExitReasonHelper_->RecordProcessExitReason(pid, bundleName, uid, accessTokenId, exitReason);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: RecordProcessExtensionExitReason_0100
 * @tc.desc: RecordProcessExtensionExitReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppExitReasonHelperTest, RecordProcessExtensionExitReason_0100, TestSize.Level1)
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

    int32_t pid = 0;
    std::string bundleName("test");
    AAFwk::ExitReason exitReason;
    int32_t result = appExitReasonHelper_->RecordProcessExtensionExitReason(pid, bundleName, exitReason);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: GetActiveAbilityList_0100
 * @tc.desc: GetActiveAbilityList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppExitReasonHelperTest, GetActiveAbilityList_0100, TestSize.Level1)
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

    int32_t uid = 0;
    std::vector<std::string> abilityLists;
    int32_t pid = 0;
    appExitReasonHelper_->GetActiveAbilityList(uid, abilityLists, pid);
    EXPECT_EQ(abilityLists.size(), 0);
}

/**
 * @tc.name: GetActiveAbilityListFromUIAbilityManager_0100
 * @tc.desc: GetActiveAbilityListFromUIAbilityManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppExitReasonHelperTest, GetActiveAbilityListFromUIAbilityManager_0100, TestSize.Level1)
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

    int32_t uid = 0;
    std::vector<std::string> abilityLists;
    int32_t pid = 0;
    appExitReasonHelper_->GetActiveAbilityListFromUIAbilityManager(uid, abilityLists, pid);
    EXPECT_EQ(abilityLists.size(), 0);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
