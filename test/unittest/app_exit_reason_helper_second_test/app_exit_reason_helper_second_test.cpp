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
 * @tc.name: RecordUIAbilityExitReason_0100
 * @tc.desc: RecordUIAbilityExitReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppExitReasonHelperTest, RecordUIAbilityExitReason_0100, TestSize.Level1)
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
    std::string abilityName("entry111");
    AAFwk::ExitReason exitReason = { AAFwk::REASON_USER_REQUEST, "User Request" };
    int32_t result = appExitReasonHelper_->RecordUIAbilityExitReason(pid, abilityName, exitReason);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: GetActiveAbilityListWithPid_0100
 * @tc.desc: GetActiveAbilityListWithPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppExitReasonHelperTest, GetActiveAbilityListWithPid_0100, TestSize.Level1)
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
    int32_t pid = 0;
    std::vector<std::string> abilityList = {};
    int32_t result = appExitReasonHelper_->GetActiveAbilityListWithPid(uid, abilityList, pid);
    EXPECT_EQ(abilityList.size(), 0);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
