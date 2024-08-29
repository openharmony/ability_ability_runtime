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
#include "ability_manager_service.h"
#undef private
#undef protected

#include "ability_manager_errors.h"
#include "ability_manager_stub_mock_test.h"
#include "hilog_tag_wrapper.h"
#include "mock_task_handler_wrap.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::AppExecFwk::AbilityType;
using OHOS::AppExecFwk::ExtensionAbilityType;
namespace OHOS {
namespace AAFwk {
namespace {
const int32_t USER_ID_U100 = 100;
const int32_t APP_MEMORY_SIZE = 512;
}  // namespace
class AbilityManagerServiceSixthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    AbilityRequest GenerateAbilityRequest(const std::string& deviceName, const std::string& abilityName,
        const std::string& appName, const std::string& bundleName, const std::string& moduleName);

public:
    AbilityRequest abilityRequest_{};
    Want want_{};
};

AbilityRequest AbilityManagerServiceSixthTest::GenerateAbilityRequest(const std::string& deviceName,
    const std::string& abilityName, const std::string& appName, const std::string& bundleName,
    const std::string& moduleName)
{
    ElementName element(deviceName, bundleName, abilityName, moduleName);
    want_.SetElement(element);

    AbilityInfo abilityInfo;
    abilityInfo.visible = true;
    abilityInfo.applicationName = appName;
    abilityInfo.type = AbilityType::EXTENSION;
    abilityInfo.name = abilityName;
    abilityInfo.bundleName = bundleName;
    abilityInfo.moduleName = moduleName;
    abilityInfo.deviceId = deviceName;
    ApplicationInfo appinfo;
    appinfo.name = appName;
    appinfo.bundleName = bundleName;
    abilityInfo.applicationInfo = appinfo;
    AbilityRequest abilityRequest;
    abilityRequest.want = want_;
    abilityRequest.abilityInfo = abilityInfo;
    abilityRequest.appInfo = appinfo;

    return abilityRequest;
}

void AbilityManagerServiceSixthTest::SetUpTestCase() {}

void AbilityManagerServiceSixthTest::TearDownTestCase() {}

void AbilityManagerServiceSixthTest::SetUp() {}

void AbilityManagerServiceSixthTest::TearDown() {}

/*
 * Feature: AbilityManagerService
 * Function: InitPushTask
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService InitPushTask
 */
HWTEST_F(AbilityManagerServiceSixthTest, InitPushTask_001, TestSize.Level1)
{
    auto abilityMs = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs, nullptr);
    std::shared_ptr<TaskHandlerWrap> taskHandler =
        MockTaskHandlerWrap::CreateQueueHandler("AbilityManagerServiceSixth");
    EXPECT_CALL(*std::static_pointer_cast<MockTaskHandlerWrap>(taskHandler), SubmitTask(_, _))
        .WillRepeatedly(Return(TaskHandle()));
    abilityMs->taskHandler_ = taskHandler;
    abilityMs->InitPushTask();
    EXPECT_NE(taskHandler, nullptr);
}

/*
 * Feature: AbilityManagerService
 * Function: SetReserveInfo
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService SetReserveInfo
 */
HWTEST_F(AbilityManagerServiceSixthTest, SetReserveInfo_001, TestSize.Level1)
{
    std::shared_ptr<AbilityManagerService> abilityMs = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs, nullptr);
    const std::string deviceName = "";
    const std::string abilityName = "EntryAbility";
    const std::string appName = "amstest";
    const std::string bundleName = "com.example.amstest";
    const std::string moduleName = "entry";
    AbilityRequest abilityRequest = AbilityManagerServiceSixthTest::GenerateAbilityRequest(deviceName,
        abilityName, appName, bundleName, moduleName);
    std::string linkString = "NaN";
    abilityMs->SetReserveInfo(linkString, abilityRequest);
    EXPECT_FALSE(abilityRequest.uriReservedFlag);
    EXPECT_EQ(abilityRequest.reservedBundleName, "");
}

/*
 * Feature: AbilityManagerService
 * Function: LockMissionForCleanup
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService LockMissionForCleanup
 */
HWTEST_F(AbilityManagerServiceSixthTest, LockMissionForCleanup_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest LockMissionForCleanup_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    EXPECT_EQ(abilityMs->LockMissionForCleanup(1), CHECK_PERMISSION_FAILED);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest LockMissionForCleanup_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: ReportEventToRss
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService ReportEventToRss
 */
HWTEST_F(AbilityManagerServiceSixthTest, ReportEventToRss_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest ReportEventToRss_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    std::shared_ptr<TaskHandlerWrap> taskHandler =
        MockTaskHandlerWrap::CreateQueueHandler("AbilityManagerServiceSixth");
    EXPECT_CALL(*std::static_pointer_cast<MockTaskHandlerWrap>(taskHandler), SubmitTask(_, _))
        .WillRepeatedly(Return(TaskHandle()));
    abilityMs->taskHandler_ = taskHandler;

    sptr<IRemoteObject> callerToken = nullptr;
    AppExecFwk::AbilityInfo abilityInfo1;
    abilityInfo1.type == AppExecFwk::AbilityType::PAGE;
    abilityMs->ReportEventToRSS(abilityInfo1, callerToken);

    AppExecFwk::AbilityInfo abilityInfo2;
    abilityInfo2.type == AppExecFwk::AbilityType::EXTENSION;
    abilityInfo2.extensionAbilityType == AppExecFwk::ExtensionAbilityType::SERVICE;
    abilityMs->ReportEventToRSS(abilityInfo2, callerToken);

    AppExecFwk::AbilityInfo abilityInfo3;
    abilityInfo3.type == AppExecFwk::AbilityType::EXTENSION;
    abilityInfo3.extensionAbilityType ==  AppExecFwk::ExtensionAbilityType::UI;
    abilityMs->ReportEventToRSS(abilityInfo3, callerToken);
    EXPECT_NE(taskHandler, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest ReportEventToRss_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: StartUIAbilityBySCBDefault
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService StartUIAbilityBySCBDefault
 */
HWTEST_F(AbilityManagerServiceSixthTest, StartUIAbilityBySCBDefault_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartUIAbilityBySCBDefault_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    ASSERT_NE(abilityMs, nullptr);
    std::shared_ptr<TaskHandlerWrap> taskHandler =
        MockTaskHandlerWrap::CreateQueueHandler("AbilityManagerServiceSixth");
    EXPECT_CALL(*std::static_pointer_cast<MockTaskHandlerWrap>(taskHandler), SubmitTask(_, _))
        .WillRepeatedly(Return(TaskHandle()));
    abilityMs->taskHandler_ = taskHandler;
    sptr<SessionInfo> sessionInfo = new SessionInfo();
    uint32_t sceneFlag = 0;
    bool isColdStart = true;
    EXPECT_EQ(abilityMs->StartUIAbilityBySCBDefault(sessionInfo, sceneFlag, isColdStart), ERR_APP_CLONE_INDEX_INVALID);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartUIAbilityBySCBDefault_001 end");
}
}  // namespace AAFwk
}  // namespace OHOS
