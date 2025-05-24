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

#include "app_mgr_service.h"
#include "app_utils.h"
#include "ability_manager_errors.h"
#include "hilog_tag_wrapper.h"
#include "mock_app_mgr_service_inner.h"
#include "parameters.h"
#include "mock_permission_verification.h"
#include "mock_my_flag.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t FOUNDATION_UID = 5523;
}
class AppMgrServiceThirdTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<AAFwk::TaskHandlerWrap> taskHandler_;
};

void AppMgrServiceThirdTest::SetUpTestCase()
{
}

void AppMgrServiceThirdTest::TearDownTestCase()
{
}

void AppMgrServiceThirdTest::SetUp()
{
    taskHandler_ = AAFwk::TaskHandlerWrap::CreateQueueHandler(Constants::APP_MGR_SERVICE_NAME);
}

void AppMgrServiceThirdTest::TearDown()
{
    taskHandler_.reset();
}

/*
 * Feature: AppMgrService
 * Function: GetRunningMultiAppInfoByBundleName
 * SubFunction: NA
 * FunctionPoints: AppMgrService GetRunningMultiAppInfoByBundleName
 * EnvConditions: NA
 * CaseDescription: Verify GetRunningMultiAppInfoByBundleName
 */
HWTEST_F(AppMgrServiceThirdTest, GetRunningMultiAppInfoByBundleName_001, TestSize.Level1)
{
    auto appMgrService = std::make_shared<AppMgrService>();
    ASSERT_NE(appMgrService, nullptr);
    appMgrService->SetInnerService(nullptr);
    std::string bundleName = "testBundleName";
    RunningMultiAppInfo info;
    int32_t res = appMgrService->GetRunningMultiAppInfoByBundleName(bundleName, info);
    EXPECT_EQ(res, ERR_INVALID_OPERATION);

    appMgrService->SetInnerService(std::make_shared<AppMgrServiceInner>());
    appMgrService->taskHandler_ = taskHandler_;
    appMgrService->eventHandler_ = std::make_shared<AMSEventHandler>(taskHandler_, appMgrService->appMgrServiceInner_);
    AAFwk::MyFlag::flag_ = 0;
    res = appMgrService->GetRunningMultiAppInfoByBundleName(bundleName, info);
    EXPECT_EQ(res, ERR_INVALID_OPERATION);

    AAFwk::MyFlag::flag_ = 1;
    AAFwk::MyFlag::perm = false;
    res = appMgrService->GetRunningMultiAppInfoByBundleName(bundleName, info);
    EXPECT_EQ(res, ERR_PERMISSION_DENIED);

    AAFwk::MyFlag::perm = true;
    res = appMgrService->GetRunningMultiAppInfoByBundleName(bundleName, info);
    EXPECT_NE(res, ERR_INVALID_VALUE);
}

/*
 * Feature: AppMgrService
 * Function: GetRunningProcessesByBundleType
 * SubFunction: NA
 * FunctionPoints: AppMgrService GetRunningProcessesByBundleType
 * EnvConditions: NA
 * CaseDescription: Verify GetRunningProcessesByBundleType
 */
HWTEST_F(AppMgrServiceThirdTest, GetRunningProcessesByBundleType_001, TestSize.Level1)
{
    auto appMgrService = std::make_shared<AppMgrService>();
    ASSERT_NE(appMgrService, nullptr);
    appMgrService->SetInnerService(nullptr);
    std::vector<RunningProcessInfo> info;
    int32_t res = appMgrService->GetRunningProcessesByBundleType(AppExecFwk::BundleType::APP_SERVICE_FWK, info);
    EXPECT_EQ(res, ERR_INVALID_OPERATION);

    appMgrService->SetInnerService(std::make_shared<AppMgrServiceInner>());
    appMgrService->taskHandler_ = taskHandler_;
    appMgrService->eventHandler_ = std::make_shared<AMSEventHandler>(taskHandler_, appMgrService->appMgrServiceInner_);
    AAFwk::MyFlag::perm = true;
    res = appMgrService->GetRunningProcessesByBundleType(AppExecFwk::BundleType::APP_SERVICE_FWK, info);
    EXPECT_EQ(res, ERR_OK);
}

/*
 * Feature: AppMgrService
 * Function: JudgeSandboxByPid
 * SubFunction: NA
 * FunctionPoints: AppMgrService JudgeSandboxByPid
 * EnvConditions: NA
 * CaseDescription: Verify JudgeSandboxByPid
 */
HWTEST_F(AppMgrServiceThirdTest, JudgeSandboxByPid_001, TestSize.Level1)
{
    auto appMgrService = std::make_shared<AppMgrService>();
    ASSERT_NE(appMgrService, nullptr);
    appMgrService->SetInnerService(nullptr);
    pid_t pid = 1001;
    bool isSandbox = false;
    int32_t res = appMgrService->JudgeSandboxByPid(pid, isSandbox);
    EXPECT_EQ(res, ERR_INVALID_OPERATION);

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    AAFwk::MyFlag::flag_ = 0;
    appMgrService->taskHandler_ = taskHandler_;
    appMgrService->SetInnerService(appMgrServiceInner);
    appMgrService->eventHandler_ = std::make_shared<AMSEventHandler>(taskHandler_, appMgrService->appMgrServiceInner_);
    res = appMgrService->JudgeSandboxByPid(pid, isSandbox);
    EXPECT_EQ(res, ERR_PERMISSION_DENIED);

    AAFwk::MyFlag::flag_ = 1;
    BundleInfo bundleInfo;
    std::string appName = "test_appName";
    std::string processName = "test_processName";
    std::string bundleName = "test_bundleName";
    ApplicationInfo applicationInfo;
    applicationInfo.name = appName;
    applicationInfo.bundleName = bundleName;
    std::shared_ptr<ApplicationInfo> applicationInfo_ = std::make_shared<ApplicationInfo>(applicationInfo);
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo, "");
    EXPECT_NE(appRecord, nullptr);
    appRecord->SetAppIndex(2000);
    appMgrServiceInner->appRunningManager_->appRunningRecordMap_.emplace(static_cast<int32_t>(pid), appRecord);
    appMgrService->SetInnerService(appMgrServiceInner);
    appMgrService->eventHandler_ = std::make_shared<AMSEventHandler>(taskHandler_, appMgrService->appMgrServiceInner_);
    res = appMgrService->JudgeSandboxByPid(0, isSandbox);
    EXPECT_EQ(res, ERR_OK);

    appRecord->SetAppIndex(1000);
    appMgrService->SetInnerService(appMgrServiceInner);
    res = appMgrService->JudgeSandboxByPid(pid, isSandbox);
    EXPECT_EQ(res, ERR_OK);
}


/*
 * Feature: AppMgrService
 * Function: IsTerminatingByPid
 * SubFunction: NA
 * FunctionPoints: AppMgrService IsTerminatingByPid
 * EnvConditions: NA
 * CaseDescription: Verify IsTerminatingByPid
 */
HWTEST_F(AppMgrServiceThirdTest, IsTerminatingByPid_001, TestSize.Level1)
{
    auto appMgrService = std::make_shared<AppMgrService>();
    ASSERT_NE(appMgrService, nullptr);
    appMgrService->SetInnerService(nullptr);
    pid_t pid = 1001;
    bool isTerminating = false;
    int32_t res = appMgrService->IsTerminatingByPid(pid, isTerminating);
    EXPECT_EQ(res, ERR_INVALID_OPERATION);

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    AAFwk::MyFlag::flag_ = 0;
    appMgrService->taskHandler_ = taskHandler_;
    appMgrService->eventHandler_ = std::make_shared<AMSEventHandler>(taskHandler_, appMgrService->appMgrServiceInner_);
    appMgrService->SetInnerService(appMgrServiceInner);
    res = appMgrService->IsTerminatingByPid(pid, isTerminating);
    EXPECT_EQ(res, ERR_PERMISSION_DENIED);

    AAFwk::MyFlag::flag_ = 1;
    BundleInfo bundleInfo;
    std::string appName = "test_appName";
    std::string processName = "test_processName";
    std::string bundleName = "test_bundleName";
    ApplicationInfo applicationInfo;
    applicationInfo.name = appName;
    applicationInfo.bundleName = bundleName;
    std::shared_ptr<ApplicationInfo> applicationInfo_ = std::make_shared<ApplicationInfo>(applicationInfo);
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo, "");
    EXPECT_NE(appRecord, nullptr);
    appMgrServiceInner->appRunningManager_->appRunningRecordMap_.emplace(static_cast<int32_t>(pid), appRecord);
    appMgrService->SetInnerService(appMgrServiceInner);
    appMgrService->eventHandler_ = std::make_shared<AMSEventHandler>(taskHandler_, appMgrService->appMgrServiceInner_);
    res = appMgrService->IsTerminatingByPid(pid, isTerminating);
    EXPECT_EQ(res, ERR_OK);

    appRecord->SetTerminating();
    appMgrService->SetInnerService(appMgrServiceInner);
    res = appMgrService->IsTerminatingByPid(0, isTerminating);
    EXPECT_EQ(res, ERR_OK);
}

/*
 * Feature: AppMgrService
 * Function: DumpJsHeapMemory
 * SubFunction: NA
 * FunctionPoints: AppMgrService DumpJsHeapMemory
 * EnvConditions: NA
 * CaseDescription: Verify DumpJsHeapMemory
 */
HWTEST_F(AppMgrServiceThirdTest, DumpJsHeapMemory_001, TestSize.Level1)
{
    auto appMgrService = std::make_shared<AppMgrService>();
    ASSERT_NE(appMgrService, nullptr);
    appMgrService->SetInnerService(nullptr);
    OHOS::AppExecFwk::JsHeapDumpInfo info;
    info.pid = 1;
    info.tid = 1;
    int32_t res = appMgrService->DumpJsHeapMemory(info);
    EXPECT_EQ(res, ERR_INVALID_OPERATION);

    appMgrService->SetInnerService(std::make_shared<AppMgrServiceInner>());
    appMgrService->taskHandler_ = taskHandler_;
    appMgrService->eventHandler_ = std::make_shared<AMSEventHandler>(taskHandler_, appMgrService->appMgrServiceInner_);
    res = appMgrService->DumpJsHeapMemory(info);
    EXPECT_NE(res, ERR_INVALID_OPERATION);
}

/*
 * Feature: AppMgrService
 * Function: NotifyMemoryLevel
 * SubFunction: NA
 * FunctionPoints: AppMgrService NotifyMemoryLevel
 * EnvConditions: NA
 * CaseDescription: Verify NotifyMemoryLevel
 */
HWTEST_F(AppMgrServiceThirdTest, NotifyMemoryLevel_001, TestSize.Level1)
{
    auto appMgrService = std::make_shared<AppMgrService>();
    ASSERT_NE(appMgrService, nullptr);
    appMgrService->SetInnerService(nullptr);
    int32_t level = OHOS::AppExecFwk::MemoryLevel::MEMORY_LEVEL_MODERATE;
    int32_t res = appMgrService->NotifyMemoryLevel(level);
    EXPECT_EQ(res, ERR_INVALID_OPERATION);

    appMgrService->SetInnerService(std::make_shared<AppMgrServiceInner>());
    appMgrService->taskHandler_ = taskHandler_;
    appMgrService->eventHandler_ = std::make_shared<AMSEventHandler>(taskHandler_, appMgrService->appMgrServiceInner_);
    AAFwk::MyFlag::perm = true;
    res = appMgrService->NotifyMemoryLevel(level);
    EXPECT_NE(res, ERR_INVALID_OPERATION);
}

/*
 * Feature: AppMgrService
 * Function: LaunchAbility
 * SubFunction: NA
 * FunctionPoints: AppMgrService LaunchAbility
 * EnvConditions: NA
 * CaseDescription: Verify LaunchAbility
 */
HWTEST_F(AppMgrServiceThirdTest, LaunchAbility_001, TestSize.Level1)
{
    auto appMgrService = std::make_shared<AppMgrService>();
    appMgrService->SetInnerService(nullptr);
    int32_t res = appMgrService->LaunchAbility(nullptr);
    EXPECT_EQ(res, AAFwk::ERR_APP_MGR_SERVICE_NOT_READY);

    appMgrService->SetInnerService(std::make_shared<AppMgrServiceInner>());
    appMgrService->taskHandler_ = taskHandler_;
    appMgrService->eventHandler_ = std::make_shared<AMSEventHandler>(taskHandler_, appMgrService->appMgrServiceInner_);
    res = appMgrService->LaunchAbility(nullptr);
    EXPECT_EQ(res, AAFwk::ERR_NULL_APP_RUNNING_MANAGER);
}

/*
 * Feature: AppMgrService
 * Function: UpdateConfigurationForBackgroundApp
 * SubFunction: NA
 * FunctionPoints: AppMgrService UpdateConfigurationForBackgroundApp
 * EnvConditions: NA
 * CaseDescription: Verify UpdateConfigurationForBackgroundApp
 */
HWTEST_F(AppMgrServiceThirdTest, UpdateConfigurationForBackgroundApp_001, TestSize.Level2)
{
    auto appMgrService = std::make_shared<AppMgrService>();
    std::vector<BackgroundAppInfo> appInfos;
    AppExecFwk::ConfigurationPolicy policy;
    int32_t userId = -1;
    appMgrService->SetInnerService(nullptr);
    AAFwk::MyFlag::flag_ = 0;
    int32_t res = appMgrService->UpdateConfigurationForBackgroundApp(appInfos, policy, userId);
    EXPECT_EQ(res, ERR_PERMISSION_DENIED);
    AAFwk::MyFlag::flag_ = 1;
    res = appMgrService->UpdateConfigurationForBackgroundApp(appInfos, policy, userId);
    EXPECT_EQ(res, ERR_INVALID_OPERATION);
}

/*
 * Feature: AppMgrService
 * Function: UpdateConfigurationForBackgroundApp
 * SubFunction: NA
 * FunctionPoints: AppMgrService UpdateConfigurationForBackgroundApp
 * EnvConditions: NA
 * CaseDescription: Verify UpdateConfigurationForBackgroundApp
 */
HWTEST_F(AppMgrServiceThirdTest, UpdateConfigurationForBackgroundApp_002, TestSize.Level2)
{
    auto appMgrService = std::make_shared<AppMgrService>();
    std::vector<BackgroundAppInfo> appInfos;
    AppExecFwk::ConfigurationPolicy policy;
    int32_t userId = -1;
    AAFwk::MyFlag::flag_ = 1;
    appMgrService->SetInnerService(std::make_shared<AppMgrServiceInner>());
    appMgrService->taskHandler_ = taskHandler_;
    appMgrService->eventHandler_ = std::make_shared<AMSEventHandler>(taskHandler_, appMgrService->appMgrServiceInner_);
    int32_t res = appMgrService->UpdateConfigurationForBackgroundApp(appInfos, policy, userId);
    EXPECT_EQ(res, ERR_PERMISSION_DENIED);
}
} // namespace AppExecFwk
} // namespace OHOS