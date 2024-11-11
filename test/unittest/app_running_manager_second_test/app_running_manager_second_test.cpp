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
#include "app_running_manager.h"
#include "app_running_record.h"
#include "child_process_record.h"
#undef private

#include "app_record_id.h"
#include "exit_resident_process_manager.h"
#include "hilog_tag_wrapper.h"
#include "mock_app_mgr_service_inner.h"
#include "mock_application.h"
#include "quick_fix_callback_proxy.h"
#include "quick_fix_callback_stub.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t USR_ID_100 = 100;
constexpr int32_t USR_ID_101 = 101;
const std::string BUNDLE_NAME = "testBundleName";
const std::string PROCESS_NAME = "testProcessName";


class QuickFixCallbackImpl : public QuickFixCallbackStub {
public:
    QuickFixCallbackImpl() = default;
    virtual ~QuickFixCallbackImpl() = default;

    void OnLoadPatchDone(int32_t resultCode, [[maybe_unused]] int32_t recordId) override
    {}

    void OnUnloadPatchDone(int32_t resultCode, [[maybe_unused]] int32_t recordId) override
    {}

    void OnReloadPageDone(int32_t resultCode, [[maybe_unused]] int32_t recordId) override
    {}
};
}

class AppRunningManagerSecondTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

protected:
    static BundleInfo bundleInfo;
    static std::shared_ptr<ApplicationInfo> appInfo_;
    static std::shared_ptr<MockAppMgrServiceInner> appServiceInner_;
    static sptr<MockApplication> mockApp1_;
};

BundleInfo AppRunningManagerSecondTest::bundleInfo;
std::shared_ptr<ApplicationInfo> AppRunningManagerSecondTest::appInfo_ = nullptr;
std::shared_ptr<MockAppMgrServiceInner> AppRunningManagerSecondTest::appServiceInner_ = nullptr;
sptr<MockApplication> AppRunningManagerSecondTest::mockApp1_ = nullptr;

void AppRunningManagerSecondTest::SetUpTestCase(void)
{
    appInfo_ = std::make_shared<ApplicationInfo>();
    appInfo_->bundleName = BUNDLE_NAME;
    appServiceInner_ = std::make_shared<MockAppMgrServiceInner>();
    mockApp1_ = sptr<MockApplication>::MakeSptr();
}

void AppRunningManagerSecondTest::TearDownTestCase(void)
{}

void AppRunningManagerSecondTest::SetUp()
{}

void AppRunningManagerSecondTest::TearDown()
{}

/**
 * @tc.name: AppRunningManager_CheckAppRunningRecordIsExistByUid_0100
 * @tc.desc: Test CheckAppRunningRecordIsExistByUid
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_CheckAppRunningRecordIsExistByUid_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager&AppRunningRecord instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_CheckAppRunningRecordIsExistByUid_0100 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_CheckAppRunningRecordIsExistByUid_0100 start 2");
    /**
     * @tc.steps: step2. SetUid USR_ID_100, SetRestartAppFlag false
     * @tc.expected: step2. expect CheckAppRunningRecordIsExistByUid true
     */
    EXPECT_NE(record, nullptr);
    record->SetUid(USR_ID_100);
    record->SetRestartAppFlag(false);
    bool ret = appRunningManager->CheckAppRunningRecordIsExistByUid(USR_ID_100);
    EXPECT_TRUE(ret);

    /**
     * @tc.steps: step3. SetRestartAppFlag true
     * @tc.expected: step3. expect CheckAppRunningRecordIsExistByUid false
     */
    record->SetRestartAppFlag(true);
    ret = appRunningManager->CheckAppRunningRecordIsExistByUid(USR_ID_100);
    EXPECT_FALSE(ret);

    /**
     * @tc.steps: step4. call CheckAppRunningRecordIsExistByUid USR_ID_101
     * @tc.expected: step4. expect call CheckAppRunningRecordIsExistByUid false
     */
    ret = appRunningManager->CheckAppRunningRecordIsExistByUid(USR_ID_101);
    EXPECT_FALSE(ret);

    /**
     * @tc.steps: step5. appRunningRecord is nullptr
     * @tc.expected: step5. expect CheckAppRunningRecordIsExistByUid false
     */
    appRunningManager->appRunningRecordMap_.clear();
    auto recordId = AppRecordId::Create();
    appRunningManager->appRunningRecordMap_.emplace(recordId, nullptr);
    ret = appRunningManager->CheckAppRunningRecordIsExistByUid(USR_ID_101);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_CheckAppRunningRecordIsExistByUid_0100 end");
}

/**
 * @tc.name: AppRunningManager_CheckAppCloneRunningRecordIsExistByBundleName_0100
 * @tc.desc: Test CheckAppCloneRunningRecordIsExistByBundleName
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_CheckAppCloneRunningRecordIsExistByBundleName_0100,
    TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    const std::string processName = "testProcessName";
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    ASSERT_NE(record, nullptr);

    /**
     * @tc.steps: step2. SetRestartAppFlag false, SetAppIndex 0
     * @tc.expected: step2. expect isRunning true
     */
    bool isRunning = false;
    record->SetRestartAppFlag(false);
    record->SetAppIndex(0);
    appRunningManager->CheckAppCloneRunningRecordIsExistByBundleName(BUNDLE_NAME, 0, isRunning);
    EXPECT_TRUE(isRunning);

    /**
     * @tc.steps: step3. call CheckAppCloneRunningRecordIsExistByBundleName appIndex 1
     * @tc.expected: step3. expect isRunning false
     */
    isRunning = false;
    appRunningManager->CheckAppCloneRunningRecordIsExistByBundleName(BUNDLE_NAME, 1, isRunning); // 1 means appIndex
    EXPECT_FALSE(isRunning);

    /**
     * @tc.steps: step4. SetRestartAppFlag false, SetRestartAppFlag true.
     * @tc.expected: step4. expect isRunning false
     */
    record->SetRestartAppFlag(true);
    appRunningManager->CheckAppCloneRunningRecordIsExistByBundleName(BUNDLE_NAME, 0, isRunning);
    EXPECT_FALSE(isRunning);

    /**
     * @tc.steps: step5. SetRestartAppFlag false
     * @tc.expected: step5. expect isRunning false by empty BundleName
     */
    record->SetRestartAppFlag(false);
    appRunningManager->CheckAppCloneRunningRecordIsExistByBundleName("", 0, isRunning);
    EXPECT_FALSE(isRunning);

    /**
     * @tc.steps: step6. SetRestartAppFlag false, SetRestartAppFlag true.
     * @tc.expected: step6. expect isRunning false
     */
    appRunningManager->appRunningRecordMap_.clear();
    auto recordId = AppRecordId::Create();
    appRunningManager->appRunningRecordMap_.emplace(recordId, nullptr);
    appRunningManager->CheckAppCloneRunningRecordIsExistByBundleName("", 0, isRunning);
    EXPECT_FALSE(isRunning);

    /**
     * @tc.steps: step7. clear appRunningRecordMap_.
     * @tc.expected: step7. expect isRunning false
     */
    appRunningManager->appRunningRecordMap_.clear();
    int32_t ret = appRunningManager->CheckAppCloneRunningRecordIsExistByBundleName("", 0, isRunning);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AppRunningManager_ProcessExitByBundleName_0100
 * @tc.desc: Test ProcessExitByBundleName
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_ProcessExitByBundleName_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    std::shared_ptr<AppRunningRecord> record1 =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    ASSERT_NE(record1, nullptr);
    record1->appInfos_.emplace(BUNDLE_NAME, appInfo_);

    /**
     * @tc.steps: step2. SetKeepAliveBundle false, SetPid valid pid
     * @tc.expected: step2. expect pids not empty
     */
    record1->SetKeepAliveBundle(false); // not resident process, can kill
    record1->GetPriorityObject()->SetPid(10000); // 10000 means valid process id
    std::list<pid_t> pids;
    appRunningManager->ProcessExitByBundleName(BUNDLE_NAME, pids, true);
    EXPECT_EQ(pids.size(), 1); // 1 means exit pid list size

    /**
     * @tc.steps: step3. ProcessExitByBundleName by empty bundleName
     * @tc.expected: step3. expect pids empty
     */
    pids.clear();
    appRunningManager->ProcessExitByBundleName("", pids, false);
    EXPECT_TRUE(pids.empty());

    /**
     * @tc.steps: step4. SetKeepAliveBundle false, SetPid Invalid pid
     * @tc.expected: step4. expect pids empty
     */
    record1->GetPriorityObject()->SetPid(0); // 10000 means invalid process id
    appRunningManager->ProcessExitByBundleName(BUNDLE_NAME, pids, false);
    EXPECT_TRUE(pids.empty());
}

/**
 * @tc.name: AppRunningManager_ProcessExitByBundleName_0200
 * @tc.desc: Test ProcessExitByBundleName
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_ProcessExitByBundleName_0200, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record1 =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    ASSERT_NE(record1, nullptr);
    record1->appInfos_.emplace(BUNDLE_NAME, appInfo_);

    /**
     * @tc.steps: step2. process resident process and ExitResidentProcessManager Memory Size Insufficent
     * @tc.expected: step2. expect pids not empty
     */
    std::vector<ExitResidentProcessInfo> processInfos;
    record1->SetUid(BASE_USER_RANGE);
    record1->SetKeepAliveBundle(true);
    record1->SetKeepAliveEnableState(true);
    record1->SetMainProcess(true);
    record1->GetPriorityObject()->SetPid(10000); // 10000 means valid process id
    ExitResidentProcessManager::GetInstance().HandleMemorySizeInSufficent(); // marked mem insufficient
    std::list<pid_t> pids;
    appRunningManager->ProcessExitByBundleName(BUNDLE_NAME, pids, false);
    EXPECT_TRUE(pids.empty());

    /**
     * @tc.steps: step2. process resident process and ExitResidentProcessManager Memory Size Insufficent
     * @tc.expected: step2. expect pids not empty, memory size sufficient
     */
    pids.clear();
    ExitResidentProcessManager::GetInstance().HandleMemorySizeSufficient(processInfos); // marked mem sufficient
    appRunningManager->ProcessExitByBundleName(BUNDLE_NAME, pids, true);
    EXPECT_TRUE(pids.empty());
}

/**
 * @tc.name: AppRunningManager_GetPidsByBundleNameUserIdAndAppIndex_0100
 * @tc.desc: Test GetPidsByBundleNameUserIdAndAppIndex
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_GetPidsByBundleNameUserIdAndAppIndex_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->appIndex = 0;
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record1 =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    ASSERT_NE(record1, nullptr);
    record1->appInfos_.emplace(BUNDLE_NAME, appInfo_);

    /**
     * @tc.steps: step2. SetKeepAliveBundle false, SetPid valid pid
     * @tc.expected: step2. expect pids not empty
     */
    record1->SetUid(0);
    record1->GetPriorityObject()->SetPid(10000); // 10000 means valid process id
    std::list<pid_t> pids;
    appRunningManager->GetPidsByBundleNameUserIdAndAppIndex(BUNDLE_NAME, 0, 0, pids);
    EXPECT_EQ(pids.size(), 1); // 1 means exit pid list size

    /**
     * @tc.steps: step3. GetPidsByBundleNameUserIdAndAppIndex by appIndex 1
     * @tc.expected: step3. expect pids empty
     */
    pids.clear();
    appRunningManager->GetPidsByBundleNameUserIdAndAppIndex(BUNDLE_NAME, 0, 1, pids); // 1 means appIndex
    EXPECT_TRUE(pids.empty()); // not exist

    /**
     * @tc.steps: step4. GetPidsByBundleNameUserIdAndAppIndex by userid 1
     * @tc.expected: step4. expect pids empty
     */
    appRunningManager->GetPidsByBundleNameUserIdAndAppIndex(BUNDLE_NAME, 1, 0, pids); // 1 means usrid
    EXPECT_TRUE(pids.empty()); // not exist

    /**
     * @tc.steps: step5. GetPidsByBundleNameUserIdAndAppIndex by empty bundleName
     * @tc.expected: step5. expect pids empty
     */
    appRunningManager->GetPidsByBundleNameUserIdAndAppIndex("", 0, 0, pids); // 1 means usrid
    EXPECT_TRUE(pids.empty()); // not exist

    /**
     * @tc.steps: step6. GetPidsByBundleNameUserIdAndAppIndex with invalid pid
     * @tc.expected: step6. expect pids empty
     */
    record1->GetPriorityObject()->SetPid(0); // set invalid pid
    appRunningManager->GetPidsByBundleNameUserIdAndAppIndex(BUNDLE_NAME, 0, 0, pids); // 1 means usrid
    EXPECT_TRUE(pids.empty()); // not exist

    /**
     * @tc.steps: step7. GetPidsByBundleNameUserIdAndAppIndex clear appInfos
     * @tc.expected: step7. expect pids empty
     */
    record1->GetPriorityObject()->SetPid(10000); // set invalid pid
    record1->appInfos_.clear();
    appRunningManager->GetPidsByBundleNameUserIdAndAppIndex(BUNDLE_NAME, 0, 0, pids); // 1 means usrid
    EXPECT_TRUE(pids.empty()); // not exist
}

/**
 * @tc.name: AppRunningManager_OnRemoteDied_0100
 * @tc.desc: Test OnRemoteDied
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_OnRemoteDied_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    ASSERT_NE(record, nullptr);
    std::shared_ptr<MockAppMgrServiceInner> appServiceInner = std::make_shared<MockAppMgrServiceInner>();
    sptr<MockApplication> mockApp1 = sptr<MockApplication>::MakeSptr();
    wptr<MockApplication> wp1 = mockApp1;

    /**
     * @tc.steps: step2. OnRemoteDied
     * @tc.expected: step2. expect not matched appRunningRecord
     */
    EXPECT_FALSE(appRunningManager->appRunningRecordMap_.empty());
    sptr<MockApplication> mockApp2 = sptr<MockApplication>::MakeSptr();
    wptr<MockApplication> wp2 = mockApp2;
    std::shared_ptr<AppRunningRecord> appRecord1 = appRunningManager->OnRemoteDied(wp2, appServiceInner); // not matched
    EXPECT_EQ(appRecord1, nullptr); // not matched

    /**
     * @tc.steps: step3. OnRemoteDied
     * @tc.expected: step3. expect clear matched appRunningRecord
     */
    record->SetApplicationClient(mockApp1);
    std::shared_ptr<AppRunningRecord> appRecord2 = appRunningManager->OnRemoteDied(wp1, appServiceInner);
    EXPECT_EQ(appRecord2, record); // matched
    EXPECT_EQ(record->GetApplicationClient(), nullptr); // client set nullptr
}

/**
 * @tc.name: AppRunningManager_NotifyMemoryLevel_0100
 * @tc.desc: Test NotifyMemoryLevel
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_NotifyMemoryLevel_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    auto recordId = AppRecordId::Create();
    appRunningManager->appRunningRecordMap_.emplace(recordId, nullptr);
    std::shared_ptr<AppRunningRecord> record2 =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    record2->priorityObject_ = nullptr;
    auto ret = appRunningManager->NotifyMemoryLevel(1);

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AppRunningManager_NotifyProcMemoryLevel_0100
 * @tc.desc: Test NotifyMemoryLevel
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_NotifyProcMemoryLevel_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    auto recordId = AppRecordId::Create();
    appRunningManager->appRunningRecordMap_.emplace(recordId, nullptr);
    std::shared_ptr<AppRunningRecord> record2 =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    record2->priorityObject_ = nullptr;
    std::map<pid_t, MemoryLevel> procLevelMap;
    auto ret = appRunningManager->NotifyProcMemoryLevel(procLevelMap);

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AppRunningManager_DumpHeapMemory_0100
 * @tc.desc: Test NotifyMemoryLevel
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_DumpHeapMemory_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_DumpHeapMemory_0100 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");

    auto record2 = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    record2->priorityObject_ = nullptr;
    OHOS::AppExecFwk::MallocInfo mallocInfo;
    auto ret = appRunningManager->DumpHeapMemory(1, mallocInfo);

    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_DumpHeapMemory_0100 end");
}

/**
 * @tc.name: GetAppRunningRecordByRenderPid
 * @tc.desc: Test GetAppRunningRecordByRenderPid
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_GetAppRunningRecordByRenderPid_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    auto record1 = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    auto record2 = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    auto renderRecord = std::make_shared<RenderRecord>(0, "", FdGuard(-1), FdGuard(-1), FdGuard(-1), record2);
    record2->AddRenderRecord(renderRecord);
    auto ret = appRunningManager->GetAppRunningRecordByRenderPid(1);

    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: AppRunningManager_NotifyLoadRepairPatch_0100
 * @tc.desc: Test NotifyLoadRepairPatch
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_NotifyLoadRepairPatch_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    auto record1 = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    auto ret = appRunningManager->NotifyLoadRepairPatch(BUNDLE_NAME, nullptr);

    /**
     * @tc.steps: step1. nullptr
     * @tc.expected: expect ERR_INVALID_VALUE
     */
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: AppRunningManager_NotifyLoadRepairPatch_0200
 * @tc.desc: Test NotifyLoadRepairPatch
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_NotifyLoadRepairPatch_0200, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_NotifyLoadRepairPatch_0200 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    auto record1 = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    sptr<MockApplication> mockApp1 = sptr<MockApplication>::MakeSptr();
    record1->SetApplicationClient(mockApp1);
    EXPECT_CALL(*mockApp1, ScheduleNotifyLoadRepairPatch(_, _, _)).Times(1).WillOnce(Return(ERR_OK));

    auto proxy = sptr<QuickFixCallbackProxy>::MakeSptr(new QuickFixCallbackImpl());
    auto ret = appRunningManager->NotifyLoadRepairPatch(BUNDLE_NAME, proxy);

    /**
     * @tc.steps: step1. nullptr
     * @tc.expected: expect ERR_OK
     */
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_NotifyLoadRepairPatch_0200 end");
}

/**
 * @tc.name: AppRunningManager_NotifyLoadRepairPatch_0300
 * @tc.desc: Test NotifyLoadRepairPatch
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_NotifyLoadRepairPatch_0300, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    auto proxy = sptr<QuickFixCallbackProxy>::MakeSptr(new QuickFixCallbackImpl());
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    auto recordId = AppRecordId::Create();
    appRunningManager->appRunningRecordMap_.emplace(recordId, nullptr);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    auto ret = appRunningManager->NotifyLoadRepairPatch("", proxy);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AppRunningManager_NotifyHotReloadPage_0100
 * @tc.desc: Test NotifyHotReloadPage
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_NotifyHotReloadPage_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    auto record1 = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    auto ret = appRunningManager->NotifyHotReloadPage(BUNDLE_NAME, nullptr);

    /**
     * @tc.steps: step1. nullptr
     * @tc.expected: expect ERR_INVALID_VALUE
     */
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: AppRunningManager_NotifyHotReloadPage_0200
 * @tc.desc: Test NotifyLoadRepairPatch
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_NotifyHotReloadPage_0200, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_NotifyHotReloadPage_0200 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    auto record1 = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    sptr<MockApplication> mockApp1 = sptr<MockApplication>::MakeSptr();
    record1->SetApplicationClient(mockApp1);
    EXPECT_CALL(*mockApp1, ScheduleNotifyHotReloadPage(_, _)).Times(1).WillOnce(Return(ERR_OK));

    auto proxy = sptr<QuickFixCallbackProxy>::MakeSptr(new QuickFixCallbackImpl());
    auto ret = appRunningManager->NotifyHotReloadPage(BUNDLE_NAME, proxy);

    /**
     * @tc.steps: step1. nullptr
     * @tc.expected: expect ERR_OK
     */
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_NotifyHotReloadPage_0200 end");
}

/**
 * @tc.name: AppRunningManager_NotifyHotReloadPage_0300
 * @tc.desc: Test NotifyLoadRepairPatch
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_NotifyHotReloadPage_0300, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_NotifyHotReloadPage_0300 start");
    auto proxy = sptr<QuickFixCallbackProxy>::MakeSptr(new QuickFixCallbackImpl());
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    auto recordId = AppRecordId::Create();
    appRunningManager->appRunningRecordMap_.emplace(recordId, nullptr);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    auto ret = appRunningManager->NotifyHotReloadPage("", proxy);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_NotifyHotReloadPage_0300 end");
}

/**
 * @tc.name: AppRunningManager_NotifyHotReloadPage_0100
 * @tc.desc: Test NotifyHotReloadPage
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_NotifyUnLoadRepairPatch_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_NotifyUnLoadRepairPatch_0100 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    auto record1 = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    auto ret = appRunningManager->NotifyUnLoadRepairPatch(BUNDLE_NAME, nullptr);

    /**
     * @tc.steps: step1. nullptr
     * @tc.expected: expect ERR_INVALID_VALUE
     */
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_NotifyUnLoadRepairPatch_0100 end");
}

/**
 * @tc.name: AppRunningManager_NotifyUnLoadRepairPatch_0200
 * @tc.desc: Test NotifyUnLoadRepairPatch
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_NotifyUnLoadRepairPatch_0200, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_NotifyUnLoadRepairPatch_0200 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    auto record1 = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    sptr<MockApplication> mockApp1 = sptr<MockApplication>::MakeSptr();
    record1->SetApplicationClient(mockApp1);
    EXPECT_CALL(*mockApp1, ScheduleNotifyUnLoadRepairPatch(_, _, _)).Times(1).WillOnce(Return(ERR_OK));

    auto proxy = sptr<QuickFixCallbackProxy>::MakeSptr(new QuickFixCallbackImpl());
    auto ret = appRunningManager->NotifyUnLoadRepairPatch(BUNDLE_NAME, proxy);

    /**
     * @tc.steps: step1. nullptr
     * @tc.expected: expect ERR_OK
     */
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_NotifyUnLoadRepairPatch_0200 end");
}

/**
 * @tc.name: AppRunningManager_NotifyUnLoadRepairPatch_0300
 * @tc.desc: Test NotifyUnLoadRepairPatch
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_NotifyUnLoadRepairPatch_0300, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_NotifyUnLoadRepairPatch_0300 start");
    auto proxy = sptr<QuickFixCallbackProxy>::MakeSptr(new QuickFixCallbackImpl());
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    auto recordId = AppRecordId::Create();
    appRunningManager->appRunningRecordMap_.emplace(recordId, nullptr);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    auto ret = appRunningManager->NotifyUnLoadRepairPatch("", proxy);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_NotifyUnLoadRepairPatch_0300 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstForeground_0100
 * @tc.desc: Test IsApplicationFirstForeground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstForeground_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0100 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    AppRunningRecord foregroundingRecord(appInfo_, 1, PROCESS_NAME);
    foregroundingRecord.extensionType_ = AppExecFwk::ExtensionAbilityType::UI;
    auto ret = appRunningManager->IsApplicationFirstForeground(foregroundingRecord);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0100 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstForeground_0200
 * @tc.desc: Test IsApplicationFirstForeground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstForeground_0200, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0200 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    AppRunningRecord foregroundingRecord(appInfo_, 1, PROCESS_NAME);
    foregroundingRecord.extensionType_ = AppExecFwk::ExtensionAbilityType::WINDOW;
    auto ret = appRunningManager->IsApplicationFirstForeground(foregroundingRecord);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0200 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstForeground_0300
 * @tc.desc: Test IsApplicationFirstForeground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstForeground_0300, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0300 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect true
     */
    AppRunningRecord foregroundingRecord(appInfo_, 1, PROCESS_NAME);
    foregroundingRecord.extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    auto ret = appRunningManager->IsApplicationFirstForeground(foregroundingRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0300 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstForeground_0400
 * @tc.desc: Test IsApplicationFirstForeground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstForeground_0400, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0400 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    auto recordId = AppRecordId::Create();
    appRunningManager->appRunningRecordMap_.emplace(recordId, nullptr);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 not matched record return false
     */
    AppRunningRecord foregroundingRecord(appInfo_, 1, PROCESS_NAME);
    foregroundingRecord.extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    auto ret = appRunningManager->IsApplicationFirstForeground(foregroundingRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0400 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstForeground_0500
 * @tc.desc: Test IsApplicationFirstForeground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstForeground_0500, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0500 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    auto recordId = AppRecordId::Create();
    appRunningManager->appRunningRecordMap_.emplace(recordId, nullptr);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect first Foreground
     */
    AppRunningRecord foregroundingRecord(appInfo_, 1, PROCESS_NAME);
    foregroundingRecord.extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    auto ret = appRunningManager->IsApplicationFirstForeground(foregroundingRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0500 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstForeground_0600
 * @tc.desc: Test IsApplicationFirstForeground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstForeground_0600, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0600 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect first Foreground
     */
    appInfo_->bundleName = "";
    AppRunningRecord foregroundingRecord(appInfo_, 1, PROCESS_NAME);
    foregroundingRecord.extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    auto ret = appRunningManager->IsApplicationFirstForeground(foregroundingRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0600 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstForeground_0700
 * @tc.desc: Test IsApplicationFirstForeground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstForeground_0700, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0700 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    record->extensionType_ = AppExecFwk::ExtensionAbilityType::UI;

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect first Foreground
     */
    AppRunningRecord foregroundingRecord(appInfo_, 1, PROCESS_NAME);
    foregroundingRecord.extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    auto ret = appRunningManager->IsApplicationFirstForeground(foregroundingRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0700 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstForeground_0800
 * @tc.desc: Test IsApplicationFirstForeground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstForeground_0800, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0800 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    record->extensionType_ = AppExecFwk::ExtensionAbilityType::UI;

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect first Foreground
     */
    AppRunningRecord foregroundingRecord(appInfo_, 1, PROCESS_NAME);
    foregroundingRecord.extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    auto ret = appRunningManager->IsApplicationFirstForeground(foregroundingRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0800 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstForeground_0900
 * @tc.desc: Test IsApplicationFirstForeground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstForeground_0900, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0900 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    record->extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    record->SetAppIndex(0);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect first Foreground
     */
    AppRunningRecord foregroundingRecord(appInfo_, 1, PROCESS_NAME);
    foregroundingRecord.SetAppIndex(1);
    foregroundingRecord.extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    auto ret = appRunningManager->IsApplicationFirstForeground(foregroundingRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_0900 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstForeground_1000
 * @tc.desc: Test IsApplicationFirstForeground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstForeground_1000, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_1000 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    record->extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    record->SetAppIndex(1);
    record->SetState(ApplicationState::APP_STATE_FOREGROUND);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect first Foreground
     */
    AppRunningRecord foregroundingRecord(appInfo_, 1, PROCESS_NAME);
    foregroundingRecord.SetAppIndex(1);
    foregroundingRecord.extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    auto ret = appRunningManager->IsApplicationFirstForeground(foregroundingRecord);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_1000 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstForeground_1100
 * @tc.desc: Test IsApplicationFirstForeground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstForeground_1100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_1100 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    record->extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    record->SetAppIndex(1);
    record->SetState(ApplicationState::APP_STATE_BACKGROUND);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect first Foreground
     */
    AppRunningRecord foregroundingRecord(appInfo_, 1, PROCESS_NAME);
    foregroundingRecord.SetAppIndex(1);
    foregroundingRecord.extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    auto ret = appRunningManager->IsApplicationFirstForeground(foregroundingRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstForeground_1000 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationBackground_0100
 * @tc.desc: Test IsApplicationBackground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationBackground_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationBackground_0100 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect true
     */
    AppRunningRecord backgroundRecord(appInfo_, 1, PROCESS_NAME);
    backgroundRecord.extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    auto ret = appRunningManager->IsApplicationBackground(backgroundRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationBackground_0100 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationBackground_0200
 * @tc.desc: Test IsApplicationBackground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationBackground_0200, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationBackground_0200 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    auto recordId = AppRecordId::Create();
    appRunningManager->appRunningRecordMap_.emplace(recordId, nullptr);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 not matched record return false
     */
    AppRunningRecord backgroundRecord(appInfo_, 1, PROCESS_NAME);
    auto ret = appRunningManager->IsApplicationBackground(backgroundRecord);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationBackground_0200 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationBackground_0300
 * @tc.desc: Test IsApplicationBackground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationBackground_0300, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationBackground_0300 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    auto record = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    record->extensionType_ = AppExecFwk::ExtensionAbilityType::UI;

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect first Foreground
     */
    AppRunningRecord backgroundRecord(appInfo_, 1, PROCESS_NAME);
    auto ret = appRunningManager->IsApplicationBackground(backgroundRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationBackground_0300 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationBackground_0400
 * @tc.desc: Test IsApplicationBackground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationBackground_0400, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationBackground_0400 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    auto record = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    record->extensionType_ = AppExecFwk::ExtensionAbilityType::WINDOW;

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect first Foreground
     */
    AppRunningRecord backgroundRecord(appInfo_, 1, PROCESS_NAME);
    auto ret = appRunningManager->IsApplicationBackground(backgroundRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationBackground_0400 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationBackground_0500
 * @tc.desc: Test IsApplicationBackground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationBackground_0500, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationBackground_0500 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);

    appInfo_->bundleName = BUNDLE_NAME;
    auto record = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    record->extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    record->SetState(ApplicationState::APP_STATE_FOREGROUND);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 not matched record return false
     */
    AppRunningRecord backgroundRecord(appInfo_, 1, PROCESS_NAME);
    auto ret = appRunningManager->IsApplicationBackground(backgroundRecord);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationBackground_0500 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationBackground_0500
 * @tc.desc: Test IsApplicationBackground
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationBackground_0600, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationBackground_0600 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    auto record = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    record->extensionType_ = AppExecFwk::ExtensionAbilityType::SERVICE;
    record->SetAppIndex(1);
    record->SetState(ApplicationState::APP_STATE_BACKGROUND);

    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 not matched record return false
     */
    appInfo_->bundleName = "";
    AppRunningRecord backgroundRecord(appInfo_, 1, PROCESS_NAME);
    backgroundRecord.SetAppIndex(1);
    auto ret = appRunningManager->IsApplicationBackground(backgroundRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationBackground_0600 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstFocused_0100
 * @tc.desc: Test IsApplicationFirstFocused
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstFocused_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstFocused_0100 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    auto recordId = AppRecordId::Create();
    appRunningManager->appRunningRecordMap_.emplace(recordId, nullptr);

    /**
     * @tc.steps: step2. Initialize AppRunningManager instance
     * @tc.expected: expect step1 first focused true
     */
    AppRunningRecord focusRecord(appInfo_, 1, PROCESS_NAME);
    auto ret = appRunningManager->IsApplicationFirstFocused(focusRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstFocused_0100 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstFocused_0200
 * @tc.desc: Test IsApplicationFirstFocused
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstFocused_0200, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstFocused_0200 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");

    /**
     * @tc.steps: step2. Initialize AppRunningManager instance
     * @tc.expected: expect step1 different bundle first focused true
     */
    appInfo_->bundleName = "";
    AppRunningRecord focusRecord(appInfo_, 1, PROCESS_NAME);
    auto ret = appRunningManager->IsApplicationFirstFocused(focusRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstFocused_0200 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstFocused_0300
 * @tc.desc: Test IsApplicationFirstFocused
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstFocused_0300, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstFocused_0300 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");

    /**
     * @tc.steps: step2. Initialize AppRunningManager instance
     * @tc.expected: expect step2 focused false
     */
    AppRunningRecord focusRecord(appInfo_, 1, PROCESS_NAME);
    auto ret = appRunningManager->IsApplicationFirstFocused(focusRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstFocused_0300 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstFocused_0400
 * @tc.desc: Test IsApplicationFirstFocused
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstFocused_0400, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstFocused_0400 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    auto record = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    auto abilityInfo = std::make_shared<AbilityInfo>();
    auto ability = std::make_shared<AbilityRunningRecord>(abilityInfo, nullptr, 0);
    record->AbilityFocused(ability);
    EXPECT_TRUE(record->GetFocusFlag());

    /**
     * @tc.steps: step2. Initialize AppRunningManager instance
     * @tc.expected: expect step1 focused false
     */
    AppRunningRecord focusRecord(appInfo_, 1, PROCESS_NAME);
    focusRecord.appRecordId_ = record->GetRecordId();
    auto ret = appRunningManager->IsApplicationFirstFocused(focusRecord);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstFocused_0400 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationFirstFocused_0500
 * @tc.desc: Test IsApplicationFirstFocused
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationFirstFocused_0500, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstFocused_0500 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    auto record = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    auto abilityInfo = std::make_shared<AbilityInfo>();
    auto ability = std::make_shared<AbilityRunningRecord>(abilityInfo, nullptr, 0);
    record->AbilityFocused(ability);
    EXPECT_TRUE(record->GetFocusFlag());

    /**
     * @tc.steps: step2. Initialize AppRunningManager instance
     * @tc.expected: expect step1 focused false
     */
    AppRunningRecord focusRecord(appInfo_, 1, PROCESS_NAME);
    focusRecord.appRecordId_ = record->GetRecordId() + 1;
    auto ret = appRunningManager->IsApplicationFirstFocused(focusRecord);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationFirstFocused_0500 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationUnfocused_0100
 * @tc.desc: Test IsApplicationFirstFocused
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationUnfocused_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationUnfocused_0100 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    auto recordId = AppRecordId::Create();
    appRunningManager->appRunningRecordMap_.emplace(recordId, nullptr);

    /**
     * @tc.steps: step2. Initialize AppRunningManager instance
     * @tc.expected: expect step1 first focused true
     */
    auto ret = appRunningManager->IsApplicationUnfocused("");
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationUnfocused_0100 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationUnfocused_0200
 * @tc.desc: Test IsApplicationUnfocused
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationUnfocused_0200, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationUnfocused_0200 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");

    /**
     * @tc.steps: step2. Initialize AppRunningManager instance
     * @tc.expected: expect step1 different bundle unfocused true
     */
    auto ret = appRunningManager->IsApplicationUnfocused("");
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationUnfocused_0200 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationUnfocused_0300
 * @tc.desc: Test IsApplicationFirstFocused
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationUnfocused_0300, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationUnfocused_0300 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");

    /**
     * @tc.steps: step2. Initialize AppRunningManager instance
     * @tc.expected: expect step2 focused false
     */
    auto ret = appRunningManager->IsApplicationUnfocused(BUNDLE_NAME);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationUnfocused_0300 end");
}

/**
 * @tc.name: AppRunningManager_IsApplicationUnfocused_0400
 * @tc.desc: Test IsApplicationFirstFocused
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_IsApplicationUnfocused_0400, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationUnfocused_0400 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    auto record = appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    auto abilityInfo = std::make_shared<AbilityInfo>();
    auto ability = std::make_shared<AbilityRunningRecord>(abilityInfo, nullptr, 0);
    record->AbilityFocused(ability);
    EXPECT_TRUE(record->GetFocusFlag());

    /**
     * @tc.steps: step2. Initialize AppRunningManager instance
     * @tc.expected: expect step1 focused false
     */
    auto ret = appRunningManager->IsApplicationUnfocused(BUNDLE_NAME);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_IsApplicationUnfocused_0400 end");
}

/**
 * @tc.name: AppRunningManager_SignRestartAppFlag_0100
 * @tc.desc: Test SignRestartAppFlag
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_SignRestartAppFlag_0100, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_SignRestartAppFlag_0100 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    auto recordId = AppRecordId::Create();
    appRunningManager->appRunningRecordMap_.emplace(recordId, nullptr);

    /**
     * @tc.steps: step2. Initialize AppRunningManager instance
     * @tc.expected: expect step1 first focused true
     */
    auto ret = appRunningManager->SignRestartAppFlag(0, "");
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_SignRestartAppFlag_0100 end");
}

/**
 * @tc.name: AppRunningManager_SignRestartAppFlag_0200
 * @tc.desc: Test IsApplicationUnfocused
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_SignRestartAppFlag_0200, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_SignRestartAppFlag_0200 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");

    /**
     * @tc.steps: step2. Initialize AppRunningManager instance
     * @tc.expected: expect step1 different bundle unfocused true
     */
    auto ret = appRunningManager->SignRestartAppFlag(0, "");
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_SignRestartAppFlag_0200 end");
}

/**
 * @tc.name: AppRunningManager_SignRestartAppFlag_0300
 * @tc.desc: Test IsApplicationFirstFocused
 * @tc.type: FUNC
 */
HWTEST_F(AppRunningManagerSecondTest, AppRunningManager_SignRestartAppFlag_0300, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Initialize AppRunningManager instance
     * @tc.expected: expect step1 succeed
     */
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_SignRestartAppFlag_0300 start");
    auto appRunningManager = std::make_shared<AppRunningManager>();
    EXPECT_NE(appRunningManager, nullptr);
    appInfo_->bundleName = BUNDLE_NAME;
    std::shared_ptr<AppRunningRecord> record =
        appRunningManager->CreateAppRunningRecord(appInfo_, PROCESS_NAME, bundleInfo, "");
    record->SetUid(0);

    /**
     * @tc.steps: step2. Initialize AppRunningManager instance
     * @tc.expected: expect step2 focused false
     */
    auto ret = appRunningManager->SignRestartAppFlag(0, "");
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(record->GetRestartAppFlag());
    TAG_LOGI(AAFwkTag::TEST, "AppRunningManager_SignRestartAppFlag_0300 end");
}
} // namespace AppExecFwk
} // namespace OHOS