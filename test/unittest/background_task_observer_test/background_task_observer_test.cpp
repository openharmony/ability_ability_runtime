/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "background_task_observer.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS::BackgroundTaskMgr;

namespace OHOS {
namespace AAFwk {
class BackgroundTaskObserverTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<BackgroundTaskObserver> observer_ {nullptr};
};

void BackgroundTaskObserverTest::SetUpTestCase(void)
{}
void BackgroundTaskObserverTest::TearDownTestCase(void)
{}
void BackgroundTaskObserverTest::TearDown(void)
{}
void BackgroundTaskObserverTest::SetUp()
{
    observer_ = std::make_shared<BackgroundTaskObserver>();
}

/*
 * Feature: BackgroundTaskObserver
 * Function: OnContinuousTaskStart
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver OnContinuousTaskStart
 * EnvConditions: NA
 * CaseDescription: Verify OnContinuousTaskStart
 */
HWTEST_F(BackgroundTaskObserverTest, OnContinuousTaskStart_001, TestSize.Level1)
{
    std::shared_ptr<ContinuousTaskCallbackInfo> info = std::make_shared<ContinuousTaskCallbackInfo>();
    EXPECT_NE(info, nullptr);
    observer_->OnContinuousTaskStart(info);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: OnContinuousTaskStart
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver OnContinuousTaskStart
 * EnvConditions: NA
 * CaseDescription: Verify OnContinuousTaskStart
 */
HWTEST_F(BackgroundTaskObserverTest, OnContinuousTaskStart_002, TestSize.Level1)
{
    std::shared_ptr<ContinuousTaskCallbackInfo> info = std::make_shared<ContinuousTaskCallbackInfo>();
    EXPECT_NE(info, nullptr);
    observer_->GetAppManager();
    observer_->OnContinuousTaskStart(info);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: OnContinuousTaskStop
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver OnContinuousTaskStop
 * EnvConditions: NA
 * CaseDescription: Verify OnContinuousTaskStop
 */
HWTEST_F(BackgroundTaskObserverTest, OnContinuousTaskStop_001, TestSize.Level1)
{
    std::shared_ptr<ContinuousTaskCallbackInfo> info = std::make_shared<ContinuousTaskCallbackInfo>();
    EXPECT_NE(info, nullptr);
    observer_->OnContinuousTaskStop(info);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: OnContinuousTaskStop
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver OnContinuousTaskStop
 * EnvConditions: NA
 * CaseDescription: Verify OnContinuousTaskStop
 */
HWTEST_F(BackgroundTaskObserverTest, OnContinuousTaskStop_002, TestSize.Level1)
{
    std::shared_ptr<ContinuousTaskCallbackInfo> info = std::make_shared<ContinuousTaskCallbackInfo>();
    EXPECT_NE(info, nullptr);
    observer_->GetAppManager();
    observer_->OnContinuousTaskStop(info);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: GetContinuousTaskApps
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver GetContinuousTaskApps
 * EnvConditions: NA
 * CaseDescription: Verify GetContinuousTaskApps
 */
HWTEST_F(BackgroundTaskObserverTest, GetContinuousTaskApps_001, TestSize.Level1)
{
    ASSERT_NE(observer_, nullptr);
    observer_->GetContinuousTaskApps();
}

/*
 * Feature: BackgroundTaskObserver
 * Function: IsBackgroundTaskUid
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver IsBackgroundTaskUid
 * EnvConditions: NA
 * CaseDescription: Verify IsBackgroundTaskUid
 */
HWTEST_F(BackgroundTaskObserverTest, IsBackgroundTaskUid_001, TestSize.Level1)
{
    int uid = 0;
    bool res = observer_->IsBackgroundTaskUid(uid);
    EXPECT_FALSE(res);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: IsBackgroundTaskUid
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver IsBackgroundTaskUid
 * EnvConditions: NA
 * CaseDescription: Verify IsBackgroundTaskUid
 */
HWTEST_F(BackgroundTaskObserverTest, IsBackgroundTaskUid_002, TestSize.Level1)
{
    int uid = 0;
    observer_->bgTaskUids_.push_front(uid);
    bool res = observer_->IsBackgroundTaskUid(uid);
    EXPECT_TRUE(res);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: OnProcEfficiencyResourcesApply
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver OnProcEfficiencyResourcesApply with null resourceInfo
 * EnvConditions: NA
 * CaseDescription: Verify OnProcEfficiencyResourcesApply with null resourceInfo
 */
HWTEST_F(BackgroundTaskObserverTest, OnProcEfficiencyResourcesApply_001, TestSize.Level1)
{
    EXPECT_NE(observer_, nullptr);
    observer_->OnProcEfficiencyResourcesApply(nullptr);
    EXPECT_NE(observer_, nullptr);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: OnProcEfficiencyResourcesApply
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver OnProcEfficiencyResourcesApply without WORK_SCHEDULER
 * EnvConditions: NA
 * CaseDescription: Verify OnProcEfficiencyResourcesApply with resourceNumber not contain WORK_SCHEDULER
 */
HWTEST_F(BackgroundTaskObserverTest, OnProcEfficiencyResourcesApply_002, TestSize.Level1)
{
    EXPECT_NE(observer_, nullptr);
    auto info = std::make_shared<BackgroundTaskMgr::ResourceCallbackInfo>();
    EXPECT_NE(info, nullptr);
    int testUid = 12345;
    info->uid_ = testUid;
    info->resourceNumber_ = 0;
    observer_->OnProcEfficiencyResourcesApply(info);
    bool res = observer_->IsEfficiencyResourcesTaskUid(testUid);
    EXPECT_EQ(res, false);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: OnProcEfficiencyResourcesApply
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver OnProcEfficiencyResourcesApply with WORK_SCHEDULER
 * EnvConditions: NA
 * CaseDescription: Verify OnProcEfficiencyResourcesApply with resourceNumber contain WORK_SCHEDULER
 */
HWTEST_F(BackgroundTaskObserverTest, OnProcEfficiencyResourcesApply_003, TestSize.Level1)
{
    EXPECT_NE(observer_, nullptr);
    auto info = std::make_shared<BackgroundTaskMgr::ResourceCallbackInfo>();
    EXPECT_NE(info, nullptr);
    int testUid = 12345;
    info->uid_ = testUid;
    info->resourceNumber_ = 1 << 3;
    observer_->OnProcEfficiencyResourcesApply(info);
    bool res = observer_->IsEfficiencyResourcesTaskUid(testUid);
    EXPECT_EQ(res, true);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: OnProcEfficiencyResourcesReset
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver OnProcEfficiencyResourcesReset with null resourceInfo
 * EnvConditions: NA
 * CaseDescription: Verify OnProcEfficiencyResourcesReset with null resourceInfo
 */
HWTEST_F(BackgroundTaskObserverTest, OnProcEfficiencyResourcesReset_001, TestSize.Level1)
{
    EXPECT_NE(observer_, nullptr);
    observer_->OnProcEfficiencyResourcesReset(nullptr);
    EXPECT_NE(observer_, nullptr);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: OnProcEfficiencyResourcesReset
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver OnProcEfficiencyResourcesReset without WORK_SCHEDULER
 * EnvConditions: NA
 * CaseDescription: Verify OnProcEfficiencyResourcesReset with resourceNumber not contain WORK_SCHEDULER
 */
HWTEST_F(BackgroundTaskObserverTest, OnProcEfficiencyResourcesReset_002, TestSize.Level1)
{
    EXPECT_NE(observer_, nullptr);
    auto info = std::make_shared<BackgroundTaskMgr::ResourceCallbackInfo>();
    EXPECT_NE(info, nullptr);
    int testUid = 67890;
    info->uid_ = testUid;
    info->resourceNumber_ = 0;
    observer_->efficiencyUids_.push_back(testUid);
    observer_->OnProcEfficiencyResourcesReset(info);
    bool res = observer_->IsEfficiencyResourcesTaskUid(testUid);
    EXPECT_EQ(res, true);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: OnProcEfficiencyResourcesReset
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver OnProcEfficiencyResourcesReset with WORK_SCHEDULER but uid not exist
 * EnvConditions: NA
 * CaseDescription: Verify OnProcEfficiencyResourcesReset with WORK_SCHEDULER but uid not in list
 */
HWTEST_F(BackgroundTaskObserverTest, OnProcEfficiencyResourcesReset_003, TestSize.Level1)
{
    EXPECT_NE(observer_, nullptr);
    auto info = std::make_shared<BackgroundTaskMgr::ResourceCallbackInfo>();
    EXPECT_NE(info, nullptr);
    int testUid = 11223;
    info->uid_ = testUid;
    info->resourceNumber_ = 1 << 3;

    observer_->OnProcEfficiencyResourcesReset(info);
    bool res = observer_->IsEfficiencyResourcesTaskUid(testUid);
    EXPECT_EQ(res, false);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: OnProcEfficiencyResourcesReset
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver OnProcEfficiencyResourcesReset with WORK_SCHEDULER and uid exist
 * EnvConditions: NA
 * CaseDescription: Verify OnProcEfficiencyResourcesReset with WORK_SCHEDULER and uid in list
 */
HWTEST_F(BackgroundTaskObserverTest, OnProcEfficiencyResourcesReset_004, TestSize.Level1)
{
    EXPECT_NE(observer_, nullptr);
    auto info = std::make_shared<BackgroundTaskMgr::ResourceCallbackInfo>();
    EXPECT_NE(info, nullptr);
    int testUid = 44556;
    info->uid_ = testUid;
    info->resourceNumber_ = 1 << 3;

    observer_->OnProcEfficiencyResourcesApply(info);
    bool resBefore = observer_->IsEfficiencyResourcesTaskUid(testUid);
    EXPECT_EQ(resBefore, true);

    observer_->OnProcEfficiencyResourcesReset(info);
    bool resAfter = observer_->IsEfficiencyResourcesTaskUid(testUid);
    EXPECT_EQ(resAfter, false);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: OnAppEfficiencyResourcesApply
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver OnAppEfficiencyResourcesApply
 * EnvConditions: NA
 * CaseDescription: Verify OnAppEfficiencyResourcesApply
 */
HWTEST_F(BackgroundTaskObserverTest, OnAppEfficiencyResourcesApply_001, TestSize.Level1)
{
    EXPECT_NE(observer_, nullptr);
    auto info = std::make_shared<BackgroundTaskMgr::ResourceCallbackInfo>();
    EXPECT_NE(info, nullptr);
    int testUid = 77889;
    info->uid_ = testUid;
    info->resourceNumber_ = 1 << 3;

    observer_->OnAppEfficiencyResourcesApply(info);
    bool res = observer_->IsEfficiencyResourcesTaskUid(testUid);
    EXPECT_EQ(res, true);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: OnAppEfficiencyResourcesReset
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver OnAppEfficiencyResourcesReset
 * EnvConditions: NA
 * CaseDescription: Verify OnAppEfficiencyResourcesReset
 */
HWTEST_F(BackgroundTaskObserverTest, OnAppEfficiencyResourcesReset_001, TestSize.Level1)
{
    EXPECT_NE(observer_, nullptr);
    auto info = std::make_shared<BackgroundTaskMgr::ResourceCallbackInfo>();
    EXPECT_NE(info, nullptr);
    int testUid = 99001;
    info->uid_ = testUid;
    info->resourceNumber_ = 1 << 3;

    observer_->OnAppEfficiencyResourcesApply(info);
    observer_->OnAppEfficiencyResourcesReset(info);
    bool res = observer_->IsEfficiencyResourcesTaskUid(testUid);
    EXPECT_EQ(res, false);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: GetEfficiencyResourcesTaskApps
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver GetEfficiencyResourcesTaskApps with result != ERR_OK
 * EnvConditions: NA
 * CaseDescription: Verify GetEfficiencyResourcesTaskApps with failed result
 */
HWTEST_F(BackgroundTaskObserverTest, GetEfficiencyResourcesTaskApps_001, TestSize.Level1)
{
    EXPECT_NE(observer_, nullptr);
    observer_->GetEfficiencyResourcesTaskApps();
    EXPECT_NE(observer_, nullptr);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: GetEfficiencyResourcesTaskApps
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver GetEfficiencyResourcesTaskApps with result == ERR_OK
 * EnvConditions: NA
 * CaseDescription: Verify GetEfficiencyResourcesTaskApps with success result
 */
HWTEST_F(BackgroundTaskObserverTest, GetEfficiencyResourcesTaskApps_002, TestSize.Level1)
{
    EXPECT_NE(observer_, nullptr);
    observer_->efficiencyUids_.clear();
    observer_->GetEfficiencyResourcesTaskApps();
    EXPECT_NE(observer_, nullptr);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: IsEfficiencyResourcesTaskUid
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver IsEfficiencyResourcesTaskUid with uid not exist
 * EnvConditions: NA
 * CaseDescription: Verify IsEfficiencyResourcesTaskUid with uid not exist
 */
HWTEST_F(BackgroundTaskObserverTest, IsEfficiencyResourcesTaskUid_001, TestSize.Level1)
{
    EXPECT_NE(observer_, nullptr);
    int uid = 123;
    bool res = observer_->IsEfficiencyResourcesTaskUid(uid);
    EXPECT_EQ(res, false);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: IsEfficiencyResourcesTaskUid
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver IsEfficiencyResourcesTaskUid with uid exist
 * EnvConditions: NA
 * CaseDescription: Verify IsEfficiencyResourcesTaskUid with uid exist
 */
HWTEST_F(BackgroundTaskObserverTest, IsEfficiencyResourcesTaskUid_002, TestSize.Level1)
{
    EXPECT_NE(observer_, nullptr);
    int uid = 456;
    observer_->efficiencyUids_.push_back(uid);
    bool res = observer_->IsEfficiencyResourcesTaskUid(uid);
    EXPECT_EQ(res, true);
}

/*
 * Feature: BackgroundTaskObserver
 * Function: GetContinuousTaskApps
 * SubFunction: NA
 * FunctionPoints: BackgroundTaskObserver GetContinuousTaskApps with result != ERR_OK
 * EnvConditions: NA
 * CaseDescription: Verify GetContinuousTaskApps with failed result
 */
HWTEST_F(BackgroundTaskObserverTest, GetContinuousTaskApps_002, TestSize.Level1)
{
    EXPECT_NE(observer_, nullptr);
    observer_->GetContinuousTaskApps();
    EXPECT_NE(observer_, nullptr);
}
}  // namespace AAFwk
}  // namespace OHOS
