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
#include <mutex>

#define private public
#include "exit_resident_process_manager.h"
#undef private

#include "ability_manager_errors.h"
#include "hilog_tag_wrapper.h"
#include "in_process_call_wrapper.h"
#include "remote_client_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class ExitResidentProcessManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void ExitResidentProcessManagerTest::SetUpTestCase()
{}

void ExitResidentProcessManagerTest::TearDownTestCase()
{}

void ExitResidentProcessManagerTest::SetUp()
{}

void ExitResidentProcessManagerTest::TearDown()
{}

/**
 * @tc.name: IsMemorySizeSufficent_001
 * @tc.desc: Verify that the IsMemorySizeSufficent interface calls normally
 * @tc.type: FUNC
 */
HWTEST_F(ExitResidentProcessManagerTest, IsMemorySizeSufficent_001, TestSize.Level1)
{
    auto exitResidentProcessManager = std::make_shared<ExitResidentProcessManager>();
    EXPECT_EQ(exitResidentProcessManager->IsMemorySizeSufficent(), true);
}

/**
 * @tc.name: RecordExitResidentBundleName_001
 * @tc.desc: Verify that the RecordExitResidentBundleName interface calls normally
 * @tc.type: FUNC
 */
HWTEST_F(ExitResidentProcessManagerTest, RecordExitResidentBundleName_001, TestSize.Level1)
{
    std::string bundleName = "bundleName";
    auto exitResidentProcessManager = std::make_shared<ExitResidentProcessManager>();
    int32_t uid = 0;
    EXPECT_EQ(exitResidentProcessManager->RecordExitResidentBundleName(bundleName, uid), false);
}

/**
 * @tc.name: RecordExitResidentBundleDependedOnWeb_001
 * @tc.desc: Verify that the RecordExitResidentBundleDependedOnWeb interface calls normally
 * @tc.type: FUNC
 */
HWTEST_F(ExitResidentProcessManagerTest, RecordExitResidentBundleDependedOnWeb_001, TestSize.Level1)
{
    std::string bundleName = "bundleName";
    auto exitResidentProcessManager = std::make_shared<ExitResidentProcessManager>();
    int32_t uid = 0;
    exitResidentProcessManager->RecordExitResidentBundleDependedOnWeb(bundleName, uid);
    auto flag = exitResidentProcessManager->exitResidentBundlesDependedOnWeb_;
    EXPECT_EQ(flag.empty(), false);
}

/**
 * @tc.name: HandleMemorySizeInSufficent_001
 * @tc.desc: Verify that the HandleMemorySizeInSufficent interface calls normally
 * @tc.type: FUNC
 */
HWTEST_F(ExitResidentProcessManagerTest, HandleMemorySizeInSufficent_001, TestSize.Level1)
{
    auto exitResidentProcessManager = std::make_shared<ExitResidentProcessManager>();
    exitResidentProcessManager->HandleMemorySizeInSufficent();
    EXPECT_EQ(exitResidentProcessManager->HandleMemorySizeInSufficent(),
        AAFwk::ERR_NATIVE_MEMORY_SIZE_STATE_UNCHANGED);
}

/**
 * @tc.name: HandleMemorySizeInSufficent_002
 * @tc.desc: Verify that the HandleMemorySizeInSufficent interface calls normally
 * @tc.type: FUNC
 */
HWTEST_F(ExitResidentProcessManagerTest, HandleMemorySizeInSufficent_002, TestSize.Level1)
{
    auto exitResidentProcessManager = std::make_shared<ExitResidentProcessManager>();
    EXPECT_EQ(exitResidentProcessManager->HandleMemorySizeInSufficent(), ERR_OK);
}

/**
 * @tc.name: HandleExitResidentBundleDependedOnWeb_001
 * @tc.desc: Verify that the HandleExitResidentBundleDependedOnWeb interface calls normally
 * @tc.type: FUNC
 */
HWTEST_F(ExitResidentProcessManagerTest, HandleExitResidentBundleDependedOnWeb_001, TestSize.Level1)
{
    std::vector<ExitResidentProcessInfo> bundleNames;
    auto exitResidentProcessManager = std::make_shared<ExitResidentProcessManager>();
    exitResidentProcessManager->HandleExitResidentBundleDependedOnWeb(bundleNames);
    auto flag = exitResidentProcessManager->exitResidentBundlesDependedOnWeb_;
    EXPECT_EQ(flag.empty(), true);
}

/**
 * @tc.name: QueryExitBundleInfos_001
 * @tc.desc: Verify that the QueryExitBundleInfos interface calls normally
 * @tc.type: FUNC
 */
HWTEST_F(ExitResidentProcessManagerTest, QueryExitBundleInfos_001, TestSize.Level1)
{
    std::vector<ExitResidentProcessInfo> exitBundleNames;
    std::vector<AppExecFwk::BundleInfo> exitBundleInfos;
    auto exitResidentProcessManager = std::make_shared<ExitResidentProcessManager>();
    std::shared_ptr<RemoteClientManager> remoteClientManager = std::make_shared<RemoteClientManager>();
    auto bundleMgrHelper = remoteClientManager->GetBundleManagerHelper();
    exitResidentProcessManager->QueryExitBundleInfos(exitBundleNames, exitBundleInfos);
    EXPECT_NE(remoteClientManager, nullptr);
    EXPECT_NE(bundleMgrHelper, nullptr);
}

/**
 * @tc.name: IsKilledForUpgradeWeb_001
 * @tc.desc: Verify that the IsKilledForUpgradeWeb interface calls normally
 * @tc.type: FUNC
 */
HWTEST_F(ExitResidentProcessManagerTest, IsKilledForUpgradeWeb_001, TestSize.Level1)
{
    std::string bundleName = "bundleName";
    auto exitResidentProcessManager = std::make_shared<ExitResidentProcessManager>();
    // exitResidentProcessManager->exitResidentBundlesDependedOnWeb_;
    EXPECT_EQ(exitResidentProcessManager->IsKilledForUpgradeWeb(bundleName), false);
}
} // namespace AppExecFwk
} // namespace OHOS