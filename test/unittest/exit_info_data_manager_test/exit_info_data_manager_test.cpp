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
#include <memory>

#define private public
#define protected public
#include "exit_info_data_manager.h"
#undef private
#undef protected

#include "ability_config.h"
#include "ability_manager_errors.h"
#include "ability_scheduler.h"
#include "ability_util.h"
#include "bundlemgr/mock_bundle_manager.h"
#include "hilog_tag_wrapper.h"
#include "mock_ability_connect_callback.h"
#include "mock_sa_call.h"
#include "mock_task_handler_wrap.h"
#include "sa_mgr_client.h"
#include "system_ability_definition.h"
#include <thread>
#include <chrono>

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using testing::_;
using testing::Return;

namespace {
    const int32_t SLEEP_TIME = 10000;
}
namespace OHOS {
namespace AAFwk {

class ExitInfoDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ExitInfoDataManagerTest::SetUpTestCase(void)
{}
void ExitInfoDataManagerTest::TearDownTestCase(void)
{}

void ExitInfoDataManagerTest::SetUp()
{}
void ExitInfoDataManagerTest::TearDown()
{}

/*
 * Feature: ExitInfoDataManager
 * Function: AddExitInfo
 * SubFunction: NA
 * EnvConditions:NA
 * CaseDescription: Verify AddExitInfo
 */
HWTEST_F(ExitInfoDataManagerTest, AddExitInfo_001, TestSize.Level1)
{
    TAG_LOGD(AAFwkTag::TEST, "AddExitInfo_001 called. start");
    uint32_t accessTokenId = 0;
    AbilityRuntime::ExitCacheInfo cacheInfo;
    auto ret = AbilityRuntime::ExitInfoDataManager::GetInstance().AddExitInfo(accessTokenId, cacheInfo);
    EXPECT_EQ(ret, true);
    ret = AbilityRuntime::ExitInfoDataManager::GetInstance().AddExitInfo(accessTokenId, cacheInfo);
    EXPECT_EQ(ret, false);
    TAG_LOGD(AAFwkTag::TEST, "AddExitInfo_001 called. end");
}

/*
 * Feature: ExitInfoDataManager
 * Function: DeleteExitInfo
 * SubFunction: NA
 * EnvConditions:NA
 * CaseDescription: Verify DeleteExitInfo
 */
HWTEST_F(ExitInfoDataManagerTest, DeleteExitInfo_001, TestSize.Level1)
{
    TAG_LOGD(AAFwkTag::TEST, "DeleteExitInfo_001 called. start");
    uint32_t accessTokenId = 222;
    AbilityRuntime::ExitCacheInfo cacheInfo;
    auto ret = AbilityRuntime::ExitInfoDataManager::GetInstance().AddExitInfo(accessTokenId, cacheInfo);
    EXPECT_EQ(ret, true);
    ret = AbilityRuntime::ExitInfoDataManager::GetInstance().DeleteExitInfo(accessTokenId);
    EXPECT_EQ(ret, true);
    ret = AbilityRuntime::ExitInfoDataManager::GetInstance().DeleteExitInfo(accessTokenId);
    EXPECT_EQ(ret, false);
    TAG_LOGD(AAFwkTag::TEST, "DeleteExitInfo_001 called. end");
}

/*
 * Feature: ExitInfoDataManager
 * Function: GetExitInfo
 * SubFunction: NA
 * EnvConditions:NA
 * CaseDescription: Verify GetExitInfo
 */
HWTEST_F(ExitInfoDataManagerTest, GetExitInfo_001, TestSize.Level1)
{
    TAG_LOGD(AAFwkTag::TEST, "GetExitInfo_001 called. start");
    uint32_t accessTokenId = 333;
    AbilityRuntime::ExitCacheInfo cacheInfo;
    auto ret = AbilityRuntime::ExitInfoDataManager::GetInstance().AddExitInfo(accessTokenId, cacheInfo);
    EXPECT_EQ(ret, true);
    ret = AbilityRuntime::ExitInfoDataManager::GetInstance().GetExitInfo(accessTokenId, cacheInfo);
    EXPECT_EQ(ret, true);
    ret = AbilityRuntime::ExitInfoDataManager::GetInstance().GetExitInfo(accessTokenId, cacheInfo);
    EXPECT_EQ(ret, false);
    TAG_LOGD(AAFwkTag::TEST, "GetExitInfo_001 called. end");
}

/*
 * Feature: ExitInfoDataManager
 * Function: GetExitInfo
 * SubFunction: NA
 * EnvConditions:NA
 * CaseDescription: Verify GetExitInfo
 */
HWTEST_F(ExitInfoDataManagerTest, GetExitInfo_002, TestSize.Level1)
{
    TAG_LOGD(AAFwkTag::TEST, "GetExitInfo_002 called. start");
    uint32_t accessTokenId = 666;
    AbilityRuntime::ExitCacheInfo cacheInfo;
    cacheInfo.exitInfo.pid_ = 111;
    cacheInfo.exitInfo.uid_ = 222;
    auto ret = AbilityRuntime::ExitInfoDataManager::GetInstance().AddExitInfo(accessTokenId, cacheInfo);
    EXPECT_EQ(ret, true);
    AbilityRuntime::ExitCacheInfo cacheInfo2;
    ret = AbilityRuntime::ExitInfoDataManager::GetInstance().GetExitInfo(111, 222, accessTokenId, cacheInfo2);
    EXPECT_EQ(ret, true);
    ret = AbilityRuntime::ExitInfoDataManager::GetInstance().GetExitInfo(111, 222, accessTokenId, cacheInfo2);
    EXPECT_EQ(ret, false);
    TAG_LOGD(AAFwkTag::TEST, "GetExitInfo_002 called. end");
}

/*
 * Feature: ExitInfoDataManager
 * Function: IsExitInfoExist
 * SubFunction: NA
 * EnvConditions:NA
 * CaseDescription: Verify IsExitInfoExist
 */
HWTEST_F(ExitInfoDataManagerTest, IsExitInfoExist_001, TestSize.Level1)
{
    TAG_LOGD(AAFwkTag::TEST, "IsExitInfoExist_001 called. start");
    uint32_t accessTokenId = 777;
    AbilityRuntime::ExitCacheInfo cacheInfo;
    auto ret = AbilityRuntime::ExitInfoDataManager::GetInstance().AddExitInfo(accessTokenId, cacheInfo);
    EXPECT_EQ(ret, true);
    ret = AbilityRuntime::ExitInfoDataManager::GetInstance().IsExitInfoExist(accessTokenId);
    EXPECT_EQ(ret, true);
    ret = AbilityRuntime::ExitInfoDataManager::GetInstance().DeleteExitInfo(accessTokenId);
    EXPECT_EQ(ret, true);
    ret = AbilityRuntime::ExitInfoDataManager::GetInstance().IsExitInfoExist(accessTokenId);
    EXPECT_EQ(ret, false);
    TAG_LOGD(AAFwkTag::TEST, "IsExitInfoExist_001 called. end");
}
}  // namespace AAFwk
}  // namespace OHOS
