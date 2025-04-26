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
#include <thread>

#define private public
#include "app_mgr_service_inner.h"
#include "app_running_record.h"
#include "remote_client_manager.h"
#undef private
#include "app_mgr_event.h"
#include "app_scheduler.h"
#include "event_handler.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"
#include "mock_my_flag.h"
#include "parameters.h"
#include "window_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class AppMgrServiceInnerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AppMgrServiceInnerTest::SetUpTestCase(void)
{}

void AppMgrServiceInnerTest::TearDownTestCase(void)
{}

void AppMgrServiceInnerTest::SetUp()
{}

void AppMgrServiceInnerTest::TearDown()
{}

/**
 * @tc.name: GetKernelPermissions_001
 * @tc.desc: Get kernel permissions
 * @tc.type: FUNC
 * @tc.Function: GetKernelPermissions
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppMgrServiceInnerTest, GetKernelPermissions_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetKernelPermissions_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::map<std::string, std::string> permissionsMap;
    uint32_t accessTokenId = MOCKTOKENID::TOKENID_ONE;
    appMgrServiceInner->GetKernelPermissions(accessTokenId, permissionsMap);
    EXPECT_EQ(permissionsMap.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "GetKernelPermissions_001 end");
}

/**
 * @tc.name: GetKernelPermissions_002
 * @tc.desc: Get kernel permissions
 * @tc.type: FUNC
 * @tc.Function: GetKernelPermissions
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppMgrServiceInnerTest, GetKernelPermissions_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetKernelPermissions_002 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::map<std::string, std::string> permissionsMap;
    uint32_t accessTokenId = MOCKTOKENID::TOKENID_TWO;
    appMgrServiceInner->GetKernelPermissions(accessTokenId, permissionsMap);
    EXPECT_EQ(permissionsMap.size(), 4);
    TAG_LOGI(AAFwkTag::TEST, "GetKernelPermissions_002 end");
}

/**
 * @tc.name: GetKernelPermissions_003
 * @tc.desc: Get kernel permissions
 * @tc.type: FUNC
 * @tc.Function: GetKernelPermissions
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppMgrServiceInnerTest, GetKernelPermissions_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetKernelPermissions_003 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::map<std::string, std::string> permissionsMap;
    uint32_t accessTokenId = MOCKTOKENID::TOKENID_THREE;
    appMgrServiceInner->GetKernelPermissions(accessTokenId, permissionsMap);
    EXPECT_EQ(permissionsMap.size(), 5);
    TAG_LOGI(AAFwkTag::TEST, "GetKernelPermissions_003 end");
}

/**
 * @tc.name: GetKernelPermissions_004
 * @tc.desc: Get kernel permissions
 * @tc.type: FUNC
 * @tc.Function: GetKernelPermissions
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppMgrServiceInnerTest, GetKernelPermissions_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetKernelPermissions_004 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::map<std::string, std::string> permissionsMap;
    uint32_t accessTokenId = MOCKTOKENID::TOKENID_FOUR;
    appMgrServiceInner->GetKernelPermissions(accessTokenId, permissionsMap);
    EXPECT_EQ(permissionsMap.size(), 4);
    TAG_LOGI(AAFwkTag::TEST, "GetKernelPermissions_004 end");
}
} // namespace AppExecFwk
} // namespace OHOS