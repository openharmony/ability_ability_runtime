/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "ability_manager_errors.h"
#define private public
#define protected public
#include "ability_record.h"
#include "ability_start_setting.h"
#include "app_scheduler.h"
#include "app_utils.h"
#include "scene_board/ui_ability_lifecycle_manager.h"
#include "scene_board/status_bar_delegate_manager.h"

#undef protected
#undef private
#include "app_mgr_client.h"
#include "process_options.h"
#include "session/host/include/session.h"
#include "session_info.h"
#include "startup_util.h"
#include "ability_manager_service.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {

class StatusBarDelegateManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void StatusBarDelegateManagerTest::SetUpTestCase() {}

void StatusBarDelegateManagerTest::TearDownTestCase() {}

void StatusBarDelegateManagerTest::SetUp() {}

void StatusBarDelegateManagerTest::TearDown() {}


/**
 * @tc.name: StatusBarDelegateManager_IsCallerInStatusBar_0100
 * @tc.desc: IsCallerInStatusBar
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, IsCallerInStatusBar_0100, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    statusBarDelegate->RegisterStatusBarDelegate(nullptr);
    statusBarDelegate->GetStatusBarDelegate();
    bool ret = statusBarDelegate->IsCallerInStatusBar();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: StatusBarDelegateManager_DoProcessAttachment_0100
 * @tc.desc: DoProcessAttachment
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, DoProcessAttachment_0100, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    statusBarDelegate->RegisterStatusBarDelegate(nullptr);
    statusBarDelegate->GetStatusBarDelegate();
    bool ret = statusBarDelegate->IsCallerInStatusBar();
    EXPECT_EQ(ret, false);
    std::shared_ptr<AbilityRecord> abilityRecord;
    int32_t attach_ret = statusBarDelegate->DoProcessAttachment(abilityRecord);
    EXPECT_NE(attach_ret, ERR_OK);
}

/**
 * @tc.name: StatusBarDelegateManager_DoCallerProcessAttachment_0100
 * @tc.desc: DoCallerProcessAttachment
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, DoCallerProcessAttachment_0100, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    statusBarDelegate->RegisterStatusBarDelegate(nullptr);
    statusBarDelegate->GetStatusBarDelegate();
    bool ret = statusBarDelegate->IsCallerInStatusBar();
    EXPECT_EQ(ret, false);
    std::shared_ptr<AbilityRecord> abilityRecord;
    int32_t attach_ret = statusBarDelegate->DoProcessAttachment(abilityRecord);
    EXPECT_NE(attach_ret, ERR_OK);
}

}  // namespace AAFwk
}  // namespace OHOS
