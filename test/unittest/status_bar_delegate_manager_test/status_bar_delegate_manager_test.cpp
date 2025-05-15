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
class MockIStatusBarDelegate : public AbilityRuntime::IStatusBarDelegate {
public:
    MockIStatusBarDelegate() = default;
    virtual ~MockIStatusBarDelegate() = default;

    int32_t CheckIfStatusBarItemExists(uint32_t accessTokenId, const std::string &instanceKey,
        bool& isExist) override
    {
        if (returnValue_ == ERR_OK) {
            isExist = itemExists_;
        }
        return returnValue_;
    }

    int32_t AttachPidToStatusBarItem(uint32_t accessTokenId, int32_t pid,
        const std::string &instanceKey) override
    {
        return returnValue_;
    }

    int32_t DetachPidToStatusBarItem(uint32_t accessTokenId, int32_t pid,
        const std::string &instanceKey) override
    {
        return returnValue_;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }

    void SetReturnValue(int32_t value)
    {
        returnValue_ = value;
    }

    void SetItemExists(bool exists)
    {
        itemExists_ = exists;
    }

private:
    int32_t returnValue_ = ERR_OK;
    bool itemExists_ = false;
};

class StatusBarDelegateManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<AbilityRecord> CreateMockAbilityRecord()
    {
        Want want;
        AppExecFwk::AbilityInfo abilityInfo;
        AppExecFwk::ApplicationInfo applicationInfo;
        return std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    }
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
    bool ret = statusBarDelegate->IsCallerInStatusBar("");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: StatusBarDelegateManager_IsCallerInStatusBar_0200
 * @tc.desc: Test IsCallerInStatusBar when CheckIfStatusBarItemExists returns ERR_OK and item exists
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, IsCallerInStatusBar_0200, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    sptr<MockIStatusBarDelegate> mockDelegate = new MockIStatusBarDelegate();
    mockDelegate->SetReturnValue(ERR_OK);
    mockDelegate->SetItemExists(true);
    statusBarDelegate->RegisterStatusBarDelegate(mockDelegate);
    bool ret = statusBarDelegate->IsCallerInStatusBar("test_instance_key");
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: StatusBarDelegateManager_IsCallerInStatusBar_0300
 * @tc.desc: Test IsCallerInStatusBar when CheckIfStatusBarItemExists returns error
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, IsCallerInStatusBar_0300, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    sptr<MockIStatusBarDelegate> mockDelegate = new MockIStatusBarDelegate();
    mockDelegate->SetReturnValue(ERR_INVALID_VALUE);
    statusBarDelegate->RegisterStatusBarDelegate(mockDelegate);
    bool ret = statusBarDelegate->IsCallerInStatusBar("test_instance_key");
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
    bool ret = statusBarDelegate->IsCallerInStatusBar("");
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
    bool ret = statusBarDelegate->IsCallerInStatusBar("");
    EXPECT_EQ(ret, false);
    std::shared_ptr<AbilityRecord> abilityRecord;
    int32_t attach_ret = statusBarDelegate->DoProcessAttachment(abilityRecord);
    EXPECT_NE(attach_ret, ERR_OK);
}

/**
 * @tc.name: StatusBarDelegateManager_IsInStatusBar_0100
 * @tc.desc: Test IsInStatusBar when statusBarDelegate is null
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, IsInStatusBar_0100, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    bool ret = statusBarDelegate->IsInStatusBar(1000, false);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: StatusBarDelegateManager_IsInStatusBar_0200
 * @tc.desc: Test IsInStatusBar when CheckIfStatusBarItemExists returns ERR_OK and item exists
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, IsInStatusBar_0200, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    sptr<MockIStatusBarDelegate> mockDelegate = new MockIStatusBarDelegate();
    mockDelegate->SetReturnValue(ERR_OK);
    mockDelegate->SetItemExists(true);
    statusBarDelegate->RegisterStatusBarDelegate(mockDelegate);
    bool ret = statusBarDelegate->IsInStatusBar(1000, false);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: StatusBarDelegateManager_IsInStatusBar_0300
 * @tc.desc: Test IsInStatusBar when CheckIfStatusBarItemExists returns error
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, IsInStatusBar_0300, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    sptr<MockIStatusBarDelegate> mockDelegate = new MockIStatusBarDelegate();
    mockDelegate->SetReturnValue(ERR_INVALID_VALUE);
    mockDelegate->SetItemExists(true);
    statusBarDelegate->RegisterStatusBarDelegate(mockDelegate);
    bool ret = statusBarDelegate->IsInStatusBar(1000, false);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: StatusBarDelegateManager_DoCallerProcessAttachment_0200
 * @tc.desc: Test DoCallerProcessAttachment when abilityRecord is null
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, DoCallerProcessAttachment_0200, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    std::shared_ptr<AbilityRecord> abilityRecord = nullptr;
    int32_t ret = statusBarDelegate->DoCallerProcessAttachment(abilityRecord);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: StatusBarDelegateManager_DoCallerProcessAttachment_0300
 * @tc.desc: Test DoCallerProcessAttachment when AttachPidToStatusBarItem returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, DoCallerProcessAttachment_0300, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    sptr<MockIStatusBarDelegate> mockDelegate = new MockIStatusBarDelegate();
    mockDelegate->SetReturnValue(ERR_OK);
    statusBarDelegate->RegisterStatusBarDelegate(mockDelegate);
    std::shared_ptr<AbilityRecord> abilityRecord = CreateMockAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    int32_t ret = statusBarDelegate->DoCallerProcessAttachment(abilityRecord);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: StatusBarDelegateManager_DoCallerProcessAttachment_0400
 * @tc.desc: Test DoCallerProcessAttachment when AttachPidToStatusBarItem returns error
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, DoCallerProcessAttachment_0400, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    sptr<MockIStatusBarDelegate> mockDelegate = new MockIStatusBarDelegate();
    mockDelegate->SetReturnValue(ERR_INVALID_VALUE);
    statusBarDelegate->RegisterStatusBarDelegate(mockDelegate);
    std::shared_ptr<AbilityRecord> abilityRecord = CreateMockAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    int32_t ret = statusBarDelegate->DoCallerProcessAttachment(abilityRecord);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: StatusBarDelegateManager_DoCallerProcessDetachment_0100
 * @tc.desc: Test DoCallerProcessDetachment when abilityRecord is null
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, DoCallerProcessDetachment_0100, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    std::shared_ptr<AbilityRecord> abilityRecord = nullptr;
    int32_t ret = statusBarDelegate->DoCallerProcessDetachment(abilityRecord);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: StatusBarDelegateManager_DoCallerProcessDetachment_0200
 * @tc.desc: Test DoCallerProcessDetachment when statusBarDelegate is null
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, DoCallerProcessDetachment_0200, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    std::shared_ptr<AbilityRecord> abilityRecord = CreateMockAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    int32_t ret = statusBarDelegate->DoCallerProcessDetachment(abilityRecord);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: StatusBarDelegateManager_DoCallerProcessDetachment_0300
 * @tc.desc: Test DoCallerProcessDetachment when DetachPidToStatusBarItem returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, DoCallerProcessDetachment_0300, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    // Create a mock delegate that will return ERR_OK
    sptr<MockIStatusBarDelegate> mockDelegate = new MockIStatusBarDelegate();
    mockDelegate->SetReturnValue(ERR_OK);
    statusBarDelegate->RegisterStatusBarDelegate(mockDelegate);
    std::shared_ptr<AbilityRecord> abilityRecord = CreateMockAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    int32_t ret = statusBarDelegate->DoCallerProcessDetachment(abilityRecord);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: StatusBarDelegateManager_DoCallerProcessDetachment_0104
 * @tc.desc: Test DoCallerProcessDetachment when DetachPidToStatusBarItem returns error
 * @tc.type: FUNC
 */
HWTEST_F(StatusBarDelegateManagerTest, DoCallerProcessDetachment_0400, TestSize.Level1)
{
    std::shared_ptr<StatusBarDelegateManager> statusBarDelegate = std::make_shared<StatusBarDelegateManager>();
    EXPECT_NE(statusBarDelegate, nullptr);
    sptr<MockIStatusBarDelegate> mockDelegate = new MockIStatusBarDelegate();
    mockDelegate->SetReturnValue(ERR_INVALID_VALUE);
    statusBarDelegate->RegisterStatusBarDelegate(mockDelegate);
    std::shared_ptr<AbilityRecord> abilityRecord = CreateMockAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    int32_t ret = statusBarDelegate->DoCallerProcessDetachment(abilityRecord);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}
}  // namespace AAFwk
}  // namespace OHOS
