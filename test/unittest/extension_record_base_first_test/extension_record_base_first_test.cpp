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

#define private public
#define protected public
#include "base_extension_record.h"
#include "lifecycle_deal.h"
#undef private
#undef protected
#include "ability_manager_service.h"
#include "ability_util.h"
#include "app_utils.h"
#include "connection_record.h"
#include "hilog_tag_wrapper.h"
#include "mock_ability_connect_callback.h"
#include "uri_utils.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
namespace {
const std::string TEST_NATIVE_DEBUG = "nativeDebug";
const std::string TEST_PERF_CMD = "perfCmd";
const std::string TEST_MULTI_THREAD = "multiThread";
const std::string TEST_ERROR_INFO_ENHANCE = "errorInfoEnhance";
const std::string TEST_PARAMS_STREAM = "ability.params.stream";
}

class ExtensionRecordBaseFirstTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<BaseExtensionRecord> GetAbilityRecord();

    std::shared_ptr<BaseExtensionRecord> abilityRecord_{ nullptr };
};

void ExtensionRecordBaseFirstTest::SetUpTestCase(void)
{}

void ExtensionRecordBaseFirstTest::TearDownTestCase(void)
{}

void ExtensionRecordBaseFirstTest::SetUp(void)
{
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    Want want;
    abilityRecord_ = std::make_shared<BaseExtensionRecord>(want, abilityInfo, applicationInfo);
    abilityRecord_->Init(AbilityRequest());
}

void ExtensionRecordBaseFirstTest::TearDown(void)
{
    abilityRecord_.reset();
}

std::shared_ptr<BaseExtensionRecord> ExtensionRecordBaseFirstTest::GetAbilityRecord()
{
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    return std::make_shared<BaseExtensionRecord>(want, abilityInfo, applicationInfo);
}

/*
* Feature: BaseExtensionRecord
* Function: GetInProgressRecordCount
* SubFunction: NA
*/
HWTEST_F(ExtensionRecordBaseFirstTest, ExtensionRecordBase_GetInProgressRecordCount_001, TestSize.Level1)
{
    TAG_LOGE(AAFwkTag::TEST, "AbilityRecord_GetInProgressRecordCount_001 start.");
    std::shared_ptr<BaseExtensionRecord> abilityRecord = GetAbilityRecord();
    std::shared_ptr<ConnectionRecord> connections = nullptr;
    abilityRecord->connRecordList_.push_back(connections);
    auto res = abilityRecord->GetInProgressRecordCount();
    EXPECT_EQ(res, 0);
    abilityRecord->connRecordList_.clear();
    OHOS::sptr<IAbilityConnection> callback = new AbilityConnectCallback();
    std::shared_ptr<ConnectionRecord> connection1 =
        std::make_shared<ConnectionRecord>(abilityRecord->GetToken(), abilityRecord, callback, nullptr);
        connection1->SetConnectState(ConnectionState::CONNECTING);
    std::shared_ptr<ConnectionRecord> connection2 =
        std::make_shared<ConnectionRecord>(abilityRecord->GetToken(), abilityRecord, callback, nullptr);
        connection2->SetConnectState(ConnectionState::CONNECTED);
    std::shared_ptr<ConnectionRecord> connection3 =
        std::make_shared<ConnectionRecord>(abilityRecord->GetToken(), abilityRecord, callback, nullptr);
        connection3->SetConnectState(ConnectionState::DISCONNECTING);
    abilityRecord->connRecordList_.push_back(connection1);
    abilityRecord->connRecordList_.push_back(connection2);
    abilityRecord->connRecordList_.push_back(connection3);
    res = abilityRecord->GetInProgressRecordCount();
    EXPECT_EQ(res, 2);
    TAG_LOGE(AAFwkTag::TEST, "AbilityRecord_GetInProgressRecordCount_001 end.");
}

/*
 * Feature: BaseExtensionRecord
 * Function: Add connection record to ability record' list
 * SubFunction: NA
 * FunctionPoints: AddConnectRecordToList
 * EnvConditions: NA
 * CaseDescription: AddConnectRecordToList UT.
 */
HWTEST_F(ExtensionRecordBaseFirstTest, AaFwk_AbilityMS_AddConnectRecordToList, TestSize.Level1)
{
    // test1 for input param is null
    abilityRecord_->AddConnectRecordToList(nullptr);
    auto connList = abilityRecord_->GetConnectRecordList();
    EXPECT_EQ(0, static_cast<int>(connList.size()));

    // test2 for adding new connection record to empty list
    OHOS::sptr<IAbilityConnection> callback1 = new AbilityConnectCallback();
    auto newConnRecord1 =
        ConnectionRecord::CreateConnectionRecord(abilityRecord_->GetToken(), abilityRecord_, callback1, nullptr);
    abilityRecord_->AddConnectRecordToList(newConnRecord1);
    connList = abilityRecord_->GetConnectRecordList();
    EXPECT_EQ(1, static_cast<int>(connList.size()));

    // test3 for adding new connection record to non-empty list
    OHOS::sptr<IAbilityConnection> callback2 = new AbilityConnectCallback();
    auto newConnRecord2 =
        ConnectionRecord::CreateConnectionRecord(abilityRecord_->GetToken(), abilityRecord_, callback2, nullptr);
    abilityRecord_->AddConnectRecordToList(newConnRecord2);
    connList = abilityRecord_->GetConnectRecordList();
    EXPECT_EQ(2, static_cast<int>(connList.size()));

    // test4 for adding old connection record to non-empty list
    abilityRecord_->AddConnectRecordToList(newConnRecord2);
    connList = abilityRecord_->GetConnectRecordList();
    EXPECT_EQ(2, static_cast<int>(connList.size()));

    // test5 for delete nullptr from list
    abilityRecord_->RemoveConnectRecordFromList(nullptr);
    connList = abilityRecord_->GetConnectRecordList();
    EXPECT_EQ(2, static_cast<int>(connList.size()));

    // test6 for delete no-match member from list
    auto newConnRecord3 =
        ConnectionRecord::CreateConnectionRecord(abilityRecord_->GetToken(), abilityRecord_, callback2, nullptr);
    abilityRecord_->RemoveConnectRecordFromList(newConnRecord3);
    connList = abilityRecord_->GetConnectRecordList();
    EXPECT_EQ(2, static_cast<int>(connList.size()));

    // test7 for delete match member from list
    abilityRecord_->RemoveConnectRecordFromList(newConnRecord2);
    connList = abilityRecord_->GetConnectRecordList();
    EXPECT_EQ(1, static_cast<int>(connList.size()));

    // test8 for get ability unknown type
    EXPECT_EQ(OHOS::AppExecFwk::AbilityType::UNKNOWN, abilityRecord_->GetAbilityInfo().type);
}

/*
 * Feature: BaseExtensionRecord
 * Function: GetConnectingRecordList
 * SubFunction: GetConnectingRecordList
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord GetConnectingRecordList
 */
HWTEST_F(ExtensionRecordBaseFirstTest, AbilityRecord_GetConnectingRecordList_001, TestSize.Level1)
{
    std::shared_ptr<BaseExtensionRecord> abilityRecord = GetAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    OHOS::sptr<IAbilityConnection> callback = new AbilityConnectCallback();
    std::shared_ptr<ConnectionRecord> connection1 =
        std::make_shared<ConnectionRecord>(abilityRecord->GetToken(), abilityRecord, callback, nullptr);
    std::shared_ptr<ConnectionRecord> connection2 =
        std::make_shared<ConnectionRecord>(abilityRecord->GetToken(), abilityRecord, callback, nullptr);
    connection1->SetConnectState(ConnectionState::CONNECTING);
    connection2->SetConnectState(ConnectionState::CONNECTED);
    abilityRecord->connRecordList_.push_back(connection1);
    abilityRecord->connRecordList_.push_back(connection2);
    abilityRecord->GetConnectingRecordList();
}

/*
 * Feature: BaseExtensionRecord
 * Function: DumpService
 * SubFunction: DumpService
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord DumpService
 */
HWTEST_F(ExtensionRecordBaseFirstTest, AbilityRecord_DumpService_001, TestSize.Level1)
{
    std::shared_ptr<BaseExtensionRecord> abilityRecord = GetAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    std::vector<std::string> info;
    std::vector<std::string> params;
    bool isClient = false;
    OHOS::sptr<IAbilityConnection> callback = new AbilityConnectCallback();
    std::shared_ptr<ConnectionRecord> connection =
        std::make_shared<ConnectionRecord>(abilityRecord->GetToken(), abilityRecord, callback, nullptr);
    abilityRecord->isLauncherRoot_ = true;
    abilityRecord->connRecordList_.push_back(nullptr);
    abilityRecord->connRecordList_.push_back(connection);
    abilityRecord->DumpService(info, params, isClient);
}

/*
 * Feature: BaseExtensionRecord
 * Function: DisconnectAbility
 * SubFunction: DisconnectAbility
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord DisconnectAbility
 */
HWTEST_F(ExtensionRecordBaseFirstTest, AbilityRecord_DisconnectAbility_001, TestSize.Level1)
{
    std::shared_ptr<BaseExtensionRecord> abilityRecord = GetAbilityRecord();
    abilityRecord->lifecycleDeal_ = std::make_unique<LifecycleDeal>();
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI_SERVICE;
    abilityRecord->connRecordList_.clear();
    abilityRecord->isConnected = true;
    abilityRecord->DisconnectAbility();
    EXPECT_FALSE(abilityRecord->isConnected);
}

/*
 * Feature: BaseExtensionRecord
 * Function: DisconnectAbilityWithWant
 * SubFunction: DisconnectAbilityWithWant
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord DisconnectAbilityWithWant
 */
HWTEST_F(ExtensionRecordBaseFirstTest, AbilityRecord_DisconnectAbilityWithWant_001, TestSize.Level1)
{
    std::shared_ptr<BaseExtensionRecord> abilityRecord = GetAbilityRecord();
    abilityRecord->abilityInfo_.name = "test";
    abilityRecord->lifecycleDeal_ = std::make_unique<LifecycleDeal>();
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI_SERVICE;
    abilityRecord->connRecordList_.clear();
    abilityRecord->isConnected = true;

    Want want;
    abilityRecord->DisconnectAbilityWithWant(want);
    EXPECT_FALSE(abilityRecord->isConnected);
}

/*
 * Feature: BaseExtensionRecord
 * Function: DumpService
 * SubFunction: DumpService
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord DumpService
 */
HWTEST_F(ExtensionRecordBaseFirstTest, AbilityRecord_DumpService_002, TestSize.Level1)
{
    std::shared_ptr<BaseExtensionRecord> abilityRecord = GetAbilityRecord();
    std::vector<std::string> info;
    std::vector<std::string> params;
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::HMS_ACCOUNT;
    abilityRecord->scheduler_ = nullptr;
    abilityRecord->isReady_ = false;
    abilityRecord->isLauncherRoot_ = false;
    abilityRecord->token_ = nullptr;
    abilityRecord->connRecordList_.clear();
    abilityRecord->DumpService(info, params, false);
    EXPECT_TRUE(info.size() == 8);
}

/*
 * Feature: BaseExtensionRecord
 * Function: DumpService
 * SubFunction: DumpService
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify BaseExtensionRecord DumpService
 */
HWTEST_F(ExtensionRecordBaseFirstTest, AbilityRecord_DumpService_003, TestSize.Level1)
{
    std::shared_ptr<BaseExtensionRecord> abilityRecord = GetAbilityRecord();
    std::vector<std::string> info;
    std::vector<std::string> params;
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI_SERVICE;
    abilityRecord->scheduler_ = nullptr;
    abilityRecord->isReady_ = false;
    abilityRecord->isLauncherRoot_ = false;
    abilityRecord->token_ = nullptr;
    abilityRecord->connRecordList_.clear();
    abilityRecord->DumpService(info, params, false);
    EXPECT_TRUE(info.size() == 9);
}

/*
 * Feature: BaseExtensionRecord
 * Function: SetConnRemoteObject GetConnRemoteObject
 * SubFunction: SetConnRemoteObject GetConnRemoteObject
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify SetConnRemoteObject GetConnRemoteObject UT
 */
HWTEST_F(ExtensionRecordBaseFirstTest, AaFwk_AbilityMS_ConnRemoteObject, TestSize.Level1)
{
    OHOS::sptr<OHOS::IRemoteObject> remote;
    abilityRecord_->SetConnRemoteObject(remote);
    EXPECT_EQ(remote, abilityRecord_->GetConnRemoteObject());
}

/*
 * Feature: BaseExtensionRecord
 * Function: DumpUIExtensionRootHostInfo
 * SubFunction: DumpUIExtensionRootHostInfo
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify DumpUIExtensionRootHostInfo
 */
HWTEST_F(ExtensionRecordBaseFirstTest, AbilityRecord_DumpUIExtensionRootHostInfo_001, TestSize.Level1)
{
    std::shared_ptr<BaseExtensionRecord> abilityRecord = GetAbilityRecord();
    std::vector<std::string> info;
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SYSDIALOG_COMMON;
    abilityRecord->token_ = nullptr;
    abilityRecord->DumpUIExtensionRootHostInfo(info);
    EXPECT_TRUE(info.size() ==  0);
}

/*
 * Feature: BaseExtensionRecord
 * Function: DumpUIExtensionRootHostInfo
 * SubFunction: DumpUIExtensionRootHostInfo
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify DumpUIExtensionRootHostInfo
 */
HWTEST_F(ExtensionRecordBaseFirstTest, AbilityRecord_DumpUIExtensionRootHostInfo_002, TestSize.Level1)
{
    std::shared_ptr<BaseExtensionRecord> abilityRecord = GetAbilityRecord();
    std::vector<std::string> info;
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SYSDIALOG_COMMON;
    abilityRecord->token_ = sptr<Token>::MakeSptr(abilityRecord);
    abilityRecord->DumpUIExtensionRootHostInfo(info);
    EXPECT_TRUE(info.size() == 0);
}

/*
 * Feature: BaseExtensionRecord
 * Function: DumpUIExtensionPid
 * SubFunction: DumpUIExtensionPid
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord DumpUIExtensionPid
 */
HWTEST_F(ExtensionRecordBaseFirstTest, AbilityRecord_DumpUIExtensionPid_001, TestSize.Level1)
{
    std::shared_ptr<BaseExtensionRecord> abilityRecord = GetAbilityRecord();
    std::vector<std::string> info;
    abilityRecord->DumpUIExtensionPid(info, true);
    EXPECT_TRUE(info.size() == 1);
}

/*
 * Feature: BaseExtensionRecord
 * Function: ConnectAbility
 * SubFunction: ConnectAbility
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify BaseExtensionRecord ConnectAbility
 */
HWTEST_F(ExtensionRecordBaseFirstTest, AbilityRecord_ConnectAbility_001, TestSize.Level1)
{
    std::shared_ptr<BaseExtensionRecord> abilityRecord = GetAbilityRecord();
    abilityRecord->lifecycleDeal_ = nullptr;
    abilityRecord->lifecycleDeal_ = std::make_unique<LifecycleDeal>();
    bool isConnected = true;
    abilityRecord->ConnectAbility();
    EXPECT_NE(abilityRecord, nullptr);
}

/*
 * Feature: BaseExtensionRecord
 * Function: PostUIExtensionAbilityTimeoutTask
 * SubFunction: PostUIExtensionAbilityTimeoutTask
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify BaseExtensionRecord PostUIExtensionAbilityTimeoutTask
 */
HWTEST_F(ExtensionRecordBaseFirstTest, AbilityRecord_PostUIExtensionAbilityTimeoutTask_001, TestSize.Level1)
{
    std::shared_ptr<BaseExtensionRecord> abilityRecord = GetAbilityRecord();
    ASSERT_NE(abilityRecord, nullptr);
    abilityRecord->PostUIExtensionAbilityTimeoutTask(AbilityManagerService::LOAD_TIMEOUT_MSG);
    abilityRecord->PostUIExtensionAbilityTimeoutTask(AbilityManagerService::FOREGROUND_TIMEOUT_MSG);
    abilityRecord->PostUIExtensionAbilityTimeoutTask(AbilityManagerService::BACKGROUND_TIMEOUT_MSG);
    EXPECT_TRUE(abilityRecord != nullptr);
}
}  // namespace AAFwk
}  // namespace OHOS
