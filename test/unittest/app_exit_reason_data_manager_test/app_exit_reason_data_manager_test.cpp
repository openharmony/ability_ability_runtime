/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#include "gmock/gmock.h"

#define private public
#define protected public
#include "app_exit_reason_data_manager.h"
#include "mock_single_kv_store.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using testing::_;
using testing::Return;
using testing::SetArgReferee;
using ::testing::DoAll;

namespace OHOS {
namespace AbilityRuntime {
namespace {
const std::string MODULE_NAME = "module_name";
const std::string ABILITY_NAME = "ability_name";
const std::string BUNDLE_NAME = "bundle_name";
constexpr uint32_t ACCESS_TOKEN_ID = 123;
const int SESSION_ID = 111;
}  // namespace

class AppExitReasonDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AppExitReasonDataManagerTest::SetUpTestCase(void)
{}

void AppExitReasonDataManagerTest::TearDownTestCase(void)
{}

void AppExitReasonDataManagerTest::SetUp()
{
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAbilityRecoverInfo(
        ACCESS_TOKEN_ID, MODULE_NAME, ABILITY_NAME);
}

void AppExitReasonDataManagerTest::TearDown()
{}

/**
 * @tc.name: AppExitReasonDataManager_AddAbilityRecoverInfo_001
 * @tc.desc: AddAbilityRecoverInfo
 * @tc.type: FUNC
 * @tc.require: issuesI7N79U
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_AddAbilityRecoverInfo_001, TestSize.Level1)
{
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->AddAbilityRecoverInfo(
        ACCESS_TOKEN_ID, MODULE_NAME, ABILITY_NAME, SESSION_ID);
    EXPECT_EQ(result, ERR_OK);

    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->AddAbilityRecoverInfo(
        ACCESS_TOKEN_ID, MODULE_NAME, ABILITY_NAME, SESSION_ID);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppExitReasonDataManager_DeleteAbilityRecoverInfo_001
 * @tc.desc: DeleteAbilityRecoverInfo
 * @tc.type: FUNC
 * @tc.require: issuesI7N79U
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_DeleteAbilityRecoverInfo_001, TestSize.Level1)
{
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAbilityRecoverInfo(
        ACCESS_TOKEN_ID, MODULE_NAME, ABILITY_NAME);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->AddAbilityRecoverInfo(
        ACCESS_TOKEN_ID, MODULE_NAME, ABILITY_NAME, SESSION_ID);
    EXPECT_EQ(result, ERR_OK);
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAbilityRecoverInfo(
        ACCESS_TOKEN_ID, MODULE_NAME, ABILITY_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppExitReasonDataManager_SetUIExtensionAbilityExitReason_001
 * @tc.desc: SetUIExtensionAbilityExitReason
 * @tc.type: FUNC
 */
HWTEST_F(
    AppExitReasonDataManagerTest, AppExitReasonDataManager_SetUIExtensionAbilityExitReason_001, TestSize.Level1)
{
    std::string bundleName = "com.test.demo";
    std::vector<std::string> extensionList;
    extensionList.push_back("testEntryUIExtAbility");
    AAFwk::ExitReason exitReason = { AAFwk::REASON_JS_ERROR, "Js Error." };
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->SetUIExtensionAbilityExitReason(
        bundleName, extensionList, exitReason, {}, false);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppExitReasonDataManager_GetAbilityRecoverInfo_001
 * @tc.desc: GetAbilityRecoverInfo
 * @tc.type: FUNC
 * @tc.require: issuesI7N79U
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_GetAbilityRecoverInfo_001, TestSize.Level1)
{
    bool hasRecoverInfo = false;
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetAbilityRecoverInfo(
        ACCESS_TOKEN_ID, MODULE_NAME, ABILITY_NAME, hasRecoverInfo);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    EXPECT_EQ(hasRecoverInfo, false);

    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->AddAbilityRecoverInfo(
        ACCESS_TOKEN_ID, MODULE_NAME, ABILITY_NAME, SESSION_ID);
    EXPECT_EQ(result, ERR_OK);
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetAbilityRecoverInfo(
        ACCESS_TOKEN_ID, MODULE_NAME, ABILITY_NAME, hasRecoverInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(hasRecoverInfo, true);
}

/**
 * @tc.name: AppExitReasonDataManager_SetAppExitReason_001
 * @tc.desc: SetAppExitReason
 * @tc.type: FUNC
 * @tc.require: issuesI7N79U
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_SetAppExitReason_001, TestSize.Level1)
{
    std::vector<std::string> abilityList;
    abilityList.push_back(ABILITY_NAME);
    AAFwk::ExitReason exitReason = { AAFwk::REASON_JS_ERROR, "Js Error." };
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->SetAppExitReason(
        "", ACCESS_TOKEN_ID, abilityList, exitReason);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->SetAppExitReason(
        BUNDLE_NAME, 0, abilityList, exitReason);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    auto tempKv = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_;
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = nullptr;
    auto& tempStoreId =
        const_cast<DistributedKv::StoreId&>(DelayedSingleton<AppExitReasonDataManager>::GetInstance()->storeId_);
    tempStoreId.storeId = "app_**exit_reason_infos";
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->SetAppExitReason(
        BUNDLE_NAME, ACCESS_TOKEN_ID, abilityList, exitReason);
    EXPECT_EQ(result, ERR_NO_INIT);

    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = tempKv;
    tempStoreId.storeId = "app_exit_reason_infos";
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->SetAppExitReason(
        BUNDLE_NAME, ACCESS_TOKEN_ID, abilityList, exitReason);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppExitReasonDataManager_DeleteAppExitReason_001
 * @tc.desc: DeleteAppExitReason
 * @tc.type: FUNC
 * @tc.require: issuesI7N79U
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_DeleteAppExitReason_001, TestSize.Level1)
{
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAppExitReason(BUNDLE_NAME, -1, 0);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAppExitReason(BUNDLE_NAME, 1, 0);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAppExitReason("", 0);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    auto tempKv = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_;
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = nullptr;
    auto& tempStoreId =
        const_cast<DistributedKv::StoreId&>(DelayedSingleton<AppExitReasonDataManager>::GetInstance()->storeId_);
    tempStoreId.storeId = "app_**exit_reason_infos";
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAppExitReason(BUNDLE_NAME,
        ACCESS_TOKEN_ID);
    EXPECT_EQ(result, ERR_NO_INIT);

    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = tempKv;
    tempStoreId =
        const_cast<DistributedKv::StoreId&>(DelayedSingleton<AppExitReasonDataManager>::GetInstance()->storeId_);
    tempStoreId.storeId = "app_exit_reason_infos";
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAppExitReason(BUNDLE_NAME,
        ACCESS_TOKEN_ID);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppExitReasonDataManager_GetAppExitReason_001
 * @tc.desc: GetAppExitReason
 * @tc.type: FUNC
 * @tc.require: issuesI7N79U
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_GetAppExitReason_001, TestSize.Level1)
{
    bool isSetReason = false;
    AAFwk::ExitReason exitReason = { AAFwk::REASON_JS_ERROR, "Js Error." };
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetAppExitReason(
        "", ACCESS_TOKEN_ID, ABILITY_NAME, isSetReason, exitReason);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetAppExitReason(
        BUNDLE_NAME, 0, ABILITY_NAME, isSetReason, exitReason);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    auto tempKv = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_;
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = nullptr;
    auto& tempStoreId =
        const_cast<DistributedKv::StoreId&>(DelayedSingleton<AppExitReasonDataManager>::GetInstance()->storeId_);
    tempStoreId.storeId = "app_**exit_reason_infos";
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetAppExitReason(
        BUNDLE_NAME, ACCESS_TOKEN_ID, ABILITY_NAME, isSetReason, exitReason);
    EXPECT_EQ(result, ERR_NO_INIT);

    tempStoreId.storeId = "app_exit_reason_infos";
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = kvStorePtr;
    EXPECT_CALL(*kvStorePtr, GetEntries(_, _)).Times(1)
        .WillOnce(DoAll(Return(DistributedKv::Status::ERROR)));
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetAppExitReason(
        BUNDLE_NAME, ACCESS_TOKEN_ID, ABILITY_NAME, isSetReason, exitReason);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    DistributedKv::Entry entry;
    entry.key = std::to_string(ACCESS_TOKEN_ID);;
    entry.value = "test_value";
    std::vector<DistributedKv::Entry> allEntries;
    allEntries.push_back(entry);
    EXPECT_CALL(*kvStorePtr, GetEntries(_, _)).Times(1)
        .WillOnce(DoAll(SetArgReferee<1>(allEntries), Return(DistributedKv::Status::SUCCESS)));
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetAppExitReason(
        BUNDLE_NAME, ACCESS_TOKEN_ID, ABILITY_NAME, isSetReason, exitReason);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppExitReasonDataManager_DeleteAllRecoverInfoByTokenId_001
 * @tc.desc: DeleteAllRecoverInfoByTokenId
 * @tc.type: FUNC
 * @tc.require: issuesI7N79U
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_DeleteAllRecoverInfoByTokenId_001, TestSize.Level1)
{
    auto tempKv = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_;
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = nullptr;
    auto& tempStoreId =
        const_cast<DistributedKv::StoreId&>(DelayedSingleton<AppExitReasonDataManager>::GetInstance()->storeId_);
    tempStoreId.storeId = "app_**exit_reason_infos";
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->
        DeleteAllRecoverInfoByTokenId(ACCESS_TOKEN_ID);
    EXPECT_EQ(result, ERR_NO_INIT);

    tempStoreId.storeId = "app_exit_reason_infos";
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = tempKv;
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->
        DeleteAllRecoverInfoByTokenId(ACCESS_TOKEN_ID);
    EXPECT_EQ(result, ERR_OK);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
