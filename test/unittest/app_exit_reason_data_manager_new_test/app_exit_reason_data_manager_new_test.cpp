/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include "gmock/gmock.h"
#include <memory>
#include <string>
#include "app_exit_reason_data_manager.h"
#include "mock_single_kv_store.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
namespace {
const std::string MODULE_NAME = "module_name";
const std::string ABILITY_NAME = "ability_name";
const std::string BUNDLE_NAME = "bundle_name";
constexpr uint32_t ACCESS_TOKEN_ID = 123;
const int SESSION_ID = 111;
} // namespace

class AppExitReasonDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AppExitReasonDataManagerTest::SetUpTestCase(void) {}

void AppExitReasonDataManagerTest::TearDownTestCase(void) {}

void AppExitReasonDataManagerTest::SetUp()
{
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAbilityRecoverInfo(ACCESS_TOKEN_ID, MODULE_NAME,
        ABILITY_NAME);
}

void AppExitReasonDataManagerTest::TearDown() {}

/* *
 * @tc.name: AppExitReasonDataManager_AddAbilityRecoverInfo_001
 * @tc.desc: AddAbilityRecoverInfo
 * @tc.type: FUNC
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_AddAbilityRecoverInfo_001, TestSize.Level1)
{
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->AddAbilityRecoverInfo(
        ACCESS_TOKEN_ID, MODULE_NAME, ABILITY_NAME, SESSION_ID);
    EXPECT_EQ(result, ERR_OK);
}

/* *
 * @tc.name: AppExitReasonDataManager_DeleteAbilityRecoverInfo_001
 * @tc.desc: DeleteAbilityRecoverInfo
 * @tc.type: FUNC
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_DeleteAbilityRecoverInfo_001, TestSize.Level1)
{
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAbilityRecoverInfo(
        ACCESS_TOKEN_ID, MODULE_NAME, ABILITY_NAME);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->AddAbilityRecoverInfo(ACCESS_TOKEN_ID,
        MODULE_NAME, ABILITY_NAME, SESSION_ID);
    EXPECT_EQ(result, ERR_OK);

    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAbilityRecoverInfo(ACCESS_TOKEN_ID,
        MODULE_NAME, ABILITY_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/* *
 * @tc.name: AppExitReasonDataManager_SetAppExitReason_001
 * @tc.desc: SetAppExitReason
 * @tc.type: FUNC
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_SetAppExitReason_001, TestSize.Level1)
{
    std::vector<std::string> abilityList;
    abilityList.push_back(ABILITY_NAME);
    AAFwk::ExitReason exitReason = {AAFwk::REASON_JS_ERROR, "Js Error."};
    AppExecFwk::RunningProcessInfo processInfo;
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->SetAppExitReason("", ACCESS_TOKEN_ID,
        abilityList, exitReason, processInfo, false);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->SetAppExitReason(BUNDLE_NAME, 0, abilityList,
        exitReason, processInfo, false);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    auto tempKv = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_;
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = nullptr;
    auto &tempStoreId =
        const_cast<DistributedKv::StoreId &>(DelayedSingleton<AppExitReasonDataManager>::GetInstance()->storeId_);
    tempStoreId.storeId = "app_**exit_reason_infos";
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->SetAppExitReason(BUNDLE_NAME, ACCESS_TOKEN_ID,
        abilityList, exitReason, processInfo, false);
    EXPECT_EQ(result, ERR_NO_INIT);

    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = tempKv;
    tempStoreId.storeId = "app_exit_reason_infos";
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->SetAppExitReason(BUNDLE_NAME, ACCESS_TOKEN_ID,
        abilityList, exitReason, processInfo, false);
    EXPECT_EQ(result, ERR_OK);
}

/* *
 * @tc.name: AppExitReasonDataManager_DeleteAppExitReason_001
 * @tc.desc: DeleteAppExitReason
 * @tc.type: FUNC
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_DeleteAppExitReason_001, TestSize.Level1)
{
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAppExitReason(
        BUNDLE_NAME, -1, 0);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAppExitReason(BUNDLE_NAME, 1, 0);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAppExitReason("", 0);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    auto tempKv = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_;
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = nullptr;
    auto &tempStoreId =
        const_cast<DistributedKv::StoreId &>(DelayedSingleton<AppExitReasonDataManager>::GetInstance()->storeId_);
    tempStoreId.storeId = "app_**exit_reason_infos";
    result =
        DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAppExitReason(BUNDLE_NAME, ACCESS_TOKEN_ID);
    EXPECT_EQ(result, ERR_NO_INIT);

    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = tempKv;
    tempStoreId =
        const_cast<DistributedKv::StoreId &>(DelayedSingleton<AppExitReasonDataManager>::GetInstance()->storeId_);
    tempStoreId.storeId = "app_exit_reason_infos";
    result =
        DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAppExitReason(BUNDLE_NAME, ACCESS_TOKEN_ID);
    EXPECT_EQ(result, ERR_OK);
}

/* *
 * @tc.name: AppExitReasonDataManager_GetAppExitReason_001
 * @tc.desc: GetAppExitReason
 * @tc.type: FUNC
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_GetAppExitReason_001, TestSize.Level1)
{
    bool isSetReason = false;
    int64_t stamp = 0;
    bool withKillMsg = false;
    AppExecFwk::RunningProcessInfo processInfo;
    AAFwk::ExitReason exitReason = {AAFwk::REASON_JS_ERROR, "Js Error."};
    auto tempKv = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_;
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetAppExitReason("", ACCESS_TOKEN_ID,
        ABILITY_NAME, isSetReason, exitReason, processInfo, stamp, withKillMsg);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetAppExitReason(BUNDLE_NAME, 0, ABILITY_NAME,
        isSetReason, exitReason, processInfo, stamp, withKillMsg);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = nullptr;
    auto &tempStoreId =
        const_cast<DistributedKv::StoreId &>(DelayedSingleton<AppExitReasonDataManager>::GetInstance()->storeId_);
    tempStoreId.storeId = "app_**exit_reason_infos";
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetAppExitReason(BUNDLE_NAME, ACCESS_TOKEN_ID,
        ABILITY_NAME, isSetReason, exitReason, processInfo, stamp, withKillMsg);
    EXPECT_EQ(result, ERR_NO_INIT);

    tempStoreId.storeId = "app_exit_reason_infos";
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = tempKv;
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetAppExitReason(BUNDLE_NAME, ACCESS_TOKEN_ID,
        ABILITY_NAME, isSetReason, exitReason, processInfo, stamp, withKillMsg);
    EXPECT_EQ(result, ERR_OK);
}

/* *
 * @tc.name: AppExitReasonDataManager_ConvertReasonFromValue_001
 * @tc.desc: ConvertReasonFromValue
 * @tc.type: FUNC
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_ConvertReasonFromValue_001, TestSize.Level1)
{
    bool withKillMsg = false;
    std::string killMsg = "test_value";
    nlohmann::json jsonObject = nlohmann::json{{ "kill_msg", killMsg }};
    AAFwk::ExitReason exitReason = {AAFwk::REASON_JS_ERROR, "Js Error."};
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->ConvertReasonFromValue(jsonObject, exitReason,
        withKillMsg);
    EXPECT_EQ(withKillMsg, true);
}

/* *
 * @tc.name: AppExitReasonDataManager_InnerDeleteAppExitReason_001
 * @tc.desc: InnerDeleteAppExitReason
 * @tc.type: FUNC
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_InnerDeleteAppExitReason_001, TestSize.Level1)
{
    std::string accessTokenIdStr = std::to_string(ACCESS_TOKEN_ID);
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = nullptr;
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->InnerDeleteAppExitReason(accessTokenIdStr);
    bool ret = accessTokenIdStr.empty();
    EXPECT_FALSE(ret);
}

/* *
 * @tc.name: AppExitReasonDataManager_DeleteAllRecoverInfoByTokenId_001
 * @tc.desc: DeleteAllRecoverInfoByTokenId
 * @tc.type: FUNC
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_DeleteAllRecoverInfoByTokenId_001, TestSize.Level1)
{
    auto tempKv = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_;
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = nullptr;
    auto &tempStoreId =
        const_cast<DistributedKv::StoreId &>(DelayedSingleton<AppExitReasonDataManager>::GetInstance()->storeId_);
    tempStoreId.storeId = "app_**exit_reason_infos";
    auto result =
        DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAllRecoverInfoByTokenId(ACCESS_TOKEN_ID);
    EXPECT_EQ(result, ERR_NO_INIT);

    tempStoreId.storeId = "app_exit_reason_infos";
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = tempKv;
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAllRecoverInfoByTokenId(ACCESS_TOKEN_ID);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = kvStorePtr;
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAllRecoverInfoByTokenId(ACCESS_TOKEN_ID);
    EXPECT_EQ(result, ERR_OK);
}

/* *
 * @tc.name: AppExitReasonDataManager_GetTokenIdBySessionID_001
 * @tc.desc: GetTokenIdBySessionID
 * @tc.type: FUNC
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_GetTokenIdBySessionID_001, TestSize.Level1)
{
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = nullptr;
    auto ret = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetTokenIdBySessionID(ACCESS_TOKEN_ID);
    EXPECT_EQ(ret, ERR_NO_INIT);

    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = kvStorePtr;
    ret = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetTokenIdBySessionID(ACCESS_TOKEN_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/* *
 * @tc.name: AppExitReasonDataManager_SetUIExtensionAbilityExitReason_001
 * @tc.desc: SetUIExtensionAbilityExitReason
 * @tc.type: FUNC
 */
HWTEST_F(AppExitReasonDataManagerTest, AppExitReasonDataManager_SetUIExtensionAbilityExitReason_001, TestSize.Level1)
{
    std::string bundleName = "com.test.demo";
    std::vector<std::string> extensionList;
    extensionList.push_back("testEntryUIExtAbility");
    AppExecFwk::RunningProcessInfo processInfo;
    AAFwk::ExitReason exitReason = {AAFwk::REASON_JS_ERROR, "Js Error."};
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->SetUIExtensionAbilityExitReason("",
        extensionList, exitReason, processInfo, false);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->SetUIExtensionAbilityExitReason(bundleName,
        extensionList, exitReason, processInfo, false);
    EXPECT_EQ(result, ERR_OK);
}
} // namespace AbilityRuntime
} // namespace OHOS
