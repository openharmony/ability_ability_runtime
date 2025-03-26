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
const int SESSION_ID = 111;
} // namespace

class AppExitReasonDataManagerSecondTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void AppExitReasonDataManagerSecondTest::SetUpTestCase(void) {}

void AppExitReasonDataManagerSecondTest::TearDownTestCase(void) {}

void AppExitReasonDataManagerSecondTest::SetUp() {}

void AppExitReasonDataManagerSecondTest::TearDown() {}


/* *
 * @tc.name: DeleteAbilityRecoverInfoBySessionId_001
 * @tc.desc: DeleteAbilityRecoverInfoBySessionId
 * @tc.type: FUNC
 */
HWTEST_F(AppExitReasonDataManagerSecondTest, DeleteAbilityRecoverInfoBySessionId_001, TestSize.Level1)
{
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = nullptr;
    auto &tempStoreId =
        const_cast<DistributedKv::StoreId &>(DelayedSingleton<AppExitReasonDataManager>::GetInstance()->storeId_);
    tempStoreId.storeId = "app_**exit_reason_infos";
    auto result =
        DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAbilityRecoverInfoBySessionId(SESSION_ID);
    EXPECT_EQ(result, ERR_NO_INIT);

    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->Get_ = DistributedKv::Status::ILLEGAL_STATE;
    tempStoreId.storeId = "app_exit_reason_infos";
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = kvStorePtr;
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAbilityRecoverInfoBySessionId(SESSION_ID);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    kvStorePtr->Get_ = DistributedKv::Status::SUCCESS;
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = kvStorePtr;
    result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->DeleteAbilityRecoverInfoBySessionId(SESSION_ID);
    EXPECT_EQ(result, ERR_OK);
}

/* *
 * @tc.name: GetUIExtensionAbilityExitReason_001
 * @tc.desc: GetUIExtensionAbilityExitReason
 * @tc.type: FUNC
 */
HWTEST_F(AppExitReasonDataManagerSecondTest, GetUIExtensionAbilityExitReason_001, TestSize.Level1)
{
    std::string bundleName = "com.test.demo";
    std::vector<std::string> extensionList;
    extensionList.push_back("testEntryUIExtAbility");
    AppExecFwk::RunningProcessInfo processInfo;
    bool withKillMsg = false;
    AAFwk::ExitReason exitReason = {AAFwk::REASON_JS_ERROR, "Js Error."};
    auto result = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->SetUIExtensionAbilityExitReason
        (bundleName, extensionList, exitReason, processInfo, withKillMsg);
    EXPECT_EQ(result, ERR_OK);

    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = nullptr;
    auto &tempStoreId =
    const_cast<DistributedKv::StoreId &>(DelayedSingleton<AppExitReasonDataManager>::GetInstance()->storeId_);
    tempStoreId.storeId = "app_**exit_reason_infos";
    std::string keyEx = bundleName + ":" + "testEntryUIExtAbility";
    int64_t stamp = 0;
    bool ret = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetUIExtensionAbilityExitReason(keyEx,
        exitReason, processInfo, stamp, withKillMsg);
    EXPECT_FALSE(ret);

    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    tempStoreId.storeId = "app_exit_reason_infos";
    kvStorePtr->GetEntries_ = DistributedKv::Status::ILLEGAL_STATE;
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = kvStorePtr;
    ret = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetUIExtensionAbilityExitReason(keyEx,
        exitReason, processInfo, stamp, withKillMsg);
    EXPECT_FALSE(ret);

    kvStorePtr->GetEntries_ = DistributedKv::Status::SUCCESS;
    ret = DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetUIExtensionAbilityExitReason(keyEx,
        exitReason, processInfo, stamp, withKillMsg);
    EXPECT_FALSE(ret);
}

/* *
 * @tc.name: GetRecordAppAbilityNames_001
 * @tc.desc: GetRecordAppAbilityNames
 * @tc.type: FUNC
 */
HWTEST_F(AppExitReasonDataManagerSecondTest, GetRecordAppAbilityNames_001, TestSize.Level1)
{
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = nullptr;
    uint32_t tokenId = 0;
    std::vector<std::string> abilityLists;
    auto &tempStoreId =
        const_cast<DistributedKv::StoreId &>(DelayedSingleton<AppExitReasonDataManager>::GetInstance()->storeId_);
    tempStoreId.storeId = "app_**exit_reason_infos";
    auto result =
        DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetRecordAppAbilityNames(tokenId, abilityLists);
    EXPECT_EQ(result, AAFwk::ERR_INVALID_ACCESS_TOKEN);

    tokenId = 1;
    result =
        DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetRecordAppAbilityNames(tokenId, abilityLists);
    EXPECT_EQ(result, AAFwk::ERR_GET_KV_STORE_HANDLE_FAILED);

    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->GetEntries_ = DistributedKv::Status::ILLEGAL_STATE;
    tempStoreId.storeId = "app_exit_reason_infos";
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = kvStorePtr;
    result =
        DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetRecordAppAbilityNames(tokenId, abilityLists);
    EXPECT_EQ(result, AAFwk::ERR_GET_EXIT_INFO_FAILED);

    kvStorePtr->GetEntries_ = DistributedKv::Status::SUCCESS;
    DelayedSingleton<AppExitReasonDataManager>::GetInstance()->kvStorePtr_ = kvStorePtr;
    result =
        DelayedSingleton<AppExitReasonDataManager>::GetInstance()->GetRecordAppAbilityNames(tokenId, abilityLists);
    EXPECT_EQ(result, ERR_OK);
}
} // namespace AbilityRuntime
} // namespace OHOS
