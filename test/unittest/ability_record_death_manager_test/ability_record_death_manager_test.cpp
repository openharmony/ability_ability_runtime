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
#include <chrono>
#include <thread>
#define private public
#define protected public
#include "ability_record_death_manager.h"
#undef protected
#undef private
#include "ability_record.h"
#include "application_info.h"
#include "time_util.h"
#include "mock_ability_token.h"

using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
namespace {
    const int32_t DEFAULT_PID = 1001;
    const int32_t DEFAULT_UID = 10001;
    const std::string DEFAULT_BUNDLE_NAME = "com.example.test";
    const std::string DEFAULT_ABILITY_NAME = "TestAbility";
    const int32_t WAIT_TIME_MS = 3500; // Wait time should be longer than DEAD_APP_RECORD_CLEAR_TIME
}

class AbilityRecordDeathManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<AbilityRecord> CreateMockAbilityRecord(int32_t pid, int32_t uid) const;
};

void AbilityRecordDeathManagerTest::SetUpTestCase()
{}

void AbilityRecordDeathManagerTest::TearDownTestCase()
{}

void AbilityRecordDeathManagerTest::SetUp()
{}

void AbilityRecordDeathManagerTest::TearDown()
{}

std::shared_ptr<AbilityRecord> AbilityRecordDeathManagerTest::CreateMockAbilityRecord(int32_t pid, int32_t uid) const
{
    sptr<AppExecFwk::MockAbilityToken> token = new AppExecFwk::MockAbilityToken();
    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = std::make_shared<AppExecFwk::AbilityInfo>();
    abilityInfo->bundleName = DEFAULT_BUNDLE_NAME;
    abilityInfo->name = DEFAULT_ABILITY_NAME;
    AppExecFwk::ApplicationInfo applicationInfo;
    Want want;
    std::shared_ptr<AbilityRecord> abilityRecord = std::make_shared<AbilityRecord>(want, *abilityInfo, applicationInfo);
    abilityRecord->Init();
    abilityRecord->SetPid(pid);
    abilityRecord->SetUid(uid);
    return abilityRecord;
}

/**
 * @tc.name: AbilityRecordDeathManager_GetInstance_001
 * @tc.desc: Test GetInstance returns a valid singleton instance.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRecordDeathManagerTest, GetInstance_001, TestSize.Level1)
{
    auto& instance1 = AbilityRecordDeathManager::GetInstance();
    auto& instance2 = AbilityRecordDeathManager::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: AbilityRecordDeathManager_AddRecordToDeadList_001
 * @tc.desc: Test adding a null ability record does nothing.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRecordDeathManagerTest, AddRecordToDeadList_001, TestSize.Level1)
{
    AbilityRecordDeathManager& manager = AbilityRecordDeathManager::GetInstance();
    std::shared_ptr<AbilityRecord> nullRecord = nullptr;
    manager.AddRecordToDeadList(nullRecord);
    auto result = manager.QueryDeadAbilityRecord(DEFAULT_PID, DEFAULT_UID);
    EXPECT_EQ(result.size(), 0);
    manager.deadAbilityRecordList_.clear();
}

/**
 * @tc.name: AbilityRecordDeathManager_AddRecordToDeadList_002
 * @tc.desc: Test adding and querying an ability record.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRecordDeathManagerTest, AddRecordToDeadList_002, TestSize.Level1)
{
    AbilityRecordDeathManager& manager = AbilityRecordDeathManager::GetInstance();
    auto record = CreateMockAbilityRecord(DEFAULT_PID, DEFAULT_UID);
    manager.AddRecordToDeadList(record);
    auto result = manager.QueryDeadAbilityRecord(DEFAULT_PID, DEFAULT_UID);
    EXPECT_EQ(result.size(), 1);
    manager.deadAbilityRecordList_.clear();
}

/**
 * @tc.name: AbilityRecordDeathManager_QueryDeadAbilityRecord_001
 * @tc.desc: Test querying for non-existent records.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRecordDeathManagerTest, QueryDeadAbilityRecord_001, TestSize.Level1)
{
    AbilityRecordDeathManager& manager = AbilityRecordDeathManager::GetInstance();
    auto result = manager.QueryDeadAbilityRecord(DEFAULT_PID, DEFAULT_UID);
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.name: AbilityRecordDeathManager_QueryDeadAbilityRecord_002
 * @tc.desc: Test querying for multiple records with same pid/uid.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRecordDeathManagerTest, QueryDeadAbilityRecord_002, TestSize.Level1)
{
    AbilityRecordDeathManager& manager = AbilityRecordDeathManager::GetInstance();
    auto record1 = CreateMockAbilityRecord(DEFAULT_PID, DEFAULT_UID);
    manager.AddRecordToDeadList(record1);
    auto result = manager.QueryDeadAbilityRecord(DEFAULT_PID, DEFAULT_UID);
    EXPECT_EQ(result.size(), 1);
    manager.deadAbilityRecordList_.clear();
}

/**
 * @tc.name: AbilityRecordDeathManager_RemoveTimeoutDeadAbilityRecord_001
 * @tc.desc: Test removing timed-out records.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRecordDeathManagerTest, RemoveTimeoutDeadAbilityRecord_001, TestSize.Level1)
{
    AbilityRecordDeathManager& manager = AbilityRecordDeathManager::GetInstance();
    auto record = CreateMockAbilityRecord(DEFAULT_PID, DEFAULT_UID);
    manager.AddRecordToDeadList(record);
    auto result = manager.QueryDeadAbilityRecord(DEFAULT_PID, DEFAULT_UID);
    EXPECT_EQ(result.size(), 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    manager.RemoveTimeoutDeadAbilityRecord();
    result = manager.QueryDeadAbilityRecord(DEFAULT_PID, DEFAULT_UID);
    EXPECT_EQ(result.size(), 0);
    manager.deadAbilityRecordList_.clear();
}

/**
 * @tc.name: AbilityRecordDeathManager_RemoveTimeoutDeadAbilityRecord_002
 * @tc.desc: Test removing timed-out records.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityRecordDeathManagerTest, RemoveTimeoutDeadAbilityRecord_002, TestSize.Level1)
{
    AbilityRecordDeathManager& manager = AbilityRecordDeathManager::GetInstance();
    auto record = CreateMockAbilityRecord(DEFAULT_PID, DEFAULT_UID);
    manager.AddRecordToDeadList(record);
    manager.RemoveTimeoutDeadAbilityRecord();
    auto result = manager.QueryDeadAbilityRecord(DEFAULT_PID, DEFAULT_UID);
    EXPECT_EQ(result.size(), 1);
    manager.deadAbilityRecordList_.clear();
}
}  // namespace AAFwk
}  // namespace OHOS
