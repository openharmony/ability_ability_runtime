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

#include "insight_intent_rdb_storage_mgr.h"

using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
void MockQueryData(bool mockRet);
void MockQueryDataBeginWithKey(bool mockRet);
void MockInsertData(bool mockRet);
void MockDeleteData(bool mockRet);
void MockDeleteDataBeginWithKey(bool mockRet);

class InsightIntentRdbStorageMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void InsightIntentRdbStorageMgrTest::SetUpTestCase()
{}

void InsightIntentRdbStorageMgrTest::TearDownTestCase()
{}

void InsightIntentRdbStorageMgrTest::SetUp()
{}

void InsightIntentRdbStorageMgrTest::TearDown()
{}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_001
 * @tc.desc: Test DeleteStorageInsightIntentByUserId
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_001, TestSize.Level0)
{
    int32_t userId = 0;
    MockDeleteDataBeginWithKey(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->DeleteStorageInsightIntentByUserId(userId);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    MockDeleteDataBeginWithKey(true);
    result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->DeleteStorageInsightIntentByUserId(userId);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_002
 * @tc.desc: Test DeleteStorageInsightIntentData
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_002, TestSize.Level0)
{
    int32_t userId = 0;
    std::string bundleName;
    std::string moduleName;
    MockDeleteDataBeginWithKey(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->DeleteStorageInsightIntentData(bundleName,
        moduleName, userId);
    MockDeleteDataBeginWithKey(true);
    result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->DeleteStorageInsightIntentData(bundleName,
        moduleName, userId);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_003
 * @tc.desc: Test SaveStorageInsightIntentData
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_003, TestSize.Level0)
{
    int32_t userId = 0;
    std::string bundleName;
    std::string moduleName;
    ExtractInsightIntentProfileInfoVec profileInfos;
    MockInsertData(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->SaveStorageInsightIntentData(bundleName,
        moduleName, userId, profileInfos);
    MockInsertData(true);
    result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->SaveStorageInsightIntentData(bundleName,
        moduleName, userId, profileInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_004
 * @tc.desc: Test LoadInsightIntentInfos
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_004, TestSize.Level0)
{
    int32_t userId = 0;
    std::vector<ExtractInsightIntentInfo> infos;
    MockQueryDataBeginWithKey(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadInsightIntentInfos(userId, infos);
    MockQueryDataBeginWithKey(true);
    result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadInsightIntentInfos(userId, infos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_005
 * @tc.desc: Test LoadInsightIntentInfoByName
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_005, TestSize.Level0)
{
    int32_t userId = 0;
    std::string bundleName;
    std::vector<ExtractInsightIntentInfo> infos;
    MockQueryDataBeginWithKey(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadInsightIntentInfoByName(bundleName,
        userId, infos);
    MockQueryDataBeginWithKey(true);
    result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadInsightIntentInfoByName(bundleName,
        userId, infos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_006
 * @tc.desc: Test LoadInsightIntentInfo
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_006, TestSize.Level0)
{
    int32_t userId = 0;
    std::string bundleName;
    std::string moduleName;
    std::string intentName;
    ExtractInsightIntentInfo infos;
    MockQueryData(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadInsightIntentInfo(bundleName,
        moduleName, intentName, userId, infos);
    MockQueryData(true);
    result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadInsightIntentInfo(bundleName,
        moduleName, intentName, userId, infos);
    EXPECT_EQ(result, ERR_OK);
}
}
}