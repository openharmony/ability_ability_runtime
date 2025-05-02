/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#define private public

#include <gtest/gtest.h>

#define private public
#include "insight_intent_rdb_data_mgr.h"
#include "rdb_data_manager.h"
#undef private

using namespace testing::ext;
using namespace OHOS::AbilityRuntime;
using namespace OHOS;

namespace {
const std::string DB_PATH = "/data/test/";
const std::string DB_NAME = "intentRdbTestDb.db";
const std::string TABLE_NAME = "intentRdbTestTable";
const std::string KEY_ONE = "KEY_ONE";
const std::string VALUE_ONE = "VALUE_ONE";
const std::string KEY_TWO = "KEY_TWO";
const std::string VALUE_TWO = "VALUE_TWO";
const std::string KEY_THREE = "KEY_THREE";
const std::string VALUE_THREE = "VALUE_THREE";
const std::string TEST_BUNDLE_NAME = "com.test.rdbone";
const std::string TEST_NAME = "NameOne";
const uint32_t TEST_VERSION = 1;
const std::string TEST_BUNDLE_NAME_TWO = "com.test.rdbtwo";
const std::string TEST_NAME_TWO = "NameTwo";
const uint32_t TEST_VERSION_TWO = 2;

class InsightIntentRdbDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void InsightIntentRdbDataManagerTest::SetUpTestCase()
{}

void InsightIntentRdbDataManagerTest::TearDownTestCase()
{}

void InsightIntentRdbDataManagerTest::SetUp()
{}

void InsightIntentRdbDataManagerTest::TearDown()
{}

/**
 * @tc.number: InsightIntentRdbDataManager_0100
 * @tc.desc: Test init
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbDataManagerTest, InsightIntentRdbDataManager_0100, Function | SmallTest | Level1)
{
    IntentRdbConfig intentRdbConfig;
    auto res = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->InitIntentTable(intentRdbConfig);
    EXPECT_TRUE(res);

    res = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->InsertData(KEY_ONE, VALUE_ONE);
    EXPECT_TRUE(res);

    std::string value;
    res = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->QueryData(KEY_ONE, value);
    EXPECT_TRUE(res);
    EXPECT_TRUE(value == VALUE_ONE);

    res = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->UpdateData(KEY_ONE, VALUE_TWO);
    EXPECT_TRUE(res);

    res = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->QueryData(KEY_ONE, value);
    EXPECT_TRUE(res);
    EXPECT_TRUE(value == VALUE_TWO);

    std::unordered_map<std::string, std::string> datas;
    res = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->QueryDataBeginWithKey(KEY_ONE, datas);
    EXPECT_TRUE(res);

    res = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->QueryAllData(datas);
    EXPECT_TRUE(res);

    res = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->DeleteData(KEY_ONE);
    EXPECT_TRUE(res);

    res = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->InsertData(KEY_ONE, VALUE_ONE);
    EXPECT_TRUE(res);

    res = DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->DeleteDataBeginWithKey(KEY_ONE);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: InsightIntentRdbDataManager_0200
 * @tc.desc: Verify functionName IntentRdbOpenCallback.
 * @tc.details: The function runs normally and the return value meets expectations.
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbDataManagerTest, InsightIntentRdbDataManager_0200, Function | SmallTest | Level1)
{
    IntentRdbConfig intentRdbConfig;
    auto rdbDataCallBack = std::make_shared<IntentRdbOpenCallback>(intentRdbConfig);
    auto result = rdbDataCallBack->
        OnCreate(*(DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->rdbStore_.get()));
    EXPECT_EQ(result, NativeRdb::E_OK);

    result = rdbDataCallBack->
        OnOpen(*(DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->rdbStore_.get()));
    EXPECT_EQ(result, NativeRdb::E_OK);

    int currentVersion = 1;
    int targetVersion = 2;
    result = rdbDataCallBack->OnUpgrade(*(DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->rdbStore_.get()),
        currentVersion, targetVersion);
    EXPECT_EQ(result, NativeRdb::E_OK);

    result = rdbDataCallBack->OnDowngrade(*(DelayedSingleton<InsightIntentRdbDataMgr>::GetInstance()->rdbStore_.get()),
        targetVersion, currentVersion);
    EXPECT_EQ(result, NativeRdb::E_OK);

    std::string data = "testKey";
    result = rdbDataCallBack->onCorruption(data);
    EXPECT_EQ(result, NativeRdb::E_OK);
}
}  // namespace
