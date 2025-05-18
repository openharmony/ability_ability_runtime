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

#include "insight_intent_db_cache.h"

using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
void MockDeleteData(bool mockRet);
void MockDeleteDataByUserId(bool mockRet);
void MockSaveData(bool mockRet);
void MockLoadInsightIntentInfo(bool mockRet);
void MockLoadInsightIntentInfoByName(bool mockRet);
void MockLoadInsightIntentInfos(bool mockRet);

class InsightIntentDbCacheTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void InsightIntentDbCacheTest::SetUpTestCase()
{}

void InsightIntentDbCacheTest::TearDownTestCase()
{}

void InsightIntentDbCacheTest::SetUp()
{}

void InsightIntentDbCacheTest::TearDown()
{}

/**
 * @tc.name: InsightIntentDbCacheTest_001
 * @tc.desc: Test InitInsightIntentCache
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentDbCacheTest, InsightIntentDbCacheTest_001, TestSize.Level0)
{
    int32_t userId = 0;
    std::string bundleName = "qwe";
    std::string moduleName = "qwe";
    std::string intentName = "qwe";
    ExtractInsightIntentProfileInfoVec profileInfos;
    ExtractInsightIntentProfileInfo info;
    profileInfos.insightIntents.push_back(info);
    MockLoadInsightIntentInfos(false);
    DelayedSingleton<InsightIntentDbCache>::GetInstance()->InitInsightIntentCache(userId);
    MockLoadInsightIntentInfos(true);
    DelayedSingleton<InsightIntentDbCache>::GetInstance()->InitInsightIntentCache(userId);
    MockSaveData(false);
    auto result = DelayedSingleton<InsightIntentDbCache>::GetInstance()->SaveInsightIntentTotalInfo(bundleName,
        moduleName, 100, profileInfos);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    result = DelayedSingleton<InsightIntentDbCache>::GetInstance()->SaveInsightIntentTotalInfo(bundleName,
        moduleName, userId, profileInfos);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    MockSaveData(true);
    result = DelayedSingleton<InsightIntentDbCache>::GetInstance()->SaveInsightIntentTotalInfo(bundleName,
        moduleName, userId, profileInfos);
    EXPECT_EQ(result, ERR_OK);

    std::vector<ExtractInsightIntentGenericInfo> genericInfos;
    DelayedSingleton<InsightIntentDbCache>::GetInstance()->GetAllInsightIntentGenericInfo(genericInfos);
    EXPECT_EQ(genericInfos.empty(), false);
    DelayedSingleton<InsightIntentDbCache>::GetInstance()->GetInsightIntentGenericInfoByName(
        bundleName, genericInfos);
    EXPECT_EQ(genericInfos.empty(), false);
    ExtractInsightIntentGenericInfo genericInfo;
    DelayedSingleton<InsightIntentDbCache>::GetInstance()->GetInsightIntentGenericInfo(
            bundleName, moduleName, intentName, genericInfo);

    std::vector<ExtractInsightIntentInfo> genericInfos2;
    DelayedSingleton<InsightIntentDbCache>::GetInstance()->GetAllInsightIntentInfo(100, genericInfos2);
    EXPECT_EQ(genericInfos2.empty(), true);
    DelayedSingleton<InsightIntentDbCache>::GetInstance()->GetAllInsightIntentInfo(userId, genericInfos2);
    EXPECT_EQ(genericInfos2.empty(), false);
    std::vector<ExtractInsightIntentInfo> genericInfos3;
    DelayedSingleton<InsightIntentDbCache>::GetInstance()->GetInsightIntentInfoByName(bundleName, 100, genericInfos3);
    EXPECT_EQ(genericInfos3.empty(), true);
    DelayedSingleton<InsightIntentDbCache>::GetInstance()->GetInsightIntentInfoByName(bundleName,
        userId, genericInfos3);
    EXPECT_EQ(genericInfos3.empty(), false);
    ExtractInsightIntentInfo intentInfo;
    DelayedSingleton<InsightIntentDbCache>::GetInstance()->GetInsightIntentInfo(
        bundleName, moduleName, intentName, 100, intentInfo);
    DelayedSingleton<InsightIntentDbCache>::GetInstance()->GetInsightIntentInfo(
        bundleName, moduleName, intentName, userId, intentInfo);
}

/**
 * @tc.name: InsightIntentDbCacheTest_002
 * @tc.desc: Test DeleteInsightIntent
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentDbCacheTest, InsightIntentDbCacheTest_002, TestSize.Level0)
{
    MockDeleteData(true);
    int32_t userId = 0;
    std::string bundleName = "qwe";
    std::string moduleName = "";
    ExtractInsightIntentProfileInfoVec profileInfos;
    auto result = DelayedSingleton<InsightIntentDbCache>::GetInstance()->DeleteInsightIntentTotalInfo(bundleName,
        moduleName, 100);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    result = DelayedSingleton<InsightIntentDbCache>::GetInstance()->DeleteInsightIntentTotalInfo(bundleName,
        moduleName, userId);
    EXPECT_EQ(result, ERR_OK);
    moduleName = "qwe";
    DelayedSingleton<InsightIntentDbCache>::GetInstance()->SaveInsightIntentTotalInfo(bundleName,
        moduleName, userId, profileInfos);
    result = DelayedSingleton<InsightIntentDbCache>::GetInstance()->DeleteInsightIntentTotalInfo(bundleName,
        moduleName, userId);
    EXPECT_EQ(result, ERR_OK);
    result = DelayedSingleton<InsightIntentDbCache>::GetInstance()->DeleteInsightIntentByUserId(userId);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    MockDeleteDataByUserId(true);
    result = DelayedSingleton<InsightIntentDbCache>::GetInstance()->DeleteInsightIntentByUserId(100);
    EXPECT_EQ(result, ERR_OK);
}
}
}