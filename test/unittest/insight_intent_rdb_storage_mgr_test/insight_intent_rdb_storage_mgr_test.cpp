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

#include "errors.h"
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
    uint32_t versionCode = 0;
    ExtractInsightIntentProfileInfoVec profileInfos;
    std::vector<InsightIntentInfo> configInfos;
    MockInsertData(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->SaveStorageInsightIntentData(bundleName,
        moduleName, userId, versionCode, profileInfos, configInfos);
    MockInsertData(true);
    result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->SaveStorageInsightIntentData(bundleName,
        moduleName, userId, versionCode, profileInfos, configInfos);
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
    std::vector<InsightIntentInfo> configInfos;
    std::map<std::string, std::string> bundleVersionMap;
    
    MockQueryDataBeginWithKey(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadInsightIntentInfos(
        userId, bundleVersionMap, infos, configInfos);
    MockQueryDataBeginWithKey(true);
    result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->
        LoadInsightIntentInfos(userId, bundleVersionMap, infos, configInfos);
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
    MockQueryDataBeginWithKey(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadInsightIntentInfo(bundleName,
        moduleName, intentName, userId, infos);
    MockQueryDataBeginWithKey(true);
    result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadInsightIntentInfo(bundleName,
        moduleName, intentName, userId, infos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_007
 * @tc.desc: Test LoadConfigInsightIntentInfos
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_007, TestSize.Level0)
{
    int32_t userId = 0;
    std::vector<InsightIntentInfo> configInfos;
    MockQueryDataBeginWithKey(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadConfigInsightIntentInfos(
        userId, configInfos);
    MockQueryDataBeginWithKey(true);
    result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadConfigInsightIntentInfos(
        userId, configInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_008
 * @tc.desc: Test LoadConfigInsightIntentInfoByName
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_008, TestSize.Level0)
{
    int32_t userId = 0;
    std::string bundleName;
    std::vector<InsightIntentInfo> infos;
    MockQueryDataBeginWithKey(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadConfigInsightIntentInfoByName(
        bundleName, userId, infos);
    MockQueryDataBeginWithKey(true);
    result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadConfigInsightIntentInfoByName(
        bundleName, userId, infos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_009
 * @tc.desc: Test LoadConfigInsightIntentInfo
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_009, TestSize.Level0)
{
    int32_t userId = 0;
    std::string bundleName;
    std::string moduleName;
    std::string intentName;
    InsightIntentInfo infos;
    MockQueryDataBeginWithKey(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadConfigInsightIntentInfo(bundleName,
        moduleName, intentName, userId, infos);
    MockQueryDataBeginWithKey(true);
    result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadConfigInsightIntentInfo(bundleName,
        moduleName, intentName, userId, infos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_010
 * @tc.desc: Test DeleteStorageInsightIntentData with non-empty moduleName
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_010, TestSize.Level0)
{
    int32_t userId = 0;
    std::string bundleName = "testBundle";
    std::string moduleName = "testModule";

    MockDeleteDataBeginWithKey(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->DeleteStorageInsightIntentData(
        bundleName, moduleName, userId);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    
    MockDeleteDataBeginWithKey(true);
    result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->DeleteStorageInsightIntentData(
        bundleName, moduleName, userId);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_011
 * @tc.desc: Test SaveStorageInsightIntentData with ToJson failed (profileInfo)
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_011, TestSize.Level0)
{
    int32_t userId = 0;
    std::string bundleName = "testBundle";
    std::string moduleName = "testModule";
    ExtractInsightIntentProfileInfoVec profileInfos;
    std::vector<InsightIntentInfo> configInfos;
    
    ExtractInsightIntentProfileInfo profileInfo;
    profileInfo.intentName = "testIntent";
    profileInfos.insightIntents.push_back(profileInfo);

    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->SaveStorageInsightIntentData(
        bundleName, moduleName, userId, 0, profileInfos, configInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_012
 * @tc.desc: Test SaveStorageInsightIntentData with ToJson failed (configInfo)
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_012, TestSize.Level0)
{
    int32_t userId = 0;
    std::string bundleName = "testBundle";
    std::string moduleName = "testModule";
    ExtractInsightIntentProfileInfoVec profileInfos;
    std::vector<InsightIntentInfo> configInfos;

    InsightIntentInfo configInfo;
    configInfo.intentName = "testIntent";
    configInfos.push_back(configInfo);

    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->SaveStorageInsightIntentData(
        bundleName, moduleName, userId, 0, profileInfos, configInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_013
 * @tc.desc: Test LoadInsightIntentInfo with TransformTo failed
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_013, TestSize.Level0)
{
    int32_t userId = 0;
    std::string bundleName = "testBundle";
    std::string moduleName = "testModule";
    std::string intentName = "testIntent";
    ExtractInsightIntentInfo totalInfo;

    MockQueryDataBeginWithKey(true);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadInsightIntentInfo(
        bundleName, moduleName, intentName, userId, totalInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_014
 * @tc.desc: Test LoadConfigInsightIntentInfo with TransformTo failed
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_014, TestSize.Level0)
{
    int32_t userId = 0;
    std::string bundleName = "testBundle";
    std::string moduleName = "testModule";
    std::string intentName = "testIntent";
    InsightIntentInfo totalInfo;

    MockQueryDataBeginWithKey(true);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadConfigInsightIntentInfo(
        bundleName, moduleName, intentName, userId, totalInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_015
 * @tc.desc: Test TransformConfigIntent with invalid value (trigger DeleteData)
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_015, TestSize.Level0)
{
    int32_t userId = 0;
    std::vector<InsightIntentInfo> configInfos;

    MockQueryDataBeginWithKey(true);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadConfigInsightIntentInfos(
        userId, configInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_016
 * @tc.desc: Test Transform with invalid value (trigger DeleteData)
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_016, TestSize.Level0)
{
    int32_t userId = 0;
    std::vector<ExtractInsightIntentInfo> totalInfos;
    std::vector<InsightIntentInfo> configInfos;
    std::map<std::string, std::string> bundleVersionMap;

    MockQueryDataBeginWithKey(true);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->LoadInsightIntentInfos(
        userId, bundleVersionMap, totalInfos, configInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_018
 * @tc.desc: Test SaveStorageInsightIntentData with InsertData failed (profileInfo)
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_018, TestSize.Level0)
{
    int32_t userId = 0;
    std::string bundleName = "testBundle";
    std::string moduleName = "testModule";
    ExtractInsightIntentProfileInfoVec profileInfos;
    std::vector<InsightIntentInfo> configInfos;

    ExtractInsightIntentProfileInfo profileInfo;
    profileInfo.intentName = "testIntent";
    profileInfos.insightIntents.push_back(profileInfo);
    
    MockInsertData(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->SaveStorageInsightIntentData(
        bundleName, moduleName, userId, 0, profileInfos, configInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InsightIntentRdbStorageMgrTest_019
 * @tc.desc: Test SaveStorageInsightIntentData with InsertData failed (configInfo)
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentRdbStorageMgrTest, InsightIntentRdbStorageMgrTest_019, TestSize.Level0)
{
    int32_t userId = 0;
    std::string bundleName = "testBundle";
    std::string moduleName = "testModule";
    ExtractInsightIntentProfileInfoVec profileInfos;
    std::vector<InsightIntentInfo> configInfos;

    InsightIntentInfo configInfo;
    configInfo.intentName = "testIntent";
    configInfos.push_back(configInfo);
    
    MockInsertData(false);
    auto result = DelayedSingleton<InsightRdbStorageMgr>::GetInstance()->SaveStorageInsightIntentData(
        bundleName, moduleName, userId, 0, profileInfos, configInfos);
    EXPECT_EQ(result, ERR_OK);
}
}
}