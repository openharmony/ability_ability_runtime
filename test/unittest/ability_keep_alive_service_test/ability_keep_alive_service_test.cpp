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

#include "ability_keep_alive_data_manager.h"
#include "ability_keep_alive_service.h"
#include "ability_manager_errors.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AbilityRuntime;
namespace OHOS {
namespace AAFwk {
class AbilityKeepAliveServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AbilityKeepAliveServiceTest::SetUpTestCase() {}

void AbilityKeepAliveServiceTest::TearDownTestCase() {}

void AbilityKeepAliveServiceTest::SetUp() {}

void AbilityKeepAliveServiceTest::TearDown() {}

/*
 * Feature: AbilityKeepAliveService
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService SetApplicationKeepAlive
 */
HWTEST_F(AbilityKeepAliveServiceTest, SetApplicationKeepAlive_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_001 start";
    KeepAliveInfo info;
    info.bundleName = "bundleName";
    info.userId = -1;
    info.setter = KeepAliveSetter::USER;
    AbilityKeepAliveDataManager::callQueryDataResult = ERR_INVALID_VALUE;
    auto result = AbilityKeepAliveService::GetInstance().SetApplicationKeepAlive(info, true);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_001 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService SetApplicationKeepAlive
 */
HWTEST_F(AbilityKeepAliveServiceTest, SetApplicationKeepAlive_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_002 start";
    KeepAliveInfo info;
    info.bundleName = "bundleName";
    info.userId = -1;
    info.setter = KeepAliveSetter::USER;
    AbilityKeepAliveDataManager::callQueryDataResult = ERR_NAME_NOT_FOUND;
    AbilityKeepAliveDataManager::callInsertResult = ERR_OK;
    auto result = AbilityKeepAliveService::GetInstance().SetApplicationKeepAlive(info, true);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_002 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService SetApplicationKeepAlive
 */
HWTEST_F(AbilityKeepAliveServiceTest, SetApplicationKeepAlive_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_003 start";
    KeepAliveInfo info;
    info.bundleName = "bundleName";
    info.userId = -1;
    info.setter = KeepAliveSetter::USER;
    AbilityKeepAliveDataManager::callQueryDataResult = ERR_NAME_NOT_FOUND;
    AbilityKeepAliveDataManager::callInsertResult = ERR_INVALID_VALUE;
    auto result = AbilityKeepAliveService::GetInstance().SetApplicationKeepAlive(info, true);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_003 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService SetApplicationKeepAlive
 */
HWTEST_F(AbilityKeepAliveServiceTest, SetApplicationKeepAlive_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_004 start";
    KeepAliveInfo info;
    info.bundleName = "bundleName";
    info.userId = -1;
    info.setter = KeepAliveSetter::USER;
    AbilityKeepAliveDataManager::callQueryDataResult = ERR_OK;
    AbilityKeepAliveDataManager::queryDataSetter = KeepAliveSetter::SYSTEM;
    auto result = AbilityKeepAliveService::GetInstance().SetApplicationKeepAlive(info, true);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_004 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService SetApplicationKeepAlive
 */
HWTEST_F(AbilityKeepAliveServiceTest, SetApplicationKeepAlive_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_005 start";
    KeepAliveInfo info;
    info.bundleName = "bundleName";
    info.userId = -1;
    info.setter = KeepAliveSetter::SYSTEM;
    AbilityKeepAliveDataManager::callQueryDataResult = ERR_OK;
    AbilityKeepAliveDataManager::queryDataSetter = KeepAliveSetter::USER;
    AbilityKeepAliveDataManager::callInsertResult = ERR_OK;
    auto result = AbilityKeepAliveService::GetInstance().SetApplicationKeepAlive(info, true);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_005 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService SetApplicationKeepAlive
 */
HWTEST_F(AbilityKeepAliveServiceTest, SetApplicationKeepAlive_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_006 start";
    KeepAliveInfo info;
    info.bundleName = "bundleName";
    info.userId = -1;
    info.setter = KeepAliveSetter::SYSTEM;
    AbilityKeepAliveDataManager::callQueryDataResult = ERR_OK;
    AbilityKeepAliveDataManager::queryDataSetter = KeepAliveSetter::USER;
    AbilityKeepAliveDataManager::callInsertResult = ERR_INVALID_VALUE;
    auto result = AbilityKeepAliveService::GetInstance().SetApplicationKeepAlive(info, true);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_006 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService SetApplicationKeepAlive
 */
HWTEST_F(AbilityKeepAliveServiceTest, SetApplicationKeepAlive_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_007 start";
    KeepAliveInfo info;
    info.bundleName = "bundleName";
    info.userId = -1;
    info.setter = KeepAliveSetter::SYSTEM;
    AbilityKeepAliveDataManager::callQueryDataResult = ERR_INVALID_VALUE;
    auto result = AbilityKeepAliveService::GetInstance().SetApplicationKeepAlive(info, false);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_007 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService SetApplicationKeepAlive
 */
HWTEST_F(AbilityKeepAliveServiceTest, SetApplicationKeepAlive_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_008 start";
    KeepAliveInfo info;
    info.bundleName = "bundleName";
    info.userId = -1;
    info.setter = KeepAliveSetter::SYSTEM;
    AbilityKeepAliveDataManager::callQueryDataResult = ERR_NAME_NOT_FOUND;
    auto result = AbilityKeepAliveService::GetInstance().SetApplicationKeepAlive(info, false);
    EXPECT_EQ(result, ERR_TARGET_BUNDLE_NOT_EXIST);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_008 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService SetApplicationKeepAlive
 */
HWTEST_F(AbilityKeepAliveServiceTest, SetApplicationKeepAlive_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_009 start";
    KeepAliveInfo info;
    info.bundleName = "bundleName";
    info.userId = -1;
    info.setter = KeepAliveSetter::USER;
    AbilityKeepAliveDataManager::callQueryDataResult = ERR_OK;
    AbilityKeepAliveDataManager::queryDataSetter = KeepAliveSetter::SYSTEM;
    auto result = AbilityKeepAliveService::GetInstance().SetApplicationKeepAlive(info, false);
    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_009 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService SetApplicationKeepAlive
 */
HWTEST_F(AbilityKeepAliveServiceTest, SetApplicationKeepAlive_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_010 start";
    KeepAliveInfo info;
    info.bundleName = "bundleName";
    info.userId = -1;
    info.setter = KeepAliveSetter::SYSTEM;
    AbilityKeepAliveDataManager::callQueryDataResult = ERR_OK;
    AbilityKeepAliveDataManager::queryDataSetter = KeepAliveSetter::USER;
    AbilityKeepAliveDataManager::callDeleteResult = ERR_INVALID_VALUE;
    auto result = AbilityKeepAliveService::GetInstance().SetApplicationKeepAlive(info, false);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_010 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService SetApplicationKeepAlive
 */
HWTEST_F(AbilityKeepAliveServiceTest, SetApplicationKeepAlive_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_011 start";
    KeepAliveInfo info;
    info.bundleName = "bundleName";
    info.userId = -1;
    info.setter = KeepAliveSetter::SYSTEM;
    AbilityKeepAliveDataManager::callQueryDataResult = ERR_OK;
    AbilityKeepAliveDataManager::queryDataSetter = KeepAliveSetter::USER;
    AbilityKeepAliveDataManager::callDeleteResult = ERR_OK;
    auto result = AbilityKeepAliveService::GetInstance().SetApplicationKeepAlive(info, false);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest SetApplicationKeepAlive_011 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: QueryKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService QueryKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, QueryKeepAliveApplications_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_001 start";
    std::vector<KeepAliveInfo> infoList;
    int32_t appType = 0;
    int32_t userId = 100;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_OK;
    auto result = AbilityKeepAliveService::GetInstance().QueryKeepAliveApplications(appType, userId, infoList);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_001 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: QueryKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService QueryKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, QueryKeepAliveApplications_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_002 start";
    std::vector<KeepAliveInfo> infoList;
    int32_t appType = 1;
    int32_t userId = 100;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_OK;
    auto result = AbilityKeepAliveService::GetInstance().QueryKeepAliveApplications(appType, userId, infoList);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_002 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: QueryKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService QueryKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, QueryKeepAliveApplications_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_003 start";
    std::vector<KeepAliveInfo> infoList;
    int32_t appType = 2;
    int32_t userId = 100;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_OK;
    auto result = AbilityKeepAliveService::GetInstance().QueryKeepAliveApplications(appType, userId, infoList);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_003 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: QueryKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService QueryKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, QueryKeepAliveApplications_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_004 start";
    std::vector<KeepAliveInfo> infoList;
    int32_t appType = 0;
    int32_t userId = -1;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_OK;
    auto result = AbilityKeepAliveService::GetInstance().QueryKeepAliveApplications(appType, userId, infoList);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_004 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: QueryKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService QueryKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, QueryKeepAliveApplications_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_005 start";
    std::vector<KeepAliveInfo> infoList;
    int32_t appType = 1;
    int32_t userId = -1;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_OK;
    auto result = AbilityKeepAliveService::GetInstance().QueryKeepAliveApplications(appType, userId, infoList);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_005 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: QueryKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService QueryKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, QueryKeepAliveApplications_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_006 start";
    std::vector<KeepAliveInfo> infoList;
    int32_t appType = 2;
    int32_t userId = -1;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_OK;
    auto result = AbilityKeepAliveService::GetInstance().QueryKeepAliveApplications(appType, userId, infoList);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_006 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: QueryKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService QueryKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, QueryKeepAliveApplications_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_007 start";
    std::vector<KeepAliveInfo> infoList;
    int32_t appType = 0;
    int32_t userId = 100;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_INVALID_VALUE;
    auto result = AbilityKeepAliveService::GetInstance().QueryKeepAliveApplications(appType, userId, infoList);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_007 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: QueryKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService QueryKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, QueryKeepAliveApplications_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_008 start";
    std::vector<KeepAliveInfo> infoList;
    int32_t appType = 1;
    int32_t userId = 100;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_INVALID_VALUE;
    auto result = AbilityKeepAliveService::GetInstance().QueryKeepAliveApplications(appType, userId, infoList);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_008 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: QueryKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService QueryKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, QueryKeepAliveApplications_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_009 start";
    std::vector<KeepAliveInfo> infoList;
    int32_t appType = 2;
    int32_t userId = 100;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_INVALID_VALUE;
    auto result = AbilityKeepAliveService::GetInstance().QueryKeepAliveApplications(appType, userId, infoList);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_009 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: QueryKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService QueryKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, QueryKeepAliveApplications_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_010 start";
    std::vector<KeepAliveInfo> infoList;
    int32_t appType = 0;
    int32_t userId = -1;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_INVALID_VALUE;
    auto result = AbilityKeepAliveService::GetInstance().QueryKeepAliveApplications(appType, userId, infoList);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_010 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: QueryKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService QueryKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, QueryKeepAliveApplications_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_011 start";
    std::vector<KeepAliveInfo> infoList;
    int32_t appType = 1;
    int32_t userId = -1;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_INVALID_VALUE;
    auto result = AbilityKeepAliveService::GetInstance().QueryKeepAliveApplications(appType, userId, infoList);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_011 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: QueryKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService QueryKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, QueryKeepAliveApplications_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_012 start";
    std::vector<KeepAliveInfo> infoList;
    int32_t appType = 2;
    int32_t userId = -1;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_INVALID_VALUE;
    auto result = AbilityKeepAliveService::GetInstance().QueryKeepAliveApplications(appType, userId, infoList);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest QueryKeepAliveApplications_012 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: IsKeepAliveApp
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService IsKeepAliveApp
 */
HWTEST_F(AbilityKeepAliveServiceTest, IsKeepAliveApp_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest IsKeepAliveApp_001 start";
    std::string bundleName;
    auto result = AbilityKeepAliveService::GetInstance().IsKeepAliveApp(bundleName, -1);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest IsKeepAliveApp_001 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: IsKeepAliveApp
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService IsKeepAliveApp
 */
HWTEST_F(AbilityKeepAliveServiceTest, IsKeepAliveApp_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest IsKeepAliveApp_002 start";
    std::string bundleName = "bundleName";
    AbilityKeepAliveDataManager::callQueryDataResult = ERR_OK;
    auto result = AbilityKeepAliveService::GetInstance().IsKeepAliveApp(bundleName, -1);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest IsKeepAliveApp_002 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: IsKeepAliveApp
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService IsKeepAliveApp
 */
HWTEST_F(AbilityKeepAliveServiceTest, IsKeepAliveApp_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest IsKeepAliveApp_003 start";
    std::string bundleName = "bundleName";
    AbilityKeepAliveDataManager::callQueryDataResult = ERR_INVALID_VALUE;
    auto result = AbilityKeepAliveService::GetInstance().IsKeepAliveApp(bundleName, -1);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest IsKeepAliveApp_003 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: GetKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService GetKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, GetKeepAliveApplications_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest GetKeepAliveApplications_001 start";
    int32_t userId = -1;
    std::vector<KeepAliveInfo> infoList;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_OK;
    auto result = AbilityKeepAliveService::GetInstance().GetKeepAliveApplications(userId, infoList);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest GetKeepAliveApplications_001 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: GetKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService GetKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, GetKeepAliveApplications_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest GetKeepAliveApplications_002 start";
    int32_t userId = -1;
    std::vector<KeepAliveInfo> infoList;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_INVALID_VALUE;
    auto result = AbilityKeepAliveService::GetInstance().GetKeepAliveApplications(userId, infoList);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest GetKeepAliveApplications_002 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: GetKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService GetKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, GetKeepAliveApplications_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest GetKeepAliveApplications_003 start";
    int32_t userId = 100;
    std::vector<KeepAliveInfo> infoList;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_INVALID_VALUE;
    auto result = AbilityKeepAliveService::GetInstance().GetKeepAliveApplications(userId, infoList);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest GetKeepAliveApplications_003 end";
}

/*
 * Feature: AbilityKeepAliveService
 * Function: GetKeepAliveApplications
 * SubFunction: NA
 * FunctionPoints: AbilityKeepAliveService GetKeepAliveApplications
 */
HWTEST_F(AbilityKeepAliveServiceTest, GetKeepAliveApplications_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest GetKeepAliveApplications_004 start";
    int32_t userId = 100;
    std::vector<KeepAliveInfo> infoList;
    AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_OK;
    auto result = AbilityKeepAliveService::GetInstance().GetKeepAliveApplications(userId, infoList);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "AbilityKeepAliveServiceTest GetKeepAliveApplications_004 end";
}
} // namespace AAFwk
} // namespace OHOS
