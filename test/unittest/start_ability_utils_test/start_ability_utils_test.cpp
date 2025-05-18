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

#include "ability_manager_errors.h"
#include "extension_ability_info.h"
#include "mock_my_status.h"
#include "start_ability_utils.h"
#include "want.h"

using namespace testing::ext;
namespace OHOS {
namespace AAFwk {

class StartAbilityUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void StartAbilityUtilsTest::SetUpTestCase()
{}

void StartAbilityUtilsTest::TearDownTestCase()
{}

void StartAbilityUtilsTest::SetUp()
{}

void StartAbilityUtilsTest::TearDown()
{}

/**
 * @tc.name: GetApplicationInfo_001
 * @tc.desc: test class StartAbilityUtil GetApplicationInfo function
 * @tc.type: FUNC
 */
HWTEST_F(StartAbilityUtilsTest, GetApplicationInfo_001, TestSize.Level1)
{
    std::string bundleName = "";
    int32_t userId = 0;
    AppExecFwk::ApplicationInfo appInfo;
    bool ret = StartAbilityUtils::GetApplicationInfo(bundleName, userId, appInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetApplicationInfo_002
 * @tc.desc: test class StartAbilityUtil GetApplicationInfo function
 * @tc.type: FUNC
 */
HWTEST_F(StartAbilityUtilsTest, GetApplicationInfo_002, TestSize.Level1)
{
    std::string bundleName = "test";
    int32_t userId = 0;
    AppExecFwk::ApplicationInfo appInfo;
    bool ret = StartAbilityUtils::GetApplicationInfo(bundleName, userId, appInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetApplicationInfo_003
 * @tc.desc: test class StartAbilityUtil GetApplicationInfo function
 * @tc.type: FUNC
 */
HWTEST_F(StartAbilityUtilsTest, GetApplicationInfo_003, TestSize.Level1)
{
    std::string bundleName = "test";
    int32_t userId = 0;
    AppExecFwk::ApplicationInfo appInfo;
    AAFwk::MyStatus::GetInstance().retValue_ = true;
    bool ret = StartAbilityUtils::GetApplicationInfo(bundleName, userId, appInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: CheckAppProvisionMode_001
 * @tc.desc: test class StartAbilityUtil CheckAppProvisionMode function
 * @tc.type: FUNC
 */
HWTEST_F(StartAbilityUtilsTest, CheckAppProvisionMode_001, TestSize.Level1)
{
    std::string bundleName = "testName";
    int32_t userId = 0;
    StartAbilityUtils::startAbilityInfo = std::make_shared<StartAbilityInfo>();
    AppExecFwk::ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    StartAbilityUtils::startAbilityInfo->abilityInfo.applicationInfo = applicationInfo;
    int32_t ret = StartAbilityUtils::CheckAppProvisionMode(bundleName, userId);
    EXPECT_EQ(ret, ERR_NOT_IN_APP_PROVISION_MODE);
}

/**
 * @tc.name: CheckAppProvisionMode_002
 * @tc.desc: test class StartAbilityUtil CheckAppProvisionMode function
 * @tc.type: FUNC
 */
HWTEST_F(StartAbilityUtilsTest, CheckAppProvisionMode_002, TestSize.Level1)
{
    std::string bundleName = "testName";
    int32_t userId = 0;
    StartAbilityUtils::startAbilityInfo = std::make_shared<StartAbilityInfo>();
    AppExecFwk::ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.appProvisionType = AppExecFwk::Constants::APP_PROVISION_TYPE_DEBUG;
    StartAbilityUtils::startAbilityInfo->abilityInfo.applicationInfo = applicationInfo;
    int32_t ret = StartAbilityUtils::CheckAppProvisionMode(bundleName, userId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: CheckAppProvisionMode_003
 * @tc.desc: test class StartAbilityUtil CheckAppProvisionMode function
 * @tc.type: FUNC
 */
HWTEST_F(StartAbilityUtilsTest, CheckAppProvisionMode_003, TestSize.Level1)
{
    std::string bundleName = "";
    int32_t userId = 0;
    int32_t ret = StartAbilityUtils::CheckAppProvisionMode(bundleName, userId);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}
}  // namespace AAFwk
}  // namespace OHOS
