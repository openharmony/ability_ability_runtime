/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "keep_alive_process_manager.h"

#include "ability_keep_alive_service.h"
#include "ability_manager_service.h"
#include "ability_util.h"
#include "app_mgr_client.h"
#include "bundle_mgr_helper.h"
#include "main_element_utils.h"
#include "mock_my_flag.h"
#include "parameters.h"
#include "permission_verification.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AAFwk {
namespace {
constexpr char PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED[] = "const.product.enterprisefeature.setting.enabled";
constexpr char FOUNDATION_PROCESS_NAME[] = "foundation";
} // namespace

class KeepAliveProcessManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void KeepAliveProcessManagerTest::SetUpTestCase(void)
{}
void KeepAliveProcessManagerTest::TearDownTestCase(void)
{}
void KeepAliveProcessManagerTest::SetUp()
{}
void KeepAliveProcessManagerTest::TearDown()
{
    AbilityManagerService::isSupportStatusBarResult = true;
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_001 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = true;
    MyFlag::verifyCallingPermissionFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    MainElementUtils::checkMainUIAbilityResult = true;
    MainElementUtils::checkStatusBarAbilityResult = true;
    AppMgrClient::isAppRunningReturnCode = ERR_OK;
    AppMgrClient::isAppRunningReturnValue = false;
    AbilityKeepAliveService::callSetResult = ERR_OK;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_001 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_002 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), false);
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_CAPABILITY_NOT_SUPPORT);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_002 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_003 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = false;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_NOT_SYSTEM_APP);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_003 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_004 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = true;
    MyFlag::verifyCallingPermissionFlag_ = false;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_004 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_005 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = true;
    MyFlag::verifyCallingPermissionFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = false;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_TARGET_BUNDLE_NOT_EXIST);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_005 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_006 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = true;
    MyFlag::verifyCallingPermissionFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    MainElementUtils::checkMainUIAbilityResult = false;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_NO_MAIN_ABILITY);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_006 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_007 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = true;
    MyFlag::verifyCallingPermissionFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    MainElementUtils::checkMainUIAbilityResult = true;
    MainElementUtils::checkStatusBarAbilityResult = false;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_NO_STATUS_BAR_ABILITY);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_007 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_008 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = true;
    MyFlag::verifyCallingPermissionFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    MainElementUtils::checkMainUIAbilityResult = true;
    MainElementUtils::checkStatusBarAbilityResult = true;
    AppMgrClient::isAppRunningReturnCode = ERR_OK;
    AppMgrClient::isAppRunningReturnValue = true;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_NOT_ATTACHED_TO_STATUS_BAR);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_008 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_009 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = true;
    MyFlag::verifyCallingPermissionFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    MainElementUtils::checkMainUIAbilityResult = true;
    MainElementUtils::checkStatusBarAbilityResult = true;
    AppMgrClient::isAppRunningReturnCode = ERR_OK;
    AppMgrClient::isAppRunningReturnValue = true;
    AbilityManagerService::isInStatusBarResult = false;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_NOT_ATTACHED_TO_STATUS_BAR);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_009 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_010 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = true;
    MyFlag::verifyCallingPermissionFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    MainElementUtils::checkMainUIAbilityResult = true;
    MainElementUtils::checkStatusBarAbilityResult = true;
    AppMgrClient::isAppRunningReturnCode = ERR_OK;
    AppMgrClient::isAppRunningReturnValue = true;
    AbilityManagerService::isInStatusBarResult = true;
    AbilityKeepAliveService::callSetResult = INNER_ERR;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, INNER_ERR);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_010 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_011 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = true;
    MyFlag::verifyCallingPermissionFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    MainElementUtils::checkMainUIAbilityResult = true;
    MainElementUtils::checkStatusBarAbilityResult = true;
    AppMgrClient::isAppRunningReturnCode = ERR_OK;
    AppMgrClient::isAppRunningReturnValue = true;
    AbilityManagerService::isInStatusBarResult = true;
    AbilityKeepAliveService::callSetResult = ERR_OK;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_011 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_012 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = false;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = true;
    MyFlag::verifyCallingPermissionFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    AbilityKeepAliveService::callSetResult = ERR_OK;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_012 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_013 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = false;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = true;
    MyFlag::verifyCallingPermissionFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    AbilityKeepAliveService::callSetResult = INNER_ERR;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, INNER_ERR);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_013 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_014 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = true;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::checkSpecificFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    MainElementUtils::checkMainUIAbilityResult = true;
    MainElementUtils::checkStatusBarAbilityResult = true;
    AppMgrClient::isAppRunningReturnCode = ERR_OK;
    AppMgrClient::isAppRunningReturnValue = true;
    AbilityManagerService::isInStatusBarResult = true;
    AbilityKeepAliveService::callSetResult = ERR_OK;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_014 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_015 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = true;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::checkSpecificFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    MainElementUtils::checkMainUIAbilityResult = true;
    MainElementUtils::checkStatusBarAbilityResult = true;
    AppMgrClient::isAppRunningReturnCode = ERR_OK;
    AppMgrClient::isAppRunningReturnValue = false;
    AbilityKeepAliveService::callSetResult = ERR_OK;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_015 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_016 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = true;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), false);
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_CAPABILITY_NOT_SUPPORT);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_016 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_017 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = true;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::checkSpecificFlag_ = false;
    AbilityManagerService::userId_ = 100;
    MyFlag::flag_ = MyFlag::FLAG::IS_SA_CALL;
    MyFlag::verifyCallingPermissionFlag_ = true;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    MainElementUtils::checkMainUIAbilityResult = true;
    MainElementUtils::checkStatusBarAbilityResult = true;
    AppMgrClient::isAppRunningReturnCode = ERR_OK;
    AppMgrClient::isAppRunningReturnValue = true;
    AbilityManagerService::isInStatusBarResult = true;
    AbilityKeepAliveService::callSetResult = ERR_OK;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_017 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_018 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = true;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::checkSpecificFlag_ = false;
    AbilityManagerService::userId_ = 100;
    MyFlag::flag_ = 0;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_018 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_019 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = true;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::checkSpecificFlag_ = false;
    AbilityManagerService::userId_ = 100;
    MyFlag::flag_ = MyFlag::FLAG::IS_SA_CALL;
    MyFlag::verifyCallingPermissionFlag_ = false;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_019 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_020 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = true;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::checkSpecificFlag_ = false;
    AbilityManagerService::userId_ = 100;
    MyFlag::flag_ = MyFlag::FLAG::IS_SA_CALL;
    MyFlag::verifyCallingPermissionFlag_ = true;
    BundleMgrHelper::getBundleInfoResult = false;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_TARGET_BUNDLE_NOT_EXIST);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_020 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_021 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = true;
    MyFlag::verifyCallingPermissionFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    MainElementUtils::checkMainUIAbilityResult = true;
    MainElementUtils::checkStatusBarAbilityResult = false;
    AbilityManagerService::isSupportStatusBarResult = false;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_021 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_022 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = true;
    MyFlag::verifyCallingPermissionFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    MainElementUtils::checkMainUIAbilityResult = true;
    MainElementUtils::checkStatusBarAbilityResult = true;
    AppMgrClient::isAppRunningReturnCode = ERR_OK;
    AppMgrClient::isAppRunningReturnValue = true;
    AbilityManagerService::isSupportStatusBarResult = false;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_022 end";
}

/*
 * Feature: KeepAliveProcessManager
 * Function: SetApplicationKeepAlive
 * SubFunction: NA
 * FunctionPoints:KeepAliveProcessManager SetApplicationKeepAlive
 * EnvConditions: NA
 * CaseDescription: Verify SetApplicationKeepAlive
 */
HWTEST_F(KeepAliveProcessManagerTest, SetApplicationKeepAlive_023, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_023 start";
    std::string bundleName = "bundleName";
    int32_t userId = -1;
    bool updataEnable = true;
    bool isByEDM = false;
    bool isInner = false;
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false), true);
    MyFlag::isAllowedToUseSystemAPIFlag_ = true;
    MyFlag::verifyCallingPermissionFlag_ = true;
    AbilityManagerService::userId_ = 100;
    BundleMgrHelper::getBundleInfoResult = true;
    AbilityKeepAliveService::callIsKeepAliveResult = false;
    MainElementUtils::checkMainUIAbilityResult = true;
    MainElementUtils::checkStatusBarAbilityResult = true;
    AppMgrClient::isAppRunningReturnCode = ERR_OK;
    AppMgrClient::isAppRunningReturnValue = true;
    AbilityManagerService::isInStatusBarResult = false;
    AbilityManagerService::isSupportStatusBarResult = false;
    auto result = KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId,
        updataEnable, isByEDM, isInner);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "KeepAliveProcessManagerTest SetApplicationKeepAlive_023 end";
}
}  // namespace AAFwk
}  // namespace OHOS
