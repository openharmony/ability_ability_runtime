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

#include "ability_auto_startup_data_manager.h"
#include "ability_auto_startup_service.h"
#include "mock_bundle_mgr_helper.h"
#include "mock_my_flag.h"
#include "mock_parameters.h"
#include "mock_permission_verification.h"
#include "mock_single_kv_store.h"

namespace {
constexpr int32_t BASE_USER_RANGE = 200000;
} // namespace

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AbilityRuntime;
namespace OHOS {
namespace AAFwk {
class AbilityAutoStartupServiceSecondTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AbilityAutoStartupServiceSecondTest::SetUpTestCase() {}

void AbilityAutoStartupServiceSecondTest::TearDownTestCase() {}

void AbilityAutoStartupServiceSecondTest::SetUp() {}

void AbilityAutoStartupServiceSecondTest::TearDown() {}

/*
 * Feature: AbilityAutoStartupService
 * Function: RegisterAutoStartupSystemCallback and UnregisterAutoStartupSystemCallback
 * SubFunction: NA
 * FunctionPoints: AbilityAutoStartupService RegisterAutoStartupSystemCallback and UnregisterAutoStartupSystemCallback
 */
HWTEST_F(AbilityAutoStartupServiceSecondTest, RegisterAutoStartupSystemCallback_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterAutoStartupSystemCallback_001 start";

    auto abilityAutoStartupService = std::make_shared<AbilityAutoStartupService>();
    EXPECT_NE(abilityAutoStartupService, nullptr);

    MyFlag::flag_ = 1;
    system::SetBoolParameter("", true);
    sptr<IRemoteObject> callback = nullptr;
    int32_t result = abilityAutoStartupService->RegisterAutoStartupSystemCallback(nullptr);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(abilityAutoStartupService->callbackVector_.size(), 1);

    result = abilityAutoStartupService->RegisterAutoStartupSystemCallback(nullptr);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(abilityAutoStartupService->callbackVector_.size(), 1);

    result = abilityAutoStartupService->UnregisterAutoStartupSystemCallback(nullptr);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(abilityAutoStartupService->callbackVector_.size(), 0);

    result = abilityAutoStartupService->UnregisterAutoStartupSystemCallback(nullptr);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(abilityAutoStartupService->callbackVector_.size(), 0);

    GTEST_LOG_(INFO) << "RegisterAutoStartupSystemCallback_001 end";
}

/*
 * Feature: AbilityAutoStartupService
 * Function: CheckAutoStartupData
 * SubFunction: NA
 * FunctionPoints: AbilityAutoStartupService CheckAutoStartupData
 */
HWTEST_F(AbilityAutoStartupServiceSecondTest, CheckAutoStartupData_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAutoStartupData_002 start";

    auto abilityAutoStartupService = std::make_shared<AbilityAutoStartupService>();
    EXPECT_NE(abilityAutoStartupService, nullptr);

    auto kvStorePtr = std::make_shared<MockSingleKvStore>();
    EXPECT_NE(kvStorePtr, nullptr);
    DelayedSingleton<AbilityAutoStartupDataManager>::GetInstance()->kvStorePtr_ = kvStorePtr;

    std::string bundleName = "infoListIs0";
    int32_t result = abilityAutoStartupService->CheckAutoStartupData(bundleName, BASE_USER_RANGE);
    EXPECT_EQ(result, 0);

    bundleName = "moduleNameIsempty";
    result = abilityAutoStartupService->CheckAutoStartupData(bundleName, BASE_USER_RANGE);
    EXPECT_EQ(result, 0);

    bundleName = "isFoundIsTrue";
    result = abilityAutoStartupService->CheckAutoStartupData(bundleName, BASE_USER_RANGE);
    EXPECT_EQ(result, 0);

    bundleName = "isFoundIsFalse";
    result = abilityAutoStartupService->CheckAutoStartupData(bundleName, BASE_USER_RANGE);
    EXPECT_EQ(result, 0);

    GTEST_LOG_(INFO) << "CheckAutoStartupData_002 end";
}

/*
 * Feature: AbilityAutoStartupService
 * Function: GetAbilityData
 * SubFunction: NA
 * FunctionPoints: AbilityAutoStartupService GetAbilityData
 */
HWTEST_F(AbilityAutoStartupServiceSecondTest, GetAbilityData_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetAbilityData_003 start";

    auto abilityAutoStartupService = std::make_shared<AbilityAutoStartupService>();
    EXPECT_NE(abilityAutoStartupService, nullptr);

    AbilityRuntime::AutoStartupInfo autoStartupInfo;
    autoStartupInfo.bundleName = "bundleNameTest";
    autoStartupInfo.abilityName = "nameTest";
    autoStartupInfo.moduleName = "moduleNameTest";
    autoStartupInfo.accessTokenId = 1;
    autoStartupInfo.appCloneIndex = 0;

    bool isVisible = true;
    std::string abilityTypeName = "";
    std::string accessTokenId = "";
    int32_t userId = 0;

    bool result =
        abilityAutoStartupService->GetAbilityData(autoStartupInfo, isVisible, abilityTypeName, accessTokenId, userId);
    EXPECT_FALSE(result);
    EXPECT_TRUE(isVisible);

    isVisible = true;
    autoStartupInfo.bundleName = "hapModuleInfosModuleNameIsempty";
    autoStartupInfo.moduleName = "";
    result =
        abilityAutoStartupService->GetAbilityData(autoStartupInfo, isVisible, abilityTypeName, accessTokenId, userId);
    EXPECT_TRUE(result);
    EXPECT_FALSE(isVisible);

    isVisible = true;
    autoStartupInfo.bundleName = "hapModuleInfosModuleNameNotempty";
    autoStartupInfo.moduleName = "moduleNameTest";
    result =
        abilityAutoStartupService->GetAbilityData(autoStartupInfo, isVisible, abilityTypeName, accessTokenId, userId);
    EXPECT_FALSE(isVisible);

    isVisible = true;
    autoStartupInfo.bundleName = "extensionInfosModuleNameIsempty";
    autoStartupInfo.moduleName = "";
    result =
        abilityAutoStartupService->GetAbilityData(autoStartupInfo, isVisible, abilityTypeName, accessTokenId, userId);
    EXPECT_TRUE(result);
    EXPECT_FALSE(isVisible);

    isVisible = true;
    autoStartupInfo.bundleName = "extensionInfosModuleNameNotempty";
    autoStartupInfo.moduleName = "moduleNameTest";
    result =
        abilityAutoStartupService->GetAbilityData(autoStartupInfo, isVisible, abilityTypeName, accessTokenId, userId);
    EXPECT_TRUE(result);
    EXPECT_FALSE(isVisible);

    GTEST_LOG_(INFO) << "GetAbilityData_003 end";
}

/*
 * Feature: AbilityAutoStartupService
 * Function: InnerApplicationAutoStartupByEDM
 * SubFunction: NA
 * FunctionPoints: AbilityAutoStartupService InnerApplicationAutoStartupByEDM
 */
HWTEST_F(AbilityAutoStartupServiceSecondTest, InnerApplicationAutoStartupByEDM_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InnerApplicationAutoStartupByEDM_004 start";

    auto abilityAutoStartupService = std::make_shared<AbilityAutoStartupService>();
    EXPECT_NE(abilityAutoStartupService, nullptr);

    auto kvStorePtr = std::make_shared<MockSingleKvStore>();
    EXPECT_NE(kvStorePtr, nullptr);
    DelayedSingleton<AbilityAutoStartupDataManager>::GetInstance()->kvStorePtr_ = kvStorePtr;
    AbilityRuntime::AutoStartupInfo autoStartupInfo;
    autoStartupInfo.bundleName = "bundleNameTest";
    autoStartupInfo.abilityName = "nameTest";
    autoStartupInfo.moduleName = "moduleNameTest";
    autoStartupInfo.accessTokenId = 1;
    autoStartupInfo.appCloneIndex = 1;
    autoStartupInfo.userId = 1;

    int32_t result = abilityAutoStartupService->InnerApplicationAutoStartupByEDM(autoStartupInfo, true, true);
    EXPECT_EQ(result, 0);

    result = abilityAutoStartupService->InnerApplicationAutoStartupByEDM(autoStartupInfo, false, true);
    EXPECT_EQ(result, 0);

    result = abilityAutoStartupService->InnerApplicationAutoStartupByEDM(autoStartupInfo, false, false);
    EXPECT_EQ(result, 0);

    GTEST_LOG_(INFO) << "InnerApplicationAutoStartupByEDM_004 end";
}
} // namespace AAFwk
} // namespace OHOS
