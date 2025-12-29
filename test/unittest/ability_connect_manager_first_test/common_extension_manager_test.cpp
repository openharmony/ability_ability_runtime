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
#include <memory>

#define private public
#define protected public
#include "common_extension_manager.h"
#undef private
#undef protected

#include "ability_config.h"
#include "ability_manager_errors.h"
#include "ability_util.h"
#include "hilog_tag_wrapper.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
namespace {
constexpr uint32_t FAKE_TOKENID = 111;
}
class CommonExtensionManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    AbilityRequest GenerateAbilityRequest(const std::string& deviceName, const std::string& abilityName,
        const std::string& appName, const std::string& bundleName, const std::string& moduleName);
};

void CommonExtensionManagerTest::SetUpTestCase()
{}

void CommonExtensionManagerTest::TearDownTestCase()
{}

void CommonExtensionManagerTest::SetUp()
{}

void CommonExtensionManagerTest::TearDown(void)
{}

AbilityRequest CommonExtensionManagerTest::GenerateAbilityRequest(const std::string& deviceName,
    const std::string& abilityName, const std::string& appName, const std::string& bundleName,
    const std::string& moduleName)
{
    ElementName element(deviceName, bundleName, abilityName, moduleName);
    Want want;
    want.SetElement(element);

    AbilityInfo abilityInfo;
    abilityInfo.visible = true;
    abilityInfo.applicationName = appName;
    abilityInfo.type = AbilityType::SERVICE;
    abilityInfo.name = abilityName;
    abilityInfo.bundleName = bundleName;
    abilityInfo.moduleName = moduleName;
    abilityInfo.deviceId = deviceName;
    ApplicationInfo appinfo;
    appinfo.name = appName;
    abilityInfo.applicationInfo = appinfo;
    AbilityRequest abilityRequest;
    abilityRequest.want = want;
    abilityRequest.abilityInfo = abilityInfo;
    abilityRequest.appInfo = appinfo;
    abilityInfo.process = bundleName;

    return abilityRequest;
}

/*
 * Feature: CommonExtensionManager
 * Function: GetOrCreateServiceRecord
 */
HWTEST_F(CommonExtensionManagerTest, GetOrCreateServiceRecord_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetOrCreateServiceRecord_001 start");
    auto connectManager = std::make_shared<CommonExtensionManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI_SERVICE;
    abilityRequest.abilityInfo.bundleName = "com.example.test";
    abilityRequest.abilityInfo.name = "TestAbility";

    std::shared_ptr<BaseExtensionRecord> serviceRecord = nullptr;
    bool isLoadedAbility = false;
    connectManager->GetOrCreateServiceRecord(abilityRequest, false, serviceRecord, isLoadedAbility);

    ASSERT_NE(serviceRecord, nullptr);
    EXPECT_EQ(serviceRecord->GetAbilityInfo().name, "TestAbility");
    TAG_LOGI(AAFwkTag::TEST, "GetOrCreateServiceRecord_001 end");
}

/*
 * Feature: CommonExtensionManager
 * Function: SetServiceAfterNewCreate
 */
HWTEST_F(CommonExtensionManagerTest, SetServiceAfterNewCreate_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetServiceAfterNewCreate_001 start");
    auto connectManager = std::make_shared<CommonExtensionManager>(0);
    std::string deviceName = "device";
    std::string abilityName = AbilityConfig::LAUNCHER_ABILITY_NAME;
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    auto abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    auto targetService = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest);

    connectManager->SetServiceAfterNewCreate(abilityRequest, *targetService);
    EXPECT_TRUE(targetService->IsLauncherRoot());
}

/*
 * Feature: CommonExtensionManager
 * Function: SetServiceAfterNewCreate
 */
HWTEST_F(CommonExtensionManagerTest, SetServiceAfterNewCreate_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetServiceAfterNewCreate_002 start");
    auto connectManager = std::make_shared<CommonExtensionManager>(0);
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    auto abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    auto targetService = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest);
    targetService->SetKeepAliveBundle(true);

    connectManager->SetServiceAfterNewCreate(abilityRequest, *targetService);
    EXPECT_FALSE(targetService->IsLauncherRoot());
}

/*
 * Feature: CommonExtensionManager
 * Function: SetServiceAfterNewCreate
 */
HWTEST_F(CommonExtensionManagerTest, SetServiceAfterNewCreate_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetServiceAfterNewCreate_003 start");
    auto connectManager = std::make_shared<CommonExtensionManager>(0);
    std::string deviceName = "device";
    std::string abilityName = AbilityConfig::SCENEBOARD_ABILITY_NAME;
    std::string appName = "hiservcie";
    std::string bundleName = AbilityConfig::SCENEBOARD_BUNDLE_NAME;
    std::string moduleName = "entry";
    auto abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    auto targetService = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest);
    abilityRequest.appInfo.accessTokenId = FAKE_TOKENID;
    connectManager->SetServiceAfterNewCreate(abilityRequest, *targetService);
    EXPECT_EQ(connectManager->sceneBoardTokenId_, FAKE_TOKENID);
}

/*
 * Feature: CommonExtensionManager
 * Function: SetServiceAfterNewCreate
 */
HWTEST_F(CommonExtensionManagerTest, SetServiceAfterNewCreate_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetServiceAfterNewCreate_004 start");
    auto connectManager = std::make_shared<CommonExtensionManager>(0);
    std::string deviceName = "device";
    std::string abilityName = AbilityConfig::SCENEBOARD_ABILITY_NAME;
    std::string appName = "hiservcie";
    std::string bundleName = AbilityConfig::SCENEBOARD_BUNDLE_NAME;
    std::string moduleName = "entry";
    auto abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    abilityRequest.restart = true;
    auto targetService = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest);
    abilityRequest.appInfo.accessTokenId = FAKE_TOKENID;
    connectManager->SetServiceAfterNewCreate(abilityRequest, *targetService);
    EXPECT_EQ(connectManager->sceneBoardTokenId_, FAKE_TOKENID);
}

/*
 * Feature: CommonExtensionManager
 * Function: SetServiceAfterNewCreate
 */
HWTEST_F(CommonExtensionManagerTest, SetServiceAfterNewCreate_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetServiceAfterNewCreate_005 start");
    auto connectManager = std::make_shared<CommonExtensionManager>(0);
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    auto abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    abilityRequest.restart = true;
    auto targetService = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest);
    targetService->SetKeepAliveBundle(true);

    connectManager->SetServiceAfterNewCreate(abilityRequest, *targetService);
    EXPECT_FALSE(targetService->IsLauncherRoot());
}
}  // namespace AAFwk
}  // namespace OHOS
