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

#include "ability_connect_manager.h"
#include "extension_record_factory.h"
#include "ability_util.h"
#include "hilog_tag_wrapper.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace {
const std::string VASSISTANT_BUNDLE_NAME = "com.huawei.hmos.vassistant";
const std::string VASSISTANT_B2 = "com.huawei.hmos.vassistant.test";
}

namespace OHOS {
namespace AAFwk {
class AbilityConnectManagerSecondTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    AbilityRequest GenerateAbilityRequest(const std::string& deviceName, const std::string& abilityName,
        const std::string& appName, const std::string& bundleName, const std::string& moduleName);

protected:
    AbilityRequest abilityRequest_{};
    std::shared_ptr<AbilityRecord> serviceRecord_{ nullptr };

private:
    std::shared_ptr<AbilityConnectManager> connectManager_;
};

AbilityRequest AbilityConnectManagerSecondTest::GenerateAbilityRequest(const std::string& deviceName,
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

void AbilityConnectManagerSecondTest::SetUpTestCase(void)
{}

void AbilityConnectManagerSecondTest::TearDownTestCase(void)
{}

void AbilityConnectManagerSecondTest::SetUp(void)
{
    connectManager_ = std::make_unique<AbilityConnectManager>(0);
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest_ = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    serviceRecord_ = AbilityRecord::CreateAbilityRecord(abilityRequest_);
}

void AbilityConnectManagerSecondTest::TearDown(void)
{
    serviceRecord_ = nullptr;
}

/*
 * Feature: AbilityConnectManager
 * Function: PreloadUIExtensionAbilityInner
 */
HWTEST_F(AbilityConnectManagerSecondTest, PreloadUIExtensionAbilityInner_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PreloadUIExtensionAbilityInner_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);
    std::string hostBundleName = "hostBundleName";
    int32_t hostPid = 1;

    auto res = connectManager->PreloadUIExtensionAbilityInner(abilityRequest_, hostBundleName, hostPid);
    EXPECT_EQ(res, ERR_WRONG_INTERFACE_CALL);

    abilityRequest_.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SHARE;
    res = connectManager->PreloadUIExtensionAbilityInner(abilityRequest_, hostBundleName, hostPid);
    EXPECT_EQ(res, ERR_OK);

    abilityRequest_.want.SetParam(Want::CREATE_APP_INSTANCE_KEY, true);
    res = connectManager->PreloadUIExtensionAbilityInner(abilityRequest_, hostBundleName, hostPid);
    EXPECT_EQ(res, ERR_INVALID_VALUE);

    abilityRequest_.want.SetParam(Want::CREATE_APP_INSTANCE_KEY, false);
    abilityRequest_.extensionType = AppExecFwk::ExtensionAbilityType::EMBEDDED_UI;
    res = connectManager->PreloadUIExtensionAbilityInner(abilityRequest_, hostBundleName, hostPid);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "PreloadUIExtensionAbilityInner_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetExtensionByIdFromTerminatingMap
 */
HWTEST_F(AbilityConnectManagerSecondTest, GetExtensionByIdFromTerminatingMap_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionByIdFromTerminatingMap_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);
    int64_t abilityRecordId = 1;

    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    connectManager->terminatingExtensionList_.push_back(nullptr);
    auto res = connectManager->GetExtensionByIdFromTerminatingMap(abilityRecordId);
    EXPECT_EQ(res, nullptr);

    connectManager->terminatingExtensionList_.push_back(abilityRecord);
    res = connectManager->GetExtensionByIdFromTerminatingMap(abilityRecordId);
    EXPECT_EQ(res, nullptr);

    abilityRecordId = abilityRecord->GetAbilityRecordId();
    res = connectManager->GetExtensionByIdFromTerminatingMap(abilityRecordId);
    EXPECT_NE(res, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionByIdFromTerminatingMap_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: ReportXiaoYiToRSSIfNeeded
 */
HWTEST_F(AbilityConnectManagerSecondTest, ReportXiaoYiToRSSIfNeeded_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionByIdFromTerminatingMap_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    abilityRequest_.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    auto res = connectManager->ReportXiaoYiToRSSIfNeeded(abilityRequest_.abilityInfo);
    EXPECT_EQ(res, ERR_OK);

    abilityRequest_.abilityInfo.type = AppExecFwk::AbilityType::UNKNOWN;
    abilityRequest_.abilityInfo.bundleName = VASSISTANT_BUNDLE_NAME;
    res = connectManager->ReportXiaoYiToRSSIfNeeded(abilityRequest_.abilityInfo);
    EXPECT_EQ(res, ERR_OK);

    abilityRequest_.abilityInfo.bundleName = VASSISTANT_B2;
    res = connectManager->ReportXiaoYiToRSSIfNeeded(abilityRequest_.abilityInfo);
    EXPECT_EQ(res, ERR_OK);

    abilityRequest_.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    abilityRequest_.abilityInfo.bundleName = VASSISTANT_BUNDLE_NAME;
    res = connectManager->ReportXiaoYiToRSSIfNeeded(abilityRequest_.abilityInfo);
    EXPECT_EQ(res, ERR_OK);

    TAG_LOGI(AAFwkTag::TEST, "ReportXiaoYiToRSSIfNeeded_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: UpdateKeepAliveEnableState
 */
HWTEST_F(AbilityConnectManagerSecondTest, UpdateKeepAliveEnableState_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "UpdateKeepAliveEnableState_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);
    std::string bundleName = "";
    std::string moduleName = "";
    std::string mainElement = "";
    bool updateEnable = false;

    abilityRequest_.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    auto res = connectManager->UpdateKeepAliveEnableState(bundleName, moduleName, mainElement, updateEnable);
    EXPECT_EQ(res, ERR_OK);

    std::string key = "testKey";
    connectManager->serviceMap_.emplace(key, serviceRecord_);
    res = connectManager->UpdateKeepAliveEnableState(bundleName, moduleName, mainElement, updateEnable);
    EXPECT_EQ(res, ERR_OK);

    bundleName = serviceRecord_->GetAbilityInfo().bundleName;
    res = connectManager->UpdateKeepAliveEnableState(bundleName, moduleName, mainElement, updateEnable);
    EXPECT_EQ(res, ERR_OK);

    mainElement = serviceRecord_->GetAbilityInfo().name;
    res = connectManager->UpdateKeepAliveEnableState(bundleName, moduleName, mainElement, updateEnable);
    EXPECT_EQ(res, ERR_OK);

    moduleName = serviceRecord_->GetAbilityInfo().moduleName;
    res = connectManager->UpdateKeepAliveEnableState(bundleName, moduleName, mainElement, updateEnable);
    EXPECT_EQ(res, ERR_OK);

    TAG_LOGI(AAFwkTag::TEST, "RUpdateKeepAliveEnableState_001 end");
}

}  // namespace AAFwk
}  // namespace OHOS
