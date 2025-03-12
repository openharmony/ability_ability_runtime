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

#define private public
#define protected public
#include "extension_base.h"
#include "ui_extension_record_factory.h"
#undef private
#undef protected
#include "hilog_tag_wrapper.h"
#include "mock_window.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS::Rosen;

namespace OHOS {
namespace AbilityRuntime {

namespace {
const std::string UIEXTENSION_ABILITY_ID = "ability.want.params.uiExtensionAbilityId";
}
class UIExtensionRecordFactoryTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    AbilityRequest GenerateAbilityRequest(const std::string& deviceName, const std::string& abilityName,
        const std::string& appName, const std::string& bundleName, const std::string& moduleName);
    sptr<SessionInfo> MockSessionInfo(int32_t persistentId);
};

void UIExtensionRecordFactoryTest::SetUpTestCase(void)
{}

void UIExtensionRecordFactoryTest::TearDownTestCase(void)
{}

void UIExtensionRecordFactoryTest::SetUp()
{}

void UIExtensionRecordFactoryTest::TearDown()
{}

AbilityRequest UIExtensionRecordFactoryTest::GenerateAbilityRequest(const std::string& deviceName,
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

sptr<SessionInfo> UIExtensionRecordFactoryTest::MockSessionInfo(int32_t persistentId)
{
    sptr<SessionInfo> sessionInfo = new (std::nothrow) SessionInfo();
    if (!sessionInfo) {
        TAG_LOGE(AAFwkTag::TEST, "sessionInfo is nullptr");
        return nullptr;
    }
    sessionInfo->persistentId = persistentId;
    Want want;
    const std::string type = "share";
    want.SetParam("ability.want.params.uiExtensionAbilityId", 1);
    sessionInfo->want = want;
    return sessionInfo;
}

/**
 * @tc.number: NeedReuse_0100
 * @tc.name: UIExtensionRecordFactoryTest
 * @tc.desc: Set UIEXTENSION_ABILITY_ID  not equal INVALID_EXTENSION_RECORD_ID
 */
HWTEST_F(UIExtensionRecordFactoryTest, NeedReuse_0100, TestSize.Level1)
{
    AbilityRuntime::UIExtensionRecordFactory info;
    AAFwk::AbilityRequest abilityRequest;
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    auto sessionInfo = MockSessionInfo(1);
    abilityRequest.sessionInfo = sessionInfo;
    int32_t extensionRecordId = 1;
    bool result = info.NeedReuse(abilityRequest, extensionRecordId);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: NeedReuse_0200
 * @tc.name: UIExtensionRecordFactoryTest
 * @tc.desc: Set UIEXTENSION_ABILITY_ID equal INVALID_EXTENSION_RECORD_ID
 */
HWTEST_F(UIExtensionRecordFactoryTest, NeedReuse_0200, TestSize.Level1)
{
    AbilityRuntime::UIExtensionRecordFactory info;
    AAFwk::AbilityRequest abilityRequest;
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    auto sessionInfo = MockSessionInfo(1);
    abilityRequest.sessionInfo = sessionInfo;
    abilityRequest.sessionInfo->want.SetParam(UIEXTENSION_ABILITY_ID, 0);
    int32_t extensionRecordId = 1;
    bool result = info.NeedReuse(abilityRequest, extensionRecordId);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: CreateRecord_0100
 * @tc.name: UIExtensionRecordFactoryTest
 * @tc.desc: Call function CreateRecord
 */
HWTEST_F(UIExtensionRecordFactoryTest, CreateRecord_0100, TestSize.Level1)
{
    AbilityRuntime::UIExtensionRecordFactory info;
    AAFwk::AbilityRequest abilityRequest;
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    auto sessionInfo = MockSessionInfo(1);
    abilityRequest.sessionInfo = sessionInfo;
    abilityRequest.sessionInfo->want.SetParam(UIEXTENSION_ABILITY_ID, 0);
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    auto extensionRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    int32_t result = info.CreateRecord(abilityRequest, extensionRecord);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: CreateRecord_0200
 * @tc.name: UIExtensionRecordFactoryTest
 * @tc.desc: Call function CreateRecord
 */
HWTEST_F(UIExtensionRecordFactoryTest, CreateRecord_0200, TestSize.Level1)
{
    AbilityRuntime::UIExtensionRecordFactory info;
    AAFwk::AbilityRequest abilityRequest;
    std::shared_ptr<ExtensionRecord> extensionRecord = nullptr;

    abilityRequest.extensionType == AppExecFwk::ExtensionAbilityType::EMBEDDED_UI;
    auto sessionInfo = MockSessionInfo(1);
    abilityRequest.sessionInfo = sessionInfo;

    std::shared_ptr<AbilityRecord> abilityRecord = nullptr;
    OHOS::sptr<OHOS::IRemoteObject> token = new OHOS::AAFwk::Token(abilityRecord);
    abilityRequest.sessionInfo->callerToken = token;
    auto result = info.CreateRecord(abilityRequest, extensionRecord);
    EXPECT_NE(extensionRecord, nullptr);
    EXPECT_NE(extensionRecord->abilityRecord_, nullptr);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: PreCheck_0100
 * @tc.name: UIExtensionRecordFactoryTest
 * @tc.desc: Call function PreCheck
 */
HWTEST_F(UIExtensionRecordFactoryTest, PreCheck_0100, TestSize.Level1)
{
    auto uiExtensionRecordFactory = std::make_shared<AbilityRuntime::UIExtensionRecordFactory>();
    AAFwk::AbilityRequest abilityRequest;
    std::string hostBundleName = "com.ohos.example.hostBundleName";
    abilityRequest.extensionType = ExtensionAbilityType::WORK_SCHEDULER;
    EXPECT_EQ(uiExtensionRecordFactory->PreCheck(abilityRequest, hostBundleName), ERR_OK);
}

/**
 * @tc.number: CreateDebugRecord_0100
 * @tc.name: UIExtensionRecordFactoryTest
 * @tc.desc: Call function CreateDebugRecord
 */
HWTEST_F(UIExtensionRecordFactoryTest, CreateDebugRecord_0200, TestSize.Level1)
{
    AbilityRuntime::UIExtensionRecordFactory info;
    AAFwk::AbilityRequest abilityRequest;
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    OHOS::sptr<OHOS::IRemoteObject> token = new OHOS::AAFwk::Token(abilityRecord);
    abilityRequest.callerToken = token;
    EXPECT_NO_THROW(info.CreateDebugRecord(abilityRequest, abilityRecord));
}
}
}
