/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "extension_config.h"
#undef private
#undef protected
#include "hilog_tag_wrapper.h"
#include "json_utils.h"

using namespace testing;
using namespace testing::ext;
using json = nlohmann::json;
namespace {
constexpr const char* EXTENSION_CONFIG_NAME = "extension_config_name";
constexpr const char* EXTENSION_TYPE_NAME = "extension_type_name";
constexpr const char* EXTENSION_AUTO_DISCONNECT_TIME = "auto_disconnect_time";

constexpr const char* EXTENSION_THIRD_PARTY_APP_BLOCKED_FLAG_NAME = "third_party_app_blocked_flag";
constexpr const char* EXTENSION_SERVICE_BLOCKED_LIST_NAME = "service_blocked_list";
constexpr const char* EXTENSION_SERVICE_STARTUP_ENABLE_FLAG = "service_startup_enable_flag";
}
namespace OHOS {
namespace AbilityRuntime {
class  AbilityExtensionConfigTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
public:
    void LoadTestConfig(const std::string &configStr);
    static std::shared_ptr<AAFwk::ExtensionConfig> extensionConfig_;
};

std::shared_ptr<AAFwk::ExtensionConfig> AbilityExtensionConfigTest::extensionConfig_ =
    DelayedSingleton<AAFwk::ExtensionConfig>::GetInstance();

void AbilityExtensionConfigTest::SetUpTestCase(void)
{}

void AbilityExtensionConfigTest::TearDownTestCase(void)
{}

void AbilityExtensionConfigTest::SetUp()
{
    extensionConfig_->configMap_.clear();
}

void AbilityExtensionConfigTest::TearDown()
{}

void AbilityExtensionConfigTest::LoadTestConfig(const std::string &configStr)
{
    nlohmann::json jsonConfig = nlohmann::json::parse(configStr);
    extensionConfig_->LoadExtensionConfig(jsonConfig);
}

/*
 * @tc.number    : GetExtensionConfigPath_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function GetExtensionConfigPath
 */
HWTEST_F(AbilityExtensionConfigTest, GetExtensionConfigPath_001, TestSize.Level1)
{
    extensionConfig_->GetExtensionConfigPath();
    extensionConfig_->LoadExtensionConfiguration();
    std::string  extensionTypeName = EXTENSION_TYPE_NAME;
    extensionConfig_->GetExtensionAutoDisconnectTime(extensionTypeName);
    auto result = extensionConfig_->IsExtensionStartThirdPartyAppEnable(extensionTypeName);
    EXPECT_EQ(result, true);
}

/*
 * @tc.number    : LoadExtensionServiceBlockedList_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function LoadExtensionServiceBlockedList
 */
HWTEST_F(AbilityExtensionConfigTest, LoadExtensionServiceBlockedList_001, TestSize.Level1)
{
    json jsOnFile;
    extensionConfig_->LoadExtensionServiceBlockedList(jsOnFile, "aa");
    jsOnFile[EXTENSION_SERVICE_STARTUP_ENABLE_FLAG] = false;
    extensionConfig_->LoadExtensionServiceBlockedList(jsOnFile, "aa");
    jsOnFile[EXTENSION_SERVICE_STARTUP_ENABLE_FLAG] = true;
    extensionConfig_->LoadExtensionServiceBlockedList(jsOnFile, "aa");
    jsOnFile[EXTENSION_SERVICE_BLOCKED_LIST_NAME] = {"aa", "bb"};
    extensionConfig_->LoadExtensionServiceBlockedList(jsOnFile, "aa");
    EXPECT_TRUE(extensionConfig_ != nullptr);
}

/*
 * @tc.number    : LoadExtensionThirdPartyAppBlockedList_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function LoadExtensionThirdPartyAppBlockedList
 */
HWTEST_F(AbilityExtensionConfigTest, LoadExtensionThirdPartyAppBlockedList_001, TestSize.Level1)
{
    json jsOnFile;
    std::string extensionTypeName = "aa";
    extensionConfig_->LoadExtensionThirdPartyAppBlockedList(jsOnFile, extensionTypeName);
    jsOnFile[EXTENSION_THIRD_PARTY_APP_BLOCKED_FLAG_NAME] = false;
    extensionConfig_->LoadExtensionThirdPartyAppBlockedList(jsOnFile, extensionTypeName);
    jsOnFile[EXTENSION_THIRD_PARTY_APP_BLOCKED_FLAG_NAME] = true;
    extensionConfig_->LoadExtensionThirdPartyAppBlockedList(jsOnFile, extensionTypeName);
    EXPECT_TRUE(extensionConfig_ != nullptr);
}

/*
 * @tc.number    : LoadExtensionAutoDisconnectTime_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function LoadExtensionAutoDisconnectTime
 */
HWTEST_F(AbilityExtensionConfigTest, LoadExtensionAutoDisconnectTime_001, TestSize.Level1)
{
    json jsOnFile;
    std::string extensionTypeName = "aa";
    extensionConfig_->LoadExtensionAutoDisconnectTime(jsOnFile, extensionTypeName);
    jsOnFile[EXTENSION_AUTO_DISCONNECT_TIME] = 100;
    extensionConfig_->LoadExtensionAutoDisconnectTime(jsOnFile, extensionTypeName);
    EXPECT_TRUE(extensionConfig_ != nullptr);
}

/*
 * @tc.number    : LoadExtensionConfig_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function LoadExtensionConfig
 */
HWTEST_F(AbilityExtensionConfigTest, LoadExtensionConfig_001, TestSize.Level1)
{
    json jsOnFile;
    json jsOnItem;
    json jsOnItem2;
    extensionConfig_->LoadExtensionConfig(jsOnFile);
    jsOnItem[EXTENSION_TYPE_NAME] = "aa";
    jsOnItem2[EXTENSION_TYPE_NAME] = "bb";
    jsOnFile[EXTENSION_CONFIG_NAME] = {jsOnItem, jsOnItem2, "cc"};
    extensionConfig_->LoadExtensionConfig(jsOnFile);
    EXPECT_TRUE(extensionConfig_ != nullptr);
}

/*
 * @tc.number    : IsExtensionStartServiceEnable_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartServiceEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartServiceEnable_001, TestSize.Level1)
{
    auto extType = "form";
    ASSERT_NE(extensionConfig_, nullptr);
    extensionConfig_->configMap_.clear();
    extensionConfig_->configMap_[extType].serviceEnableFlag = false;
    bool enable = extensionConfig_->IsExtensionStartServiceEnable(extType, "form");
    EXPECT_EQ(enable, false);
}

/*
 * @tc.number    : IsExtensionStartServiceEnable_002
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartServiceEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartServiceEnable_002, TestSize.Level1)
{
    auto extType = "form";
    ASSERT_NE(extensionConfig_, nullptr);
    extensionConfig_->configMap_.clear();
    extensionConfig_->configMap_[extType].serviceEnableFlag = true;
    bool enable = extensionConfig_->IsExtensionStartServiceEnable(extType, "bbb");
    EXPECT_EQ(enable, true);
}

/*
 * @tc.number    : IsExtensionStartServiceEnable_003
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartServiceEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartServiceEnable_003, TestSize.Level1)
{
    json jsOnFile;
    auto extType = "form";
    jsOnFile[EXTENSION_SERVICE_STARTUP_ENABLE_FLAG] = true;
    jsOnFile[EXTENSION_SERVICE_BLOCKED_LIST_NAME] = {"aa", "bb", "/bundle/module/ability"};
    extensionConfig_->LoadExtensionServiceBlockedList(jsOnFile, extType);
    // uri not valid
    bool enable = extensionConfig_->IsExtensionStartServiceEnable(extType, "bb");
    EXPECT_EQ(enable, true);
}

/*
 * @tc.number    : IsExtensionStartServiceEnable_004
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartServiceEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartServiceEnable_004, TestSize.Level1)
{
    json jsOnFile;
    auto extType = "form";
    jsOnFile[EXTENSION_SERVICE_STARTUP_ENABLE_FLAG] = true;
    jsOnFile[EXTENSION_SERVICE_BLOCKED_LIST_NAME] = {"aa", "bb", "/bundle/module/ability"};
    extensionConfig_->LoadExtensionServiceBlockedList(jsOnFile, extType);
    // uri is valid
    bool enable = extensionConfig_->IsExtensionStartServiceEnable(extType, "/bundle/module/ability");
    EXPECT_EQ(enable, false);
}

/*
 * @tc.number    : ReadFileInfoJson_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function ReadFileInfoJson
 */
HWTEST_F(AbilityExtensionConfigTest, ReadFileInfoJson_001, TestSize.Level1)
{
    nlohmann::json jsOne;
    auto result = extensionConfig_->ReadFileInfoJson("d://dddd", jsOne);
    EXPECT_EQ(result, false);
}

/*
 * @tc.number    : CheckExtensionUriValid_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function CheckExtensionUriValid
 */
HWTEST_F(AbilityExtensionConfigTest, CheckExtensionUriValid_001, TestSize.Level1)
{
    auto result = extensionConfig_->CheckExtensionUriValid("http://aaa/bb/");
    EXPECT_EQ(result, false);
    result = extensionConfig_->CheckExtensionUriValid("http://aaa/bb/cc/");
    EXPECT_EQ(result, false);
    result = extensionConfig_->CheckExtensionUriValid("http://aaa//cc/");
    EXPECT_EQ(result, false);
    result = extensionConfig_->CheckExtensionUriValid("/bundleName/moduleName/abilityName");
    EXPECT_EQ(result, true);
    result = extensionConfig_->CheckExtensionUriValid("deviceName/bundleName/moduleName/abilityName");
    EXPECT_EQ(result, true);
    AppExecFwk::ElementName targetElementName;
    EXPECT_EQ(targetElementName.ParseURI("deviceName/bundleName/moduleName/abilityName"), true);
    EXPECT_EQ(targetElementName.GetBundleName(), "bundleName");
    EXPECT_EQ(targetElementName.GetModuleName(), "moduleName");
    EXPECT_EQ(targetElementName.GetAbilityName(), "abilityName");
}

/*
 * @tc.number    : GetExtensionAutoDisconnectTime_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function GetExtensionAutoDisconnectTime
 */
HWTEST_F(AbilityExtensionConfigTest, GetExtensionAutoDisconnectTime_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionAutoDisconnectTime_001 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "auto_disconnect_time": 5000
        }]
    })";
    LoadTestConfig(configStr);
    auto disconnectTime = extensionConfig_->GetExtensionAutoDisconnectTime("form");
    EXPECT_EQ(disconnectTime, 5000);
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionAutoDisconnectTime_001 end.");
}

/*
 * @tc.number    : GetExtensionAutoDisconnectTime_002
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function GetExtensionAutoDisconnectTime
 */
HWTEST_F(AbilityExtensionConfigTest, GetExtensionAutoDisconnectTime_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionAutoDisconnectTime_002 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form"
        }]
    })";
    LoadTestConfig(configStr);
    auto disconnectTime = extensionConfig_->GetExtensionAutoDisconnectTime("form");
    EXPECT_EQ(disconnectTime, -1);
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionAutoDisconnectTime_002 end.");
}

/*
 * @tc.number    : GetExtensionAutoDisconnectTime_003
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function GetExtensionAutoDisconnectTime
 */
HWTEST_F(AbilityExtensionConfigTest, GetExtensionAutoDisconnectTime_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionAutoDisconnectTime_003 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "auto_disconnect_time": "invalid_value"
        }]
    })";
    LoadTestConfig(configStr);
    auto disconnectTime = extensionConfig_->GetExtensionAutoDisconnectTime("form");
    EXPECT_EQ(disconnectTime, -1);
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionAutoDisconnectTime_003 end.");
}

/*
 * @tc.number    : GetExtensionAutoDisconnectTime_004
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function GetExtensionAutoDisconnectTime
 */
HWTEST_F(AbilityExtensionConfigTest, GetExtensionAutoDisconnectTime_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionAutoDisconnectTime_004 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": 2,
            "auto_disconnect_time": "invalid_value"
        }]
    })";
    LoadTestConfig(configStr);
    auto disconnectTime = extensionConfig_->GetExtensionAutoDisconnectTime("form");
    EXPECT_EQ(disconnectTime, -1);
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionAutoDisconnectTime_004 end.");
}

/*
 * @tc.number    : GetExtensionAutoDisconnectTime_005
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function GetExtensionAutoDisconnectTime
 */
HWTEST_F(AbilityExtensionConfigTest, GetExtensionAutoDisconnectTime_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionAutoDisconnectTime_005 start.");
    const std::string configStr = R"({
        "ams_extension_config": []
    })";
    LoadTestConfig(configStr);
    auto disconnectTime = extensionConfig_->GetExtensionAutoDisconnectTime("form");
    EXPECT_EQ(disconnectTime, -1);
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionAutoDisconnectTime_005 end.");
}

/*
 * @tc.number    : LoadExtensionAbilityAccess_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function LoadExtensionAbilityAccess
 */
HWTEST_F(AbilityExtensionConfigTest, LoadExtensionAbilityAccess_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_001 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form"
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    auto flag = extensionConfig_->configMap_["form"].abilityAccess.thirdPartyAppAccessFlag;
    EXPECT_EQ(flag, std::nullopt);
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_001 end.");
}

/*
 * @tc.number    : LoadExtensionAbilityAccess_002
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function LoadExtensionAbilityAccess
 */
HWTEST_F(AbilityExtensionConfigTest, LoadExtensionAbilityAccess_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_002 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : 1
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    auto flag = extensionConfig_->configMap_["form"].abilityAccess.thirdPartyAppAccessFlag;
    EXPECT_EQ(flag, std::nullopt);
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_002 end.");
}

/*
 * @tc.number    : LoadExtensionAbilityAccess_003
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function LoadExtensionAbilityAccess
 */
HWTEST_F(AbilityExtensionConfigTest, LoadExtensionAbilityAccess_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_003 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {}
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    auto flag = extensionConfig_->configMap_["form"].abilityAccess.thirdPartyAppAccessFlag;
    EXPECT_EQ(flag, std::nullopt);
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_003 end.");
}

/*
 * @tc.number    : LoadExtensionAbilityAccess_004
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function LoadExtensionAbilityAccess
 */
HWTEST_F(AbilityExtensionConfigTest, LoadExtensionAbilityAccess_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_004 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "third_party_app_access_flag": "invalid_value",
                "allowlist" : "invalid_value"
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);

    auto &abilityAccess = extensionConfig_->configMap_["form"].abilityAccess;
    auto flag = abilityAccess.thirdPartyAppAccessFlag;
    EXPECT_EQ(flag, std::nullopt);
    auto allowListSize = abilityAccess.allowList.size();
    EXPECT_EQ(allowListSize, 0);
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_004 end.");
}

/*
 * @tc.number    : LoadExtensionAbilityAccess_005
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function LoadExtensionAbilityAccess
 */
HWTEST_F(AbilityExtensionConfigTest, LoadExtensionAbilityAccess_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_005 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "allowlist" : []
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);

    auto &abilityAccess = extensionConfig_->configMap_["form"].abilityAccess;
    auto allowListSize = abilityAccess.allowList.size();
    EXPECT_EQ(allowListSize, 0);
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_005 end.");
}

/*
 * @tc.number    : LoadExtensionAbilityAccess_006
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function LoadExtensionAbilityAccess
 */
HWTEST_F(AbilityExtensionConfigTest, LoadExtensionAbilityAccess_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_006 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "allowlist" : [123]
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);

    auto &abilityAccess = extensionConfig_->configMap_["form"].abilityAccess;
    auto allowListSize = abilityAccess.allowList.size();
    EXPECT_EQ(allowListSize, 0);
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_006 end.");
}

/*
 * @tc.number    : LoadExtensionAbilityAccess_007
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function LoadExtensionAbilityAccess
 */
HWTEST_F(AbilityExtensionConfigTest, LoadExtensionAbilityAccess_007, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_007 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "allowlist" : [123]
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);

    auto &abilityAccess = extensionConfig_->configMap_["form"].abilityAccess;
    auto allowListSize = abilityAccess.allowList.size();
    EXPECT_EQ(allowListSize, 0);
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_007 end.");
}

/*
 * @tc.number    : LoadExtensionAbilityAccess_008
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function LoadExtensionAbilityAccess
 */
HWTEST_F(AbilityExtensionConfigTest, LoadExtensionAbilityAccess_008, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_008 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "allowlist" : ["invalidUrl"]
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);

    auto &abilityAccess = extensionConfig_->configMap_["form"].abilityAccess;
    auto allowListSize = abilityAccess.allowList.size();
    EXPECT_EQ(allowListSize, 0);
    TAG_LOGI(AAFwkTag::TEST, "LoadExtensionAbilityAccess_008 end.");
}

/*
 * @tc.number    : HasAbilityAccess_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function HasAbilityAccess
 */
HWTEST_F(AbilityExtensionConfigTest, HasAbilityAccess_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HasAbilityAccess_001 start.");
    const std::string configStr = R"({
        "ams_extension_config": []
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);

    bool result = extensionConfig_->HasAbilityAccess("form");
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "HasAbilityAccess_001 end.");
}

/*
 * @tc.number    : HasAbilityAccess_002
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function HasAbilityAccess
 */
HWTEST_F(AbilityExtensionConfigTest, HasAbilityAccess_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HasAbilityAccess_002 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access": {
                "third_party_app_access_flag": false
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);

    bool result = extensionConfig_->HasAbilityAccess("form");
    EXPECT_TRUE(result);
    TAG_LOGI(AAFwkTag::TEST, "HasAbilityAccess_002 end.");
}

/*
 * @tc.number    : HasThridPartyAppAccessFlag_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function HasThridPartyAppAccessFlag
 */
HWTEST_F(AbilityExtensionConfigTest, HasThridPartyAppAccessFlag_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HasThridPartyAppAccessFlag_001 start.");
    const std::string configStr = R"({
        "ams_extension_config": []
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);

    bool result = extensionConfig_->HasThridPartyAppAccessFlag("form");
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "HasThridPartyAppAccessFlag_001 end.");
}

/*
 * @tc.number    : HasThridPartyAppAccessFlag_002
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function HasThridPartyAppAccessFlag
 */
HWTEST_F(AbilityExtensionConfigTest, HasThridPartyAppAccessFlag_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HasThridPartyAppAccessFlag_002 start.");

    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form"
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);

    bool result = extensionConfig_->HasThridPartyAppAccessFlag("form");
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "HasThridPartyAppAccessFlag_002 end.");
}

/*
 * @tc.number    : HasThridPartyAppAccessFlag_003
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function HasThridPartyAppAccessFlag
 */
HWTEST_F(AbilityExtensionConfigTest, HasThridPartyAppAccessFlag_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HasThridPartyAppAccessFlag_003 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {}
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);

    bool result = extensionConfig_->HasThridPartyAppAccessFlag("form");
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "HasThridPartyAppAccessFlag_003 end.");
}

/*
 * @tc.number    : HasThridPartyAppAccessFlag_004
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function HasThridPartyAppAccessFlag
 */
HWTEST_F(AbilityExtensionConfigTest, HasThridPartyAppAccessFlag_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HasThridPartyAppAccessFlag_004 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "third_party_app_access_flag": false
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);

    bool result = extensionConfig_->HasThridPartyAppAccessFlag("form");
    EXPECT_TRUE(result);
    TAG_LOGI(AAFwkTag::TEST, "HasThridPartyAppAccessFlag_004 end.");
}

/*
 * @tc.number    : HasServiceAccessFlag_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function HasServiceAccessFlag
 */
HWTEST_F(AbilityExtensionConfigTest, HasServiceAccessFlag_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HasServiceAccessFlag_001 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "service_access_flag": false
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);

    bool result = extensionConfig_->HasServiceAccessFlag("form");
    EXPECT_TRUE(result);
    TAG_LOGI(AAFwkTag::TEST, "HasServiceAccessFlag_001 end.");
}

/*
 * @tc.number    : HasDefaultAccessFlag_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function HasDefaultAccessFlag
 */
HWTEST_F(AbilityExtensionConfigTest, HasDefaultAccessFlag_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HasDefaultAccessFlag_001 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "default_access_flag": false
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);

    bool result = extensionConfig_->HasDefaultAccessFlag("form");
    EXPECT_TRUE(result);
    TAG_LOGI(AAFwkTag::TEST, "HasDefaultAccessFlag_001 end.");
}

/*
 * @tc.number    : IsExtensionStartThirdPartyAppEnableNew_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartThirdPartyAppEnableNew
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartThirdPartyAppEnableNew_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_001 start.");
    const std::string configStr = R"({
        "ams_extension_config": []
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);

    bool enable = extensionConfig_->IsExtensionStartThirdPartyAppEnableNew("form",
        "/com.acts.helloworld/entry/AllowAbility1");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_001 end.");
}

/*
 * @tc.number    : IsExtensionStartThirdPartyAppEnableNew_002
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartThirdPartyAppEnableNew
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartThirdPartyAppEnableNew_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_002 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {}
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartThirdPartyAppEnableNew("form",
        "/com.acts.helloworld/entry/AllowAbility1");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_002 end.");
}

/*
 * @tc.number    : IsExtensionStartThirdPartyAppEnableNew_003
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartThirdPartyAppEnableNew
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartThirdPartyAppEnableNew_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_003 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "third_party_app_access_flag": false
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartThirdPartyAppEnableNew("form", "invalid_uri");
    EXPECT_FALSE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_003 end.");
}

/*
 * @tc.number    : IsExtensionStartThirdPartyAppEnableNew_004
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartThirdPartyAppEnableNew
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartThirdPartyAppEnableNew_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_004 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "third_party_app_access_flag": true
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartThirdPartyAppEnableNew("form", "invalid_uri");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_004 end.");
}

/*
 * @tc.number    : IsExtensionStartThirdPartyAppEnableNew_005
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartThirdPartyAppEnableNew
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartThirdPartyAppEnableNew_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_005 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "third_party_app_access_flag": true,
                "blocklist" : ["/com.acts.helloworld2/entry/BlockAbility1"]
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartThirdPartyAppEnableNew("form",
        "/com.acts.helloworld/entry/BlockAbility1");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_005 end.");
}

/*
 * @tc.number    : IsExtensionStartThirdPartyAppEnableNew_006
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartThirdPartyAppEnableNew
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartThirdPartyAppEnableNew_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_006 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "third_party_app_access_flag": true,
                "blocklist" : ["/com.acts.helloworld/entry/BlockAbility2"]
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartThirdPartyAppEnableNew("form",
        "/com.acts.helloworld/entry/BlockAbility1");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_006 end.");
}

/*
 * @tc.number    : IsExtensionStartThirdPartyAppEnableNew_007
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartThirdPartyAppEnableNew
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartThirdPartyAppEnableNew_007, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_007 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "third_party_app_access_flag": true,
                "blocklist" : ["/com.acts.helloworld/entry/BlockAbility1"]
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartThirdPartyAppEnableNew("form",
        "/com.acts.helloworld/entry/BlockAbility1");
    EXPECT_FALSE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_007 end.");
}

/*
 * @tc.number    : IsExtensionStartThirdPartyAppEnableNew_008
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartThirdPartyAppEnableNew
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartThirdPartyAppEnableNew_008, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_008 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "third_party_app_access_flag": true,
                "blocklist" : []
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartThirdPartyAppEnableNew("form",
        "/com.acts.helloworld/entry/BlockAbility1");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_008 end.");
}

/*
 * @tc.number    : IsExtensionStartThirdPartyAppEnableNew_009
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartThirdPartyAppEnableNew
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartThirdPartyAppEnableNew_009, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_009 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "third_party_app_access_flag": false,
                "allowlist" : ["/com.acts.helloworld/entry/AllowAbility1"]
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartThirdPartyAppEnableNew("form",
        "/com.acts.helloworld/entry/AllowAbility1");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_009 end.");
}

/*
 * @tc.number    : IsExtensionStartThirdPartyAppEnableNew_010
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartThirdPartyAppEnableNew
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartThirdPartyAppEnableNew_010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_010 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "third_party_app_access_flag": false,
                "allowlist" : []
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartThirdPartyAppEnableNew("form",
        "/com.acts.helloworld/entry/AllowAbility1");
    EXPECT_FALSE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartThirdPartyAppEnableNew_010 end.");
}

/*
 * @tc.number    : IsExtensionStartServiceEnableNew_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartServiceEnableNew
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartServiceEnableNew_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartServiceEnableNew_001 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "service_access_flag": true,
                "blocklist" : ["/com.acts.helloworld/entry/BlockAbility1"]
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartServiceEnableNew("form",
        "/com.acts.helloworld/entry/BlockAbility1");
    EXPECT_FALSE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartServiceEnableNew_001 end.");
}

/*
 * @tc.number    : IsExtensionStartServiceEnableNew_002
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartServiceEnableNew
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartServiceEnableNew_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartServiceEnableNew_002 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "service_access_flag": true,
                "blocklist" : []
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartServiceEnableNew("form",
        "/com.acts.helloworld/entry/BlockAbility1");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartServiceEnableNew_002 end.");
}

/*
 * @tc.number    : IsExtensionStartServiceEnableNew_003
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartServiceEnableNew
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartServiceEnableNew_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartServiceEnableNew_003 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "service_access_flag": false,
                "allowlist" : ["/com.acts.helloworld/entry/AllowAbility1"]
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartServiceEnableNew("form",
        "/com.acts.helloworld/entry/AllowAbility1");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartServiceEnableNew_003 end.");
}

/*
 * @tc.number    : IsExtensionStartServiceEnableNew_004
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartServiceEnableNew
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartServiceEnableNew_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartServiceEnableNew_004 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "service_access_flag": false,
                "allowlist" : []
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartServiceEnableNew("form",
        "/com.acts.helloworld/entry/AllowAbility1");
    EXPECT_FALSE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartServiceEnableNew_004 end.");
}

/*
 * @tc.number    : IsExtensionStartDefaultEnable_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartDefaultEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartDefaultEnable_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartDefaultEnable_001 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "default_access_flag": true,
                "blocklist" : ["/com.acts.helloworld/entry/BlockAbility1"]
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartDefaultEnable("form",
        "/com.acts.helloworld/entry/BlockAbility1");
    EXPECT_FALSE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartDefaultEnable_001 end.");
}

/*
 * @tc.number    : IsExtensionStartDefaultEnable_002
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartDefaultEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartDefaultEnable_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartDefaultEnable_002 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "default_access_flag": true,
                "blocklist" : []
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartDefaultEnable("form",
        "/com.acts.helloworld/entry/BlockAbility1");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartDefaultEnable_002 end.");
}

/*
 * @tc.number    : IsExtensionStartDefaultEnable_003
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartDefaultEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartDefaultEnable_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartDefaultEnable_003 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "default_access_flag": false,
                "allowlist" : ["/com.acts.helloworld/entry/AllowAbility1"]
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartDefaultEnable("form",
        "/com.acts.helloworld/entry/AllowAbility1");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartDefaultEnable_003 end.");
}

/*
 * @tc.number    : IsExtensionStartDefaultEnable_004
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionStartDefaultEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionStartDefaultEnable_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartDefaultEnable_004 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "ability_access" : {
                "default_access_flag": false,
                "allowlist" : []
            }
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionStartDefaultEnable("form",
        "/com.acts.helloworld/entry/AllowAbility1");
    EXPECT_FALSE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionStartDefaultEnable_004 end.");
}

/*
 * @tc.number    : IsExtensionNetworkEnable_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionNetworkEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionNetworkEnable_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionNetworkEnable_001 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "network_access_enable_flag": true
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionNetworkEnable("form");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionNetworkEnable_001 end.");
}

/*
 * @tc.number    : IsExtensionNetworkEnable_002
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionNetworkEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionNetworkEnable_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionNetworkEnable_002 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "network_access_enable_flag": "invalid_value"
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionNetworkEnable("form");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionNetworkEnable_001 end.");
}

/*
 * @tc.number    : IsExtensionNetworkEnable_003
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionNetworkEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionNetworkEnable_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionNetworkEnable_003 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "network_access_enable_flag": false
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionNetworkEnable("form");
    EXPECT_FALSE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionNetworkEnable_003 end.");
}

/*
 * @tc.number    : IsExtensionSAEnable_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionSAEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionSAEnable_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionSAEnable_001 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "sa_access_enable_flag": true
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionSAEnable("form");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionSAEnable_001 end.");
}

/*
 * @tc.number    : IsExtensionSAEnable_002
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionSAEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionSAEnable_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionSAEnable_002 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "sa_access_enable_flag": "invalid_value"
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionSAEnable("form");
    EXPECT_TRUE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionSAEnable_002 end.");
}

/*
 * @tc.number    : IsExtensionSAEnable_003
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionSAEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionSAEnable_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionSAEnable_003 start.");
    const std::string configStr = R"({
        "ams_extension_config": [{
            "name": "FormExtension",
            "extension_type_name": "form",
            "sa_access_enable_flag": false
        }]
    })";
    ASSERT_NE(extensionConfig_, nullptr);
    LoadTestConfig(configStr);
    bool enable = extensionConfig_->IsExtensionSAEnable("form");
    EXPECT_FALSE(enable);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionSAEnable_003 end.");
}
}
}
