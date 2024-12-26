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
constexpr const char* EXTENSION_NETWORK_ENABLE_FLAG = "network_acesss_enable_flag";
constexpr const char* EXTENSION_SA_ENABLE_FLAG = "sa_acesss_enable_flag";
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
    static std::shared_ptr<AAFwk::ExtensionConfig> extensionConfig_;
};

std::shared_ptr<AAFwk::ExtensionConfig> AbilityExtensionConfigTest::extensionConfig_ =
    DelayedSingleton<AAFwk::ExtensionConfig>::GetInstance();

void AbilityExtensionConfigTest::SetUpTestCase(void)
{}

void AbilityExtensionConfigTest::TearDownTestCase(void)
{}

void AbilityExtensionConfigTest::SetUp()
{}

void AbilityExtensionConfigTest::TearDown()
{}

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
 * @tc.number    : ReadFileInfoJson_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function ReadFileInfoJson CheckServiceExtensionUriValid IsExtensionStartServiceEnable
 */
HWTEST_F(AbilityExtensionConfigTest, ReadFileInfoJson_001, TestSize.Level1)
{
    extensionConfig_->IsExtensionStartServiceEnable("aa", "http://aaa/bb/cc/");
    extensionConfig_->CheckServiceExtensionUriValid("http://aaa/bb/");
    extensionConfig_->CheckServiceExtensionUriValid("http://aaa/bb/cc/");
    extensionConfig_->CheckServiceExtensionUriValid("http://aaa//cc/");
    nlohmann::json jsOne;
    auto result = extensionConfig_->ReadFileInfoJson("d://dddd", jsOne);
    EXPECT_EQ(result, false);
}

/*
 * @tc.number    : LoadExtensionNetworkEnable_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function LoadExtensionNetworkEnable
 */
HWTEST_F(AbilityExtensionConfigTest, LoadExtensionNetworkEnable_001, TestSize.Level1)
{
    json jsOnFile;
    jsOnFile[EXTENSION_NETWORK_ENABLE_FLAG] = true;
    extensionConfig_->LoadExtensionNetworkEnable(jsOnFile, "form");
    EXPECT_TRUE(extensionConfig_->networkEnableFlags_["form"]);
}

/*
 * @tc.number    : LoadExtensionSAEnable_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function LoadExtensionSAEnable
 */
HWTEST_F(AbilityExtensionConfigTest, LoadExtensionSAEnable_001, TestSize.Level1)
{
    json jsOnFile;
    jsOnFile[EXTENSION_SA_ENABLE_FLAG] = true;
    auto extType = "form";
    extensionConfig_->LoadExtensionSAEnable(jsOnFile, extType);
    EXPECT_TRUE(extensionConfig_->saEnableFlags_[extType]);
}

/*
 * @tc.number    : IsExtensionNetworkEnable_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionNetworkEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionNetworkEnable_001, TestSize.Level1)
{
    json jsOnFile;
    jsOnFile[EXTENSION_NETWORK_ENABLE_FLAG] = true;
    auto extType = "form";
    extensionConfig_->networkEnableFlags_[extType] = true;
    bool enable = extensionConfig_->IsExtensionNetworkEnable(extType);
    EXPECT_TRUE(enable);
}

/*
 * @tc.number    : IsExtensionSAEnable_001
 * @tc.name      : AbilityExtensionConfigTest
 * @tc.desc      : Test Function IsExtensionSAEnable
 */
HWTEST_F(AbilityExtensionConfigTest, IsExtensionSAEnable_001, TestSize.Level1)
{
    json jsOnFile;
    jsOnFile[EXTENSION_SA_ENABLE_FLAG] = true;
    auto extType = "form";
    extensionConfig_->saEnableFlags_[extType] = true;
    bool enable = extensionConfig_->IsExtensionSAEnable(extType);
    EXPECT_TRUE(enable);
}
}
}
