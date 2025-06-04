/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "extension_manager_client.h"
#undef private
#include "ability_manager_client.h"
#include "appexecfwk_errors.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {

class ExtensionManagerClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ExtensionManagerClientTest::SetUpTestCase(void)
{}
void ExtensionManagerClientTest::TearDownTestCase(void)
{}
void ExtensionManagerClientTest::SetUp(void)
{}
void ExtensionManagerClientTest::TearDown(void)
{}

/*
 * Feature: ExtensionManagerClient
 * Function: GetInstance
 */
HWTEST_F(ExtensionManagerClientTest, ExtensionManagerClientTest_001, TestSize.Level1)
{
    auto client = std::make_shared<ExtensionManagerClient>();
    EXPECT_TRUE(client != nullptr);
    client->GetInstance();
}

/*
 * Feature: ExtensionManagerClient
 * Function: GetExtensionManager
 */
HWTEST_F(ExtensionManagerClientTest, ExtensionManagerClientTest_002, TestSize.Level1)
{
    auto client = std::make_shared<ExtensionManagerClient>();
    EXPECT_NE(client->GetExtensionManager(), nullptr);
}

/*
 * Feature: ExtensionManagerClient
 * Function: Connect
 */
HWTEST_F(ExtensionManagerClientTest, ExtensionManagerClientTest_003, TestSize.Level1)
{
    auto client = std::make_shared<ExtensionManagerClient>();
    EXPECT_TRUE(client != nullptr);
    client->Connect();
}

/*
 * Feature: ExtensionManagerClient
 * Function: ResetProxy
 */
HWTEST_F(ExtensionManagerClientTest, ExtensionManagerClientTest_004, TestSize.Level1)
{
    auto client = std::make_shared<ExtensionManagerClient>();
    EXPECT_TRUE(client != nullptr);
    wptr<IRemoteObject> remote = nullptr;
    client->ResetProxy(remote);
}

/*
 * Feature: ExtensionManagerClient
 * Function: OnRemoteDied
 */
HWTEST_F(ExtensionManagerClientTest, ExtensionManagerClientTest_005, TestSize.Level1)
{
    auto client = std::make_shared<ExtensionManagerClient>();
    EXPECT_TRUE(client != nullptr);
    auto deathRecipient = new ExtensionManagerClient::ExtensionMgrDeathRecipient();
    wptr<IRemoteObject> remote = nullptr;
    deathRecipient->OnRemoteDied(remote);
}

/*
 * Feature: ExtensionManagerClient
 * Function: ConnectServiceExtensionAbility
 */
HWTEST_F(ExtensionManagerClientTest, ExtensionManagerClientTest_006, TestSize.Level1)
{
    auto client = std::make_shared<ExtensionManagerClient>();
    Want want;
    sptr<IRemoteObject> connect;
    int32_t userId = 0;
    auto result = client->ConnectServiceExtensionAbility(want, connect, userId);
    EXPECT_TRUE(result != ERR_OK);
}

/*
 * Feature: ExtensionManagerClient
 * Function: ConnectServiceExtensionAbility
 */
HWTEST_F(ExtensionManagerClientTest, ExtensionManagerClientTest_007, TestSize.Level1)
{
    auto client = std::make_shared<ExtensionManagerClient>();
    Want want;
    sptr<IRemoteObject> connect;
    sptr<IRemoteObject> callerToken;
    int32_t userId = 0;
    auto result = client->ConnectServiceExtensionAbility(want, connect, callerToken, userId);
    EXPECT_TRUE(result != ERR_OK);
}

/*
 * Feature: ExtensionManagerClient
 * Function: ConnectExtensionAbility
 */
HWTEST_F(ExtensionManagerClientTest, ExtensionManagerClientTest_008, TestSize.Level1)
{
    auto client = std::make_shared<ExtensionManagerClient>();
    Want want;
    sptr<IRemoteObject> connect;
    int32_t userId = 0;
    auto result = client->ConnectExtensionAbility(want, connect, userId);
    EXPECT_TRUE(result != ERR_OK);
}

/*
 * Feature: ExtensionManagerClient
 * Function: DisconnectAbility
 */
HWTEST_F(ExtensionManagerClientTest, ExtensionManagerClientTest_009, TestSize.Level1)
{
    auto client = std::make_shared<ExtensionManagerClient>();
    sptr<IRemoteObject> connect;
    auto result = client->DisconnectAbility(connect);
    EXPECT_TRUE(result != ERR_OK);
}

/*
 * Feature: ExtensionManagerClient
 * Function: ConnectEnterpriseAdminExtensionAbility
 */
HWTEST_F(ExtensionManagerClientTest, ExtensionManagerClientTest_010, TestSize.Level1)
{
    auto client = std::make_shared<ExtensionManagerClient>();
    
    Want want;
    sptr<IRemoteObject> connect;
    sptr<IRemoteObject> callerToken;
    int32_t userId = 1;
    auto result = client->ConnectEnterpriseAdminExtensionAbility(want, connect, callerToken, userId);
    EXPECT_TRUE(result != ERR_OK);
}

/*
 * Feature: ExtensionManagerClient
 * Function: StartExtensionAbility
 */
HWTEST_F(ExtensionManagerClientTest, StartExtensionAbility_0100, TestSize.Level1)
{
    auto client = std::make_shared<ExtensionManagerClient>();
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t userId = DEFAULT_INVAL_VALUE;
    AppExecFwk::ExtensionAbilityType extensionType = AppExecFwk::ExtensionAbilityType::UNSPECIFIED;
    auto result = client->StartExtensionAbility(want, callerToken, userId, extensionType);
    EXPECT_NE(ERR_OK, result);
}

/*
 * Feature: ExtensionManagerClient
 * Function: StopExtensionAbility
 */
HWTEST_F(ExtensionManagerClientTest, StopExtensionAbility_0100, TestSize.Level1)
{
    auto client = std::make_shared<ExtensionManagerClient>();
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t userId = DEFAULT_INVAL_VALUE;
    AppExecFwk::ExtensionAbilityType extensionType = AppExecFwk::ExtensionAbilityType::UNSPECIFIED;
    auto result = client->StopExtensionAbility(want, callerToken, userId, extensionType);
    EXPECT_NE(ERR_OK, result);
}

/*
 * Feature: ExtensionManagerClient
 * Function: GetExtensionRunningInfos
 */
HWTEST_F(ExtensionManagerClientTest, GetExtensionRunningInfos_0100, TestSize.Level1)
{
    auto client = std::make_shared<ExtensionManagerClient>();
    int upperLimit = 1;
    std::vector<ExtensionRunningInfo> info;
    auto result = client->GetExtensionRunningInfos(upperLimit, info);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: ExtensionManagerClient
 * Function: TransferAbilityResultForExtension
 */
HWTEST_F(ExtensionManagerClientTest, TransferAbilityResultForExtension_0100, TestSize.Level1)
{
    auto client = std::make_shared<ExtensionManagerClient>();
    sptr<IRemoteObject> callerToken;
    int resultCode = 0;
    Want resultWant;
    auto result = client->TransferAbilityResultForExtension(callerToken, resultCode, resultWant);
    EXPECT_NE(result, NO_ERROR);
}
}
}