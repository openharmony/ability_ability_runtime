/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "ability_record.h"
#include "app_mgr_client.h"
#include "app_mgr_constants.h"
#include "app_scheduler.h"
#include "hilog_tag_wrapper.h"
#include "mock_ability_debug_response_stub.h"
#include "mock_app_debug_listener_stub.h"
#include "mock_native_token.h"
#include "mock_sa_call.h"
#undef protected
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t APP_NUMBER_ZERO = 0;
const int32_t ERROR_PID = 999999;
const int32_t ERROR_USER_ID = -1;
const int32_t ERROR_STATE = -1;
const std::string EMPTY_STRING = "";
const int32_t INIT_VALUE = 0;
const int32_t ERROR_RET = 3;
}  // namespace

class AppMgrClientFirstTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    AbilityRequest GenerateAbilityRequest(const std::string& deviceName,
                                        const std::string& abilityName,
                                        const std::string& appName,
                                        const std::string& bundleName);
};

void AppMgrClientFirstTest::SetUpTestCase(void)
{
    MockNativeToken::SetNativeToken();
}

void AppMgrClientFirstTest::TearDownTestCase(void) {}

void AppMgrClientFirstTest::SetUp() {}

void AppMgrClientFirstTest::TearDown() {}

AbilityRequest AppMgrClientFirstTest::GenerateAbilityRequest(
    const std::string& deviceName, const std::string& abilityName,
    const std::string& appName, const std::string& bundleName)
{
    ElementName element(deviceName, abilityName, bundleName);
    AAFwk::Want want;
    want.SetElement(element);
    AbilityInfo abilityInfo;
    abilityInfo.applicationName = appName;
    ApplicationInfo appinfo;
    appinfo.name = appName;
    AbilityRequest abilityRequest;
    abilityRequest.want = want;
    abilityRequest.abilityInfo = abilityInfo;
    abilityRequest.appInfo = appinfo;
    return abilityRequest;
}

sptr<Token> GetTestAbilityToken()
{
    sptr<Token> token = nullptr;
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.utTest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::DATA;
    std::shared_ptr<AbilityRecord> abilityRecord =
        AbilityRecord::CreateAbilityRecord(abilityRequest);
    if (abilityRecord) {
        token = abilityRecord->GetToken();
    }
    return token;
}

/**
 * @tc.name: ForceKillApplication_001
 * @tc.desc: AppMgrClient test for ForceKillApplication.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrClientFirstTest, ForceKillApplication_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ForceKillApplication_001 start");
    auto appMgrClient = std::make_unique<AppMgrClient>();
    EXPECT_NE(appMgrClient, nullptr);
    std::string bundleName = "bundleName";
    int userId = ERROR_USER_ID;
    int appIndex = 0;
    auto result =
        appMgrClient->ForceKillApplication(bundleName, userId, appIndex);
    EXPECT_EQ(result, AppMgrResultCode::ERROR_SERVICE_NOT_READY);
    TAG_LOGI(AAFwkTag::TEST, "ForceKillApplication_001 end");
}

/**
 * @tc.name: NotifyProcMemoryLevel_001
 * @tc.desc: AppMgrClient test for NotifyProcMemoryLevel.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrClientFirstTest, NotifyProcMemoryLevel_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "NotifyProcMemoryLevel_001 start");
    auto appMgrClient = std::make_unique<AppMgrClient>();
    EXPECT_NE(appMgrClient, nullptr);
    std::map<pid_t, MemoryLevel> procLevelMap = {};
    auto result = appMgrClient->NotifyProcMemoryLevel(procLevelMap);
    EXPECT_EQ(result, OHOS::ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "NotifyProcMemoryLevel_001 end");
}

/**
 * @tc.name: IsKilledForUpgradeWeb_001
 * @tc.desc: AppMgrClient test for IsKilledForUpgradeWeb.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrClientFirstTest, IsKilledForUpgradeWeb_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsKilledForUpgradeWeb_001 start");
    auto appMgrClient = std::make_unique<AppMgrClient>();
    std::string bundleName = "bundleName";
    auto result = appMgrClient->IsKilledForUpgradeWeb(bundleName);
    EXPECT_EQ(result, false);
    TAG_LOGI(AAFwkTag::TEST, "IsKilledForUpgradeWeb_001 end");
}

/**
 * @tc.name: IsProcessContainsOnlyUIAbility_001
 * @tc.desc: AppMgrClient test for IsProcessContainsOnlyUIAbility.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrClientFirstTest, IsProcessContainsOnlyUIAbility_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsProcessContainsOnlyUIAbility_001 start");
    auto appMgrClient = std::make_unique<AppMgrClient>();
    pid_t pid = 1;
    auto result = appMgrClient->IsProcessContainsOnlyUIAbility(pid);
    EXPECT_EQ(result, false);
    TAG_LOGI(AAFwkTag::TEST, "IsProcessContainsOnlyUIAbility_001 end");
}

/**
 * @tc.name: KillProcessesByAccessTokenId_001
 * @tc.desc: AppMgrClient test for KillProcessesByAccessTokenId.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrClientFirstTest, KillProcessesByAccessTokenId_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "KillProcessesByAccessTokenId_001 start");
    auto appMgrClient = std::make_unique<AppMgrClient>();
    uint32_t accessTokenId = 1;
    auto result = appMgrClient->KillProcessesByAccessTokenId(accessTokenId);
    EXPECT_EQ(result, AppMgrResultCode::ERROR_SERVICE_NOT_READY);
    TAG_LOGI(AAFwkTag::TEST, "KillProcessesByAccessTokenId_001 end");
}

/**
 * @tc.name: CleanAbilityByUserRequest_001
 * @tc.desc: AppMgrClient test for CleanAbilityByUserRequest.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrClientFirstTest, CleanAbilityByUserRequest_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CleanAbilityByUserRequest_001 start");
    auto appMgrClient = std::make_unique<AppMgrClient>();
    sptr<IRemoteObject> token = GetTestAbilityToken();
    auto result = appMgrClient->CleanAbilityByUserRequest(token);
    EXPECT_TRUE(result != true);
    TAG_LOGI(AAFwkTag::TEST, "CleanAbilityByUserRequest_001 end");
}

/**
 * @tc.name: IsCallerKilling_001
 * @tc.desc: AppMgrClient test for IsCallerKilling.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrClientFirstTest, IsCallerKilling_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsCallerKilling_001 start");
    auto appMgrClient = std::make_unique<AppMgrClient>();
    auto result = appMgrClient->IsCallerKilling("");
    EXPECT_TRUE(result != true);
    TAG_LOGI(AAFwkTag::TEST, "IsCallerKilling_001 end");
}
}  // namespace AppExecFwk
}  // namespace OHOS
