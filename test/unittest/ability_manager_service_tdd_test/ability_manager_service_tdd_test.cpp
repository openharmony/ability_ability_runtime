/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "mock_permission_verification.h"

#define private public
#define protected public
#include "ability_manager_service.h"
#include "ability_event_handler.h"
#include "ability_connect_manager.h"
#include "ams_configuration_parameter.h"
#undef private
#undef protected

#include "app_process_data.h"
#include "system_ability_definition.h"
#include "ability_manager_errors.h"
#include "connection_observer_errors.h"
#include "hilog_wrapper.h"
#include "sa_mgr_client.h"
#include "mock_ability_connect_callback.h"
#include "mock_ability_token.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "mock_ability_controller.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::AppExecFwk::AbilityType;
using OHOS::AppExecFwk::ExtensionAbilityType;
namespace OHOS {
namespace AAFwk {
namespace {

const std::string COMPONENT_STARTUP_NEW_RULES = "component.startup.newRules";
}  // namespace
static void WaitUntilTaskFinished()
{
    const uint32_t maxRetryCount = 1000;
    const uint32_t sleepTime = 1000;
    uint32_t count = 0;
    auto handler = OHOS::DelayedSingleton<AbilityManagerService>::GetInstance()->GetEventHandler();
    std::atomic<bool> taskCalled(false);
    auto f = [&taskCalled]() { taskCalled.store(true); };
    if (handler->PostTask(f)) {
        while (!taskCalled.load()) {
            ++count;
            if (count >= maxRetryCount) {
                break;
            }
            usleep(sleepTime);
        }
    }
}
class AbilityManagerServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<AbilityRecord> MockAbilityRecord(AbilityType);
    sptr<Token> MockToken(AbilityType);

    AbilityRequest GenerateAbilityRequest(const std::string& deviceName, const std::string& abilityName,
        const std::string& appName, const std::string& bundleName, const std::string& moduleName);

public:
    inline static std::shared_ptr<AbilityManagerService> abilityMs_{ nullptr };
    AbilityRequest abilityRequest_{};
    Want want_{};
};

std::shared_ptr<AbilityRecord> AbilityManagerServiceTest::MockAbilityRecord(AbilityType abilityType)
{
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.test.demo";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = abilityType;
    return AbilityRecord::CreateAbilityRecord(abilityRequest);
}

sptr<Token> AbilityManagerServiceTest::MockToken(AbilityType abilityType)
{
    std::shared_ptr<AbilityRecord> abilityRecord = MockAbilityRecord(abilityType);
    if (!abilityRecord) {
        return nullptr;
    }
    return abilityRecord->GetToken();
}

AbilityRequest AbilityManagerServiceTest::GenerateAbilityRequest(const std::string& deviceName,
    const std::string& abilityName, const std::string& appName, const std::string& bundleName,
    const std::string& moduleName)
{
    ElementName element(deviceName, bundleName, abilityName, moduleName);
    want_.SetElement(element);

    AbilityInfo abilityInfo;
    abilityInfo.visible = true;
    abilityInfo.applicationName = appName;
    abilityInfo.type = AbilityType::EXTENSION;
    abilityInfo.name = abilityName;
    abilityInfo.bundleName = bundleName;
    abilityInfo.moduleName = moduleName;
    abilityInfo.deviceId = deviceName;
    ApplicationInfo appinfo;
    appinfo.name = appName;
    appinfo.bundleName = bundleName;
    abilityInfo.applicationInfo = appinfo;
    AbilityRequest abilityRequest;
    abilityRequest.want = want_;
    abilityRequest.abilityInfo = abilityInfo;
    abilityRequest.appInfo = appinfo;

    return abilityRequest;
}

void AbilityManagerServiceTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "AbilityManagerServiceTest SetUpTestCase called";
    abilityMs_ = OHOS::DelayedSingleton<AbilityManagerService>::GetInstance();
    abilityMs_->OnStart();
    WaitUntilTaskFinished();
}

void AbilityManagerServiceTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "AbilityManagerServiceTest TearDownTestCase called";
    abilityMs_->OnStop();
    OHOS::DelayedSingleton<SaMgrClient>::DestroyInstance();
    OHOS::DelayedSingleton<AbilityManagerService>::DestroyInstance();
}

void AbilityManagerServiceTest::SetUp()
{
    // generate ability request
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest_ = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
}

void AbilityManagerServiceTest::TearDown()
{}

/*
 * Feature: AbilityManagerService
 * Function: UpdateCallerInfo
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService UpdateCallerInfo
 */
HWTEST_F(AbilityManagerServiceTest, UpdateCallerInfo_001, TestSize.Level1)
{
    HILOG_INFO("AbilityManagerServiceTest UpdateCallerInfo_001 start");
    Want want;
    constexpr int32_t invalid = -1;
    sptr<IRemoteObject> callerToken = MockToken(AbilityType::PAGE);
    want.SetParam(Want::PARAM_RESV_HAS_CALLER_INFO, true);
    abilityMs_->UpdateCallerInfo(want, callerToken);

    EXPECT_EQ(want.GetIntParam(Want::PARAM_RESV_CALLER_TOKEN, invalid), invalid);
    EXPECT_EQ(want.GetIntParam(Want::PARAM_RESV_CALLER_UID, invalid), invalid);
    EXPECT_EQ(want.GetIntParam(Want::PARAM_RESV_CALLER_PID, invalid), invalid);
    HILOG_INFO("AbilityManagerServiceTest UpdateCallerInfo_001 end");
}
}  // namespace AAFwk
}  // namespace OHOS
