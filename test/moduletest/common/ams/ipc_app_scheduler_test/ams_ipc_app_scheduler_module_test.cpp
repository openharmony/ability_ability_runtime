/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "app_scheduler_host.h"
#include "app_scheduler_proxy.h"
#include "semaphore_ex.h"

#include "mock_ability_token.h"
#include "mock_app_scheduler.h"
#include "mock_application.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::iface_cast;
using OHOS::sptr;
using testing::_;
using testing::Invoke;
using testing::InvokeWithoutArgs;

namespace {
const int32_t COUNT = 10000;
}  // namespace
class AmsIpcAppSchedulerModuleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    sptr<MockAbilityToken> GetMockToken() const
    {
        return mock_token_;
    }

private:
    sptr<MockAbilityToken> mock_token_;
};

void AmsIpcAppSchedulerModuleTest::SetUpTestCase()
{}

void AmsIpcAppSchedulerModuleTest::TearDownTestCase()
{}

void AmsIpcAppSchedulerModuleTest::SetUp()
{}

void AmsIpcAppSchedulerModuleTest::TearDown()
{}

/*
 * Feature: ApplicationFramework
 * Function: AppManagerService
 * SubFunction: IApplicationScheduler
 * FunctionPoints: test ScheduleForegroundApplication API,then check the function whether is good or not
 * EnvConditions: system running normally
 * CaseDescription: execute ScheduleForegroundApplication API 10000 times
 */
HWTEST_F(AmsIpcAppSchedulerModuleTest, ExcuteApplicationIPCInterface_001, TestSize.Level3)
{
    sptr<MockApplication> mockApplication(new MockApplication());
    sptr<IAppScheduler> client = iface_cast<IAppScheduler>(mockApplication);

    EXPECT_CALL(*mockApplication, ScheduleForegroundApplication())
        .WillOnce(testing::Return(true));
    client->ScheduleForegroundApplication();

    mockApplication = nullptr;
}

/*
 * Feature: ApplicationFramework
 * Function: AppManagerService
 * SubFunction: IApplicationScheduler
 * FunctionPoints: test ScheduleBackgroundApplication API,then check the function whether is good or not
 * EnvConditions: system running normally
 * CaseDescription: execute ScheduleBackgroundApplication API 10000 times
 */
HWTEST_F(AmsIpcAppSchedulerModuleTest, ExcuteApplicationIPCInterface_002, TestSize.Level3)
{
    sptr<MockApplication> mockApplication(new MockApplication());
    sptr<IAppScheduler> client = iface_cast<IAppScheduler>(mockApplication);

    EXPECT_CALL(*mockApplication, ScheduleBackgroundApplication())
        .WillOnce(testing::Return());
    client->ScheduleBackgroundApplication();

    mockApplication = nullptr;
}

/*
 * Feature: ApplicationFramework
 * Function: AppManagerService
 * SubFunction: IApplicationScheduler
 * FunctionPoints: test ScheduleTerminateApplication API,then check the function whether is good or not
 * EnvConditions: system running normally
 * CaseDescription: execute ScheduleTerminateApplication API 10000 times
 */
HWTEST_F(AmsIpcAppSchedulerModuleTest, ExcuteApplicationIPCInterface_003, TestSize.Level3)
{
    sptr<MockApplication> mockApplication(new MockApplication());
    sptr<IAppScheduler> client = iface_cast<IAppScheduler>(mockApplication);

    EXPECT_CALL(*mockApplication, ScheduleTerminateApplication(_))
        .WillOnce(testing::Return());
    client->ScheduleTerminateApplication();

    mockApplication = nullptr;
}

/*
 * Feature: ApplicationFramework
 * Function: AppManagerService
 * SubFunction: IApplicationScheduler
 * FunctionPoints: test ScheduleTrimMemory API,then check the function whether is good or not
 * EnvConditions: system running normally
 * CaseDescription: execute ScheduleTrimMemory API 10000 times
 */
HWTEST_F(AmsIpcAppSchedulerModuleTest, ExcuteApplicationIPCInterface_004, TestSize.Level3)
{
    sptr<MockApplication> mockApplication(new MockApplication());
    sptr<IAppScheduler> client = iface_cast<IAppScheduler>(mockApplication);

    EXPECT_CALL(*mockApplication, ScheduleShrinkMemory(_))
        .WillOnce(testing::Return());
    int level = 1;
    client->ScheduleShrinkMemory(level);

    int getLevel = mockApplication->GetShrinkLevel() + 1;
    EXPECT_EQ(getLevel, level);

    mockApplication = nullptr;
}

/*
 * Feature: ApplicationFramework
 * Function: AppManagerService
 * SubFunction: IApplicationScheduler
 * FunctionPoints: test scheduleLowMemory API,then check the function whether is good or not
 * EnvConditions: system running normally
 * CaseDescription: execute LowMemoryWarning API 10000 times
 */
HWTEST_F(AmsIpcAppSchedulerModuleTest, ExcuteApplicationIPCInterface_005, TestSize.Level3)
{
    sptr<MockApplication> mockApplication(new MockApplication());
    sptr<IAppScheduler> client = iface_cast<IAppScheduler>(mockApplication);

    EXPECT_CALL(*mockApplication, ScheduleLowMemory())
        .WillOnce(testing::Return());
    client->ScheduleLowMemory();

    mockApplication = nullptr;
}

/*
 * Feature: ApplicationFramework
 * Function: AppManagerService
 * SubFunction: IApplicationScheduler
 * FunctionPoints: test scheduleProfileChanged API,then check the function whether is good or not
 * EnvConditions: system running normally
 * CaseDescription: execute scheduleProfileChanged API 10000 times
 */
HWTEST_F(AmsIpcAppSchedulerModuleTest, ExcuteApplicationIPCInterface_006, TestSize.Level3)
{
    sptr<MockApplication> mockApplication(new MockApplication());
    sptr<IAppScheduler> client = iface_cast<IAppScheduler>(mockApplication);

    std::string profileName("mockProfile");
    Profile profile(profileName);

    EXPECT_CALL(*mockApplication, ScheduleProfileChanged(_))
        .WillOnce(testing::Return());
    client->ScheduleProfileChanged(profile);

    bool result = mockApplication->CompareProfile(profile);
    EXPECT_EQ(result, false);

    mockApplication = nullptr;
}

/*
 * Feature: ApplicationFramework
 * Function: AppManagerService
 * SubFunction: IApplicationScheduler
 * FunctionPoints: test ScheduleLaunchApplication API,then check the function whether is good or not
 * EnvConditions: system running normally
 * CaseDescription: execute ScheduleLaunchApplication API 10000 times
 */
HWTEST_F(AmsIpcAppSchedulerModuleTest, ExcuteApplicationIPCInterface_008, TestSize.Level3)
{
    sptr<MockApplication> mockApplication = new MockApplication();
    sptr<IAppScheduler> client = iface_cast<IAppScheduler>(mockApplication);

    std::string applicationName("mockApplicationInfo");
    ApplicationInfo applicationInfo;
    applicationInfo.name = applicationName;
    std::string profileName("mockProfile");
    Profile profile(profileName);
    std::string processName("mockProcessInfo");
    ProcessInfo processInfo(processName, 123);

    AppLaunchData launchData;
    launchData.SetApplicationInfo(applicationInfo);
    launchData.SetProfile(profile);
    launchData.SetProcessInfo(processInfo);

    Configuration config;
    EXPECT_CALL(*mockApplication, ScheduleLaunchApplication(_, _))
        .WillOnce(testing::Return());
    client->ScheduleLaunchApplication(launchData, config);

    bool isEqual = mockApplication->CompareAppLaunchData(launchData);
    EXPECT_EQ(isEqual, false);

    mockApplication = nullptr;
}

/*
 * Feature: ApplicationFramework
 * Function: AppManagerService
 * SubFunction: IApplicationScheduler
 * FunctionPoints: test ScheduleCleanAbility API,then check the function whether is good or not
 * EnvConditions: system running normally
 * CaseDescription: execute ScheduleCleanAbility API 10000 times
 */
HWTEST_F(AmsIpcAppSchedulerModuleTest, ExcuteApplicationIPCInterface_009, TestSize.Level3)
{
    sptr<MockApplication> mockApp = new MockApplication();
    sptr<IAppScheduler> client = iface_cast<IAppScheduler>(mockApp);
    EXPECT_CALL(*mockApp, ScheduleCleanAbility(_, _))
        .WillOnce(testing::Return());
    client->ScheduleCleanAbility(GetMockToken());

    mockApp = nullptr;
}

/*
 * Feature: ApplicationFramework
 * Function: AppManagerService
 * SubFunction: IApplicationScheduler
 * FunctionPoints: test ScheduleConfigurationUpdated API,then check the function whether is good or not
 * EnvConditions: system running normally
 * CaseDescription: execute ScheduleConfigurationUpdated API 10000 times
 */
HWTEST_F(AmsIpcAppSchedulerModuleTest, ExcuteApplicationIPCInterface_010, TestSize.Level3)
{
    Configuration testConfig;
    std::string val = "ZH-HANS";
    testConfig.AddItem(OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, val);
    sptr<MockApplication> mockApp = new MockApplication();
    sptr<IAppScheduler> client = iface_cast<IAppScheduler>(mockApp);
    EXPECT_CALL(*mockApp, ScheduleConfigurationUpdated(_))
        .WillOnce(testing::Return());
    client->ScheduleConfigurationUpdated(testConfig);

    mockApp = nullptr;
}
