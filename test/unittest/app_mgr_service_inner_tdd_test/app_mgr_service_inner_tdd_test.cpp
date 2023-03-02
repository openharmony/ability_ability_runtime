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
#include <thread>

#define private public
#include "app_mgr_service_inner.h"
#include "app_running_record.h"
#include "remote_client_manager.h"
#undef private
#include "app_scheduler.h"
#include "event_handler.h"
#include "hilog_wrapper.h"
#include "ipc_skeleton.h"
#include "mock_ability_token.h"
#include "mock_app_scheduler.h"
#include "mock_bundle_manager.h"
#include "mock_configuration_observer.h"
#include "mock_iapp_state_callback.h"
#include "mock_native_token.h"
#include "mock_render_scheduler.h"
#include "parameters.h"
#include "window_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
// static int recordId_ = 0;
class AppMgrServiceInnerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    void InitAppInfo(const std::string& deviceName, const std::string& abilityName,
        const std::string& appName, const std::string& bundleName, const std::string& moduleName);

public:
    std::shared_ptr<AbilityInfo> abilityInfo_;
    std::shared_ptr<ApplicationInfo> applicationInfo_;
};

void AppMgrServiceInnerTest::InitAppInfo(const std::string& deviceName,
    const std::string& abilityName, const std::string& appName, const std::string& bundleName,
    const std::string& moduleName)
{
    ApplicationInfo applicationInfo;
    applicationInfo.name = appName;
    applicationInfo.bundleName = bundleName;
    applicationInfo_ = std::make_shared<ApplicationInfo>(applicationInfo);

    AbilityInfo abilityInfo;
    abilityInfo.visible = true;
    abilityInfo.applicationName = appName;
    abilityInfo.type = AbilityType::EXTENSION;
    abilityInfo.name = abilityName;
    abilityInfo.bundleName = bundleName;
    abilityInfo.moduleName = moduleName;
    abilityInfo.deviceId = deviceName;
    abilityInfo_ = std::make_shared<AbilityInfo>(abilityInfo);
}

void AppMgrServiceInnerTest::SetUpTestCase(void)
{
    MockNativeToken::SetNativeToken();
}

void AppMgrServiceInnerTest::TearDownTestCase(void)
{}

void AppMgrServiceInnerTest::SetUp()
{
    // init test app info
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    InitAppInfo(deviceName, abilityName, appName, bundleName, moduleName);
}

void AppMgrServiceInnerTest::TearDown()
{}

/**
 * @tc.name: SendProcessStartEvent_001
 * @tc.desc: Verify that the SendProcessStartEvent interface calls normally
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, SendProcessStartEvent_001, TestSize.Level0)
{
    HILOG_INFO("SendProcessStartEvent_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    EXPECT_FALSE(appMgrServiceInner->SendProcessStartEvent(nullptr));

    BundleInfo bundleInfo;
    std::string processName = "test_processName";
    sptr<IRemoteObject> token = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord, nullptr);
    EXPECT_TRUE(appMgrServiceInner->SendProcessStartEvent(appRecord));

    std::shared_ptr<ApplicationInfo> appInfo = std::make_shared<ApplicationInfo>();
    std::shared_ptr<ModuleRunningRecord> moduleRunningRecord = std::make_shared<ModuleRunningRecord>(appInfo, nullptr);
    std::shared_ptr<AbilityRunningRecord> abilityRecordEmpty = std::make_shared<AbilityRunningRecord>(nullptr, token);
    moduleRunningRecord->abilities_[token] = abilityRecordEmpty;
    std::vector<std::shared_ptr<ModuleRunningRecord>> moduleRecordList = { moduleRunningRecord };
    appRecord->hapModules_["moduleRecordList"] = moduleRecordList;
    EXPECT_TRUE(appMgrServiceInner->SendProcessStartEvent(appRecord));

    std::shared_ptr<AbilityInfo> abilityInfo = std::make_shared<AbilityInfo>();
    std::shared_ptr<AbilityRunningRecord> abilityRecord = std::make_shared<AbilityRunningRecord>(abilityInfo, token);
    moduleRunningRecord->abilities_[token] = abilityRecord;
    EXPECT_TRUE(appMgrServiceInner->SendProcessStartEvent(appRecord));

    appRecord->SetCallerTokenId(IPCSkeleton::GetCallingTokenID());
    EXPECT_TRUE(appMgrServiceInner->SendProcessStartEvent(appRecord));

    appRecord->SetCallerUid(IPCSkeleton::GetCallingUid());
    EXPECT_TRUE(appMgrServiceInner->SendProcessStartEvent(appRecord));

    auto &recordMap = appMgrServiceInner->appRunningManager_->appRunningRecordMap_;
    auto iter = recordMap.find(IPCSkeleton::GetCallingPid());
    if (iter == recordMap.end()) {
        recordMap.insert({IPCSkeleton::GetCallingPid(), appRecord});
    } else {
        recordMap.erase(iter);
        recordMap.insert({IPCSkeleton::GetCallingPid(), appRecord});
    }
    appRecord->GetPriorityObject()->pid_ = IPCSkeleton::GetCallingPid();
    appRecord->SetCallerPid(IPCSkeleton::GetCallingPid());
    EXPECT_TRUE(appMgrServiceInner->SendProcessStartEvent(appRecord));
    HILOG_INFO("SendProcessStartEvent_001 end");
}

/**
 * @tc.name: SendProcessExitEventTask_001
 * @tc.desc: Verify that the SendProcessExitEventTask interface calls normally
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, SendProcessExitEventTask_001, TestSize.Level0)
{
    HILOG_INFO("SendProcessExitEventTask_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    auto runner = EventRunner::Create(Constants::APP_MGR_SERVICE_NAME);
    appMgrServiceInner->eventHandler_ = std::make_shared<AMSEventHandler>(runner, appMgrServiceInner);

    pid_t pid = -1;
    time_t exitTime = 0;
    int32_t count = 2;
    appMgrServiceInner->SendProcessExitEventTask(pid, exitTime, count);

    auto eventTask = [eventRunner = runner] () {
        eventRunner->Run();
    };
    std::thread testThread(eventTask);
    pid_t pid1 = IPCSkeleton::GetCallingPid();
    appMgrServiceInner->SendProcessExitEventTask(pid1, exitTime, count);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    auto stopEventTask = [eventRunner = runner] () {
        eventRunner->Stop();
    };
    appMgrServiceInner->eventHandler_->PostTask(stopEventTask, "stopEventTask");
    testThread.join();
    HILOG_INFO("SendProcessExitEventTask_001 end");
}

/**
 * @tc.name: SendProcessExitEvent_001
 * @tc.desc: Verify that the SendProcessExitEvent interface calls normally
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, SendProcessExitEvent_001, TestSize.Level0)
{
    HILOG_INFO("SendProcessExitEvent_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    pid_t pid = -1;
    appMgrServiceInner->SendProcessExitEvent(pid);
    HILOG_INFO("SendProcessExitEvent_001 end");
}

/**
 * @tc.name: ConvertAbilityType_001
 * @tc.desc: Verify that the ConvertAbilityType and ConvertExtensionAbilityType interface calls normally
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, ConvertAbilityType_001, TestSize.Level0)
{
    HILOG_INFO("ConvertAbilityType_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::UNKNOWN,
        ExtensionAbilityType::UNSPECIFIED), appMgrServiceInner->UNKNOWN_TYPE);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::PAGE, ExtensionAbilityType::UNSPECIFIED),
        appMgrServiceInner->FA_PAGE);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::SERVICE,
        ExtensionAbilityType::UNSPECIFIED), appMgrServiceInner->FA_SERVICE);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::DATA, ExtensionAbilityType::UNSPECIFIED),
        appMgrServiceInner->FA_DATA);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::FORM),
        appMgrServiceInner->EXTENSION_FORM);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::WORK_SCHEDULER),
        appMgrServiceInner->EXTENSION_WORK_SCHEDULER);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::INPUTMETHOD),
        appMgrServiceInner->EXTENSION_INPUTMETHOD);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::SERVICE),
        appMgrServiceInner->EXTENSION_SERVICE);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::ACCESSIBILITY),
        appMgrServiceInner->EXTENSION_ACCESSIBILITY);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::DATASHARE),
        appMgrServiceInner->EXTENSION_DATASHARE);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::FILESHARE),
        appMgrServiceInner->EXTENSION_FILESHARE);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::STATICSUBSCRIBER),
        appMgrServiceInner->EXTENSION_STATICSUBSCRIBER);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::WALLPAPER),
        appMgrServiceInner->EXTENSION_WALLPAPER);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::BACKUP),
        appMgrServiceInner->EXTENSION_BACKUP);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::WINDOW),
        appMgrServiceInner->EXTENSION_WINDOW);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::ENTERPRISE_ADMIN),
        appMgrServiceInner->EXTENSION_ENTERPRISE_ADMIN);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION,
        ExtensionAbilityType::FILEACCESS_EXTENSION), appMgrServiceInner->EXTENSION_FILEACCESS_EXTENSION);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::THUMBNAIL),
        appMgrServiceInner->EXTENSION_THUMBNAIL);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::PREVIEW),
        appMgrServiceInner->EXTENSION_PREVIEW);
    EXPECT_EQ(appMgrServiceInner->ConvertAbilityType(AbilityType::EXTENSION, ExtensionAbilityType::UNSPECIFIED),
        appMgrServiceInner->EXTENSION_UNSPECIFIED);
    HILOG_INFO("ConvertAbilityType_001 end");
}
} // namespace AppExecFwk
} // namespace OHOS