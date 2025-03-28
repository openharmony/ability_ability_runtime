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

#define private public
#include "app_mgr_service_inner.h"
#include "app_running_record.h"
#include "remote_client_manager.h"
#undef private
#include "ability_manager_errors.h"
#include "accesstoken_kit.h"
#include "advanced_security_mode_manager.h"
#include "app_scheduler.h"
#include "appspawn_util.h"
#include "app_spawn_client.h"
#include "event_handler.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"
#include "mock_ability_token.h"
#include "mock_app_scheduler.h"
#include "mock_bundle_manager.h"
#include "mock_configuration_observer.h"
#include "mock_iapp_state_callback.h"
#include "mock_kia_interceptor.h"
#include "mock_native_token.h"
#include "mock_render_scheduler.h"
#include "mock_sa_call.h"
#include "mock_task_handler_wrap.h"
#include "param.h"
#include "parameters.h"
#include "render_state_observer_stub.h"
#include "window_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class WindowFocusChangedListener : public OHOS::Rosen::IFocusChangedListener {
public:
    WindowFocusChangedListener(const std::shared_ptr<AppMgrServiceInner>& owner,
        const std::shared_ptr<AAFwk::TaskHandlerWrap>& handler);
    virtual ~WindowFocusChangedListener();

    void OnFocused(const sptr<OHOS::Rosen::FocusChangeInfo> &focusChangeInfo) override;
    void OnUnfocused(const sptr<OHOS::Rosen::FocusChangeInfo> &focusChangeInfo) override;

private:
    std::weak_ptr<AppMgrServiceInner> owner_;
    std::shared_ptr<AAFwk::TaskHandlerWrap> taskHandler_;
};
namespace {
constexpr int32_t RECORD_ID = 1;
constexpr int32_t APP_DEBUG_INFO_PID = 0;
constexpr int32_t APP_DEBUG_INFO_UID = 0;
constexpr const char* PERMISSION_PROTECT_SCREEN_LOCK_DATA_TEST = "ohos.permission.PROTECT_SCREEN_LOCK_DATA";
}

class MockIAppStateCallback : public IAppStateCallback {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.AppStateCallback");
    void OnAppStateChanged(const AppProcessData &appProcessData) override {};
    void OnAbilityRequestDone(const sptr<IRemoteObject> &token, const AbilityState state) override {};
    void OnAppRemoteDied(const std::vector<sptr<IRemoteObject>> &abilityTokens)
    {
        dealed = true;
    }
    void OnCacheExitInfo(uint32_t accessTokenId, const AAFwk::LastExitDetailInfo &exitInfo,
        const std::string &bundleName, const std::vector<std::string> &abilityNames,
        const std::vector<std::string> &uiExtensionNames) override
    {
        dealed = true;
    }
    void NotifyConfigurationChange(const AppExecFwk::Configuration &config, int32_t userId) override
    {
        dealed = true;
    }
    sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    }
    bool dealed = false;
};

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

class RenderStateObserverMock : public RenderStateObserverStub {
public:
    RenderStateObserverMock() = default;
    virtual ~RenderStateObserverMock() = default;
    void OnRenderStateChanged(const RenderStateData &renderStateData) override
    {}
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
 * @tc.name: reportpreLoadTask_001
 * @tc.desc: reportpreLoadTask
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, reportpreLoadTask_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "reportpreLoadTask_001 start");

    std::shared_ptr<ApplicationInfo> info = std::make_shared<AppExecFwk::ApplicationInfo>();
    int32_t recordId = 0x0001;
    std::string processName = "processName for reportpreLoadTask";
    std::shared_ptr<AppRunningRecord> appRecord =
        std::make_shared<AppExecFwk::AppRunningRecord>(info, recordId, processName);
    appRecord->SetUid(1);
    
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    appMgrServiceInner->reportpreLoadTask(appRecord);

    appRecord->priorityObject_ = std::make_shared<AppExecFwk::PriorityObject>();
    appMgrServiceInner->reportpreLoadTask(appRecord);

    appMgrServiceInner->taskHandler_ = AAFwk::TaskHandlerWrap::CreateQueueHandler("");
    appMgrServiceInner->reportpreLoadTask(appRecord);
    EXPECT_NE(appMgrServiceInner, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "reportpreLoadTask_001 end");
}

/**
 * @tc.name: MakeProcessName_001
 * @tc.desc: MakeProcessName
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, MakeProcessName_003, TestSize.Level0)
{
    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    std::shared_ptr<AppExecFwk::ApplicationInfo> appInfo =  nullptr;
    AppExecFwk::HapModuleInfo hapModuleInfo;
    int32_t appIndex = 1;
    std::string specifiedProcessFlag {};
    std::string processName {};
    bool isCallerSetProcess = true;

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    appMgrServiceInner->MakeProcessName(abilityInfo, appInfo,
        hapModuleInfo, appIndex, specifiedProcessFlag, processName, isCallerSetProcess);

    abilityInfo = std::make_shared<AppExecFwk::AbilityInfo>();
    appMgrServiceInner->MakeProcessName(abilityInfo, appInfo,
        hapModuleInfo, appIndex, specifiedProcessFlag, processName, isCallerSetProcess);
    appInfo = std::make_shared<AppExecFwk::ApplicationInfo>();

    abilityInfo->process = "abilityInfoProcess";
    appInfo->bundleName = "appInfoBundleName";
    abilityInfo->process = "abilityInfoProcess";

    appMgrServiceInner->MakeProcessName(abilityInfo, appInfo,
        hapModuleInfo, appIndex, specifiedProcessFlag, processName, isCallerSetProcess);
    EXPECT_EQ(processName, abilityInfo->process + ":" + std::to_string(appIndex));

    abilityInfo->type = AppExecFwk::AbilityType::PAGE;
    abilityInfo->isStageBasedModel = true;
    appMgrServiceInner->MakeProcessName(abilityInfo, appInfo,
        hapModuleInfo, appIndex, specifiedProcessFlag, processName, isCallerSetProcess);
    EXPECT_EQ(processName, appInfo->bundleName +
        abilityInfo->process + ":" + std::to_string(appIndex));

    abilityInfo->process.clear();
    hapModuleInfo.process = "hapModuleInfoProcess";
    hapModuleInfo.isStageBasedModel = true;
    appMgrServiceInner->MakeProcessName(abilityInfo, appInfo,
        hapModuleInfo, appIndex, specifiedProcessFlag, processName, isCallerSetProcess);
    EXPECT_EQ(processName, hapModuleInfo.process + std::to_string(appIndex));

    specifiedProcessFlag = "specifiedProcessFlag";
    appMgrServiceInner->MakeProcessName(abilityInfo, appInfo,
        hapModuleInfo, appIndex, specifiedProcessFlag, processName, isCallerSetProcess);
    EXPECT_EQ(processName, hapModuleInfo.process +
        std::to_string(appIndex) + ":" + specifiedProcessFlag);
}

/**
 * @tc.name: LaunchApplicationExt_001
 * @tc.desc: LaunchApplicationExt
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, LaunchApplicationExt_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    std::shared_ptr<AppExecFwk::AppRunningRecord> appRecord =
        std::make_shared<AppExecFwk::AppRunningRecord>(nullptr, 1, "111");
    appMgrServiceInner->nwebPreloadSet_.insert("111");

    appRecord->isAllowedNWebPreload_ = false;
    appMgrServiceInner->LaunchApplicationExt(appRecord);
    EXPECT_EQ(appRecord->isAllowedNWebPreload_, true);
}

/**
 * @tc.name: IsAllowedNWebPreload_001
 * @tc.desc: IsAllowedNWebPreload
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, IsAllowedNWebPreload_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    appMgrServiceInner->nwebPreloadSet_.clear();

    EXPECT_EQ(appMgrServiceInner->IsAllowedNWebPreload("111"), false);
    appMgrServiceInner->nwebPreloadSet_.insert("111");
    EXPECT_EQ(appMgrServiceInner->IsAllowedNWebPreload("111"), true);
}

/**
 * @tc.name: NotifyAppAttachFailed_001
 * @tc.desc: NotifyAppAttachFailed
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, NotifyAppAttachFailed_001, TestSize.Level0)
{
    std::shared_ptr<AppExecFwk::AppRunningRecord> appRecord =
        std::make_shared<AppExecFwk::AppRunningRecord>(nullptr, 1, "111");
    
    auto moduleRunningRecord =
        std::make_shared<AppExecFwk::ModuleRunningRecord>(nullptr, nullptr);
    sptr<IRemoteObject> iremoteObject =
        sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    auto abilityRunningRecord =
        std::make_shared<AppExecFwk::AbilityRunningRecord>(nullptr, nullptr, 1);
    moduleRunningRecord->abilities_.emplace(iremoteObject, abilityRunningRecord);
    std::vector<std::shared_ptr<AppExecFwk::ModuleRunningRecord>> modulerunningrecordVector;
    modulerunningrecordVector.push_back(moduleRunningRecord);
    appRecord->hapModules_.emplace(std::make_pair("111", modulerunningrecordVector));

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    AppMgrServiceInner::AppStateCallbackWithUserId appStateCallbackWithUserId;
    appStateCallbackWithUserId.callback = nullptr;
    appMgrServiceInner->appStateCallbacks_.push_back(appStateCallbackWithUserId);
    appMgrServiceInner->NotifyAppAttachFailed(appRecord);

    appMgrServiceInner->appStateCallbacks_.clear();
    appStateCallbackWithUserId.callback = sptr<MockIAppStateCallback>::MakeSptr();
    appMgrServiceInner->appStateCallbacks_.push_back(appStateCallbackWithUserId);
    appMgrServiceInner->NotifyAppAttachFailed(appRecord);
    for (auto &item : appMgrServiceInner->appStateCallbacks_) {
        MockIAppStateCallback* rawPtr =
            static_cast<MockIAppStateCallback*>(item.callback.GetRefPtr());
        if (rawPtr) {
            sptr<MockIAppStateCallback> iapp(rawPtr);
            EXPECT_EQ(iapp->dealed, true);
        }
    }
}

/**
 * @tc.name: NotifyLoadAbilityFailed_001
 * @tc.desc: NotifyLoadAbilityFailed
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, NotifyLoadAbilityFailed_001, TestSize.Level0)
{
    OHOS::sptr<IRemoteObject> token = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    AppMgrServiceInner::AppStateCallbackWithUserId appStateCallbackWithUserId;
    appStateCallbackWithUserId.callback = nullptr;
    appMgrServiceInner->appStateCallbacks_.push_back(appStateCallbackWithUserId);
    appMgrServiceInner->NotifyLoadAbilityFailed(token);

    appMgrServiceInner->appStateCallbacks_.clear();
    appStateCallbackWithUserId.callback = sptr<MockIAppStateCallback>::MakeSptr();
    appMgrServiceInner->appStateCallbacks_.push_back(appStateCallbackWithUserId);
    appMgrServiceInner->NotifyLoadAbilityFailed(token);
    for (auto &item : appMgrServiceInner->appStateCallbacks_) {
        MockIAppStateCallback* rawPtr =
            static_cast<MockIAppStateCallback*>(item.callback.GetRefPtr());
        if (rawPtr) {
            sptr<MockIAppStateCallback> iapp(rawPtr);
            EXPECT_EQ(iapp->dealed, true);
        }   
    }
}

/**
 * @tc.name: OpenAppSpawnConnection_002
 * @tc.desc: open app spawn connection.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, OpenAppSpawnConnection_002, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    appMgrServiceInner->remoteClientManager_ = nullptr;
    auto ret = appMgrServiceInner->OpenAppSpawnConnection();
    EXPECT_EQ(ret, 22);

    appMgrServiceInner->remoteClientManager_ =
        std::make_shared<RemoteClientManager>();
    appMgrServiceInner->remoteClientManager_->appSpawnClient_.reset();
    ret = appMgrServiceInner->OpenAppSpawnConnection();
    EXPECT_EQ(ret, 8454147);

    appMgrServiceInner->remoteClientManager_->appSpawnClient_ =
        std::make_shared<AppExecFwk::AppSpawnClient>();
    appMgrServiceInner->remoteClientManager_->appSpawnClient_->state_ =
        SpawnConnectionState::STATE_CONNECTED;
    ret = appMgrServiceInner->OpenAppSpawnConnection();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: SetAppSpawnClient_002
 * @tc.desc: set app spawn client.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, SetAppSpawnClient_002, TestSize.Level0)
{
    std::shared_ptr<AppSpawnClient> spawnClient = nullptr;
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    appMgrServiceInner->remoteClientManager_ = nullptr;

    appMgrServiceInner->SetAppSpawnClient(spawnClient);
    appMgrServiceInner->remoteClientManager_ =
        std::make_shared<RemoteClientManager>();

    appMgrServiceInner->remoteClientManager_->appSpawnClient_ = nullptr;
    spawnClient = std::make_shared<AppExecFwk::AppSpawnClient>(false);
    appMgrServiceInner->SetAppSpawnClient(spawnClient);
    EXPECT_NE(appMgrServiceInner->remoteClientManager_->appSpawnClient_, nullptr);
}

/**
 * @tc.name: SetBundleManagerHelper_002
 * @tc.desc: set app SetBundleManagerHelper.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, SetBundleManagerHelper_002, TestSize.Level0)
{
    std::shared_ptr<BundleMgrHelper> bundleMgrHelper = nullptr;
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    appMgrServiceInner->remoteClientManager_ = nullptr;
    appMgrServiceInner->SetBundleManagerHelper(bundleMgrHelper);

    appMgrServiceInner->remoteClientManager_ =
        std::make_shared<RemoteClientManager>();
    appMgrServiceInner->remoteClientManager_->bundleManagerHelper_ = nullptr;
    bundleMgrHelper =
        appMgrServiceInner->remoteClientManager_->GetBundleManagerHelper();
    appMgrServiceInner->SetBundleManagerHelper(bundleMgrHelper);
    EXPECT_NE(appMgrServiceInner->remoteClientManager_->bundleManagerHelper_, nullptr);
}

/**
 * @tc.name: SetStartMsgStrictMode_001
 * @tc.desc: SetStartMsgStrictMode.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, SetStartMsgStrictMode_001, TestSize.Level0)
{
    CreateStartMsgParam param;
    param.strictMode = true;
    AppSpawnStartMsg startMsg;
    startMsg.strictMode = false;
    startMsg.isolatedNetworkFlag = true;
    startMsg.isolatedSELinuxFlag = true;

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    appMgrServiceInner->SetStartMsgStrictMode(startMsg, param);
    EXPECT_EQ(startMsg.isolatedNetworkFlag, false);
    EXPECT_EQ(startMsg.isolatedSELinuxFlag, false);
    
    param.extensionAbilityType = ExtensionAbilityType::INPUTMETHOD;
    startMsg.isolatedSandboxFlagLegacy = false;
    appMgrServiceInner->SetStartMsgStrictMode(startMsg, param);
    EXPECT_EQ(startMsg.strictMode, param.strictMode);
    EXPECT_EQ(startMsg.isolatedSandboxFlagLegacy, true);
}

/**
 * @tc.name: SetProcessJITState_001
 * @tc.desc: SetProcessJITState.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, SetProcessJITState_001, TestSize.Level0)
{
    std::shared_ptr<AppRunningRecord> appRecord = nullptr;
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    appMgrServiceInner->SetProcessJITState(appRecord);

    appRecord = std::make_shared<AppExecFwk::AppRunningRecord>(nullptr, 0, "");
    appMgrServiceInner->securityModeManager_ = nullptr;
    appMgrServiceInner->SetProcessJITState(appRecord);
    EXPECT_EQ(appRecord->jitEnabled_, true);

    appMgrServiceInner->securityModeManager_ =
        std::make_shared<AppExecFwk::AdvancedSecurityModeManager>();
    appMgrServiceInner->SetProcessJITState(appRecord);
    EXPECT_EQ(appRecord->jitEnabled_, true);
}

/**
 * @tc.name: SendCreateAtomicServiceProcessEvent_001
 * @tc.desc: SendCreateAtomicServiceProcessEvent.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, SendCreateAtomicServiceProcessEvent_002, TestSize.Level0)
{
    std::shared_ptr<AppRunningRecord> appRecord = nullptr;
    BundleType bundleType { BundleType::APP };
    std::string moduleName {};
    std::string abilityName {};

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    bool result = appMgrServiceInner->SendCreateAtomicServiceProcessEvent(appRecord,
        bundleType, moduleName, abilityName);
    EXPECT_EQ(result, false);

    bundleType = { BundleType::ATOMIC_SERVICE };
    result = appMgrServiceInner->SendCreateAtomicServiceProcessEvent(appRecord,
        bundleType, moduleName, abilityName);
    EXPECT_EQ(result, false);

    appRecord = std::make_shared<AppExecFwk::AppRunningRecord>(nullptr, 0, "");
    result = appMgrServiceInner->SendCreateAtomicServiceProcessEvent(appRecord,
        bundleType, moduleName, abilityName);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: SendReStartProcessEvent_006
 * @tc.desc: SendReStartProcessEvent.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, SendReStartProcessEvent_006, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    int64_t restartTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
        system_clock::now().time_since_epoch()).count();
    int64_t killtime1 = restartTime - 2001;
    appMgrServiceInner->killedProcessMap_.emplace(std::make_pair(killtime1, "killtime1"));
    int64_t killtime2 = restartTime - 1999;
    appMgrServiceInner->killedProcessMap_.emplace(std::make_pair(killtime2, "killtime2"));

    std::string testString1 = "11111";
    std::string testString2 = "22222";
    AAFwk::EventInfo eventInfo;
    int32_t appUid = 1;
    eventInfo.bundleName = testString1;
    eventInfo.callerBundleName = testString1;
    eventInfo.processName = testString1;
    eventInfo.callerProcessName = testString1;

    appMgrServiceInner->SendReStartProcessEvent(eventInfo, appUid);
    EXPECT_EQ(appMgrServiceInner->killedProcessMap_.size(), 1);

    eventInfo.bundleName = testString1;
    eventInfo.callerBundleName = testString2;
    eventInfo.processName = testString1;
    eventInfo.callerProcessName = testString2;
    appMgrServiceInner->SendReStartProcessEvent(eventInfo, appUid);
    EXPECT_EQ(appMgrServiceInner->killedProcessMap_.size(), 1);

    eventInfo.bundleName = testString1;
    eventInfo.callerBundleName = testString2;
    eventInfo.processName = testString1;
    eventInfo.callerProcessName = testString1;
    appMgrServiceInner->SendReStartProcessEvent(eventInfo, appUid);
    EXPECT_EQ(appMgrServiceInner->killedProcessMap_.size(), 1);

    eventInfo.bundleName = testString1;
    eventInfo.callerBundleName = testString1;
    eventInfo.processName = testString1;
    eventInfo.callerProcessName = testString2;
    appMgrServiceInner->SendReStartProcessEvent(eventInfo, appUid);
    EXPECT_EQ(appMgrServiceInner->killedProcessMap_.size(), 0);
}

/**
 * @tc.name: SendPreloadAppStartupTypeEvent_001
 * @tc.desc: SendPreloadAppStartupTypeEvent.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, SendPreloadAppStartupTypeEvent_001, TestSize.Level0)
{
    std::shared_ptr<AppRunningRecord> appRecord = nullptr;
    std::shared_ptr<AbilityInfo> abilityInfo = nullptr;
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    appMgrServiceInner->SendPreloadAppStartupTypeEvent(appRecord, abilityInfo);

    appRecord = std::make_shared<AppExecFwk::AppRunningRecord>(nullptr, 0, "");
    appRecord->SetPreloadState(PreloadState::PRELOADED);
    appMgrServiceInner->SendPreloadAppStartupTypeEvent(appRecord, abilityInfo);

    appRecord->SetPreloadState(PreloadState::NONE);
    appRecord->SetPreloadMode(PreloadMode::PRE_MAKE);
    appMgrServiceInner->SendPreloadAppStartupTypeEvent(appRecord, abilityInfo);

    appRecord->SetPreloadMode(PreloadMode::PRELOAD_MODULE);
    appMgrServiceInner->SendPreloadAppStartupTypeEvent(appRecord, abilityInfo);

    appRecord->SetPreloadMode(PreloadMode::PRESS_DOWN);
    appMgrServiceInner->SendPreloadAppStartupTypeEvent(appRecord, abilityInfo);
    EXPECT_NE(appMgrServiceInner, nullptr);
}

/**
 * @tc.name: SendAppStartupTypeEvent_001
 * @tc.desc: SendAppStartupTypeEvent.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, SendAppStartupTypeEvent_001, TestSize.Level0)
{
    std::shared_ptr<AppRunningRecord> appRecord = nullptr;
    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo1 = nullptr;
    AppStartType startType { AppStartType::COLD };
    AppStartReason reason { AppStartReason::NONE };

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    appMgrServiceInner->SendAppStartupTypeEvent(appRecord, abilityInfo1, startType, reason);

    appRecord = std::make_shared<AppExecFwk::AppRunningRecord>(nullptr, 0, "");
    appMgrServiceInner->SendAppStartupTypeEvent(appRecord, abilityInfo1, startType, reason);

    appRecord->appInfo_ = std::make_shared<ApplicationInfo>();
    appRecord->appInfo_->name = "name";
    appRecord->appInfo_->versionName = "versionName";
    appRecord->appInfo_->versionCode = 1;
    appRecord->priorityObject_ = std::make_shared<AppExecFwk::PriorityObject>();
    appRecord->priorityObject_->SetPid(9999);
    abilityInfo1 = std::make_shared<AppExecFwk::AbilityInfo>();
    abilityInfo1->name = "name";

    appMgrServiceInner->SendAppStartupTypeEvent(appRecord, abilityInfo1, startType, reason);
    EXPECT_NE(appMgrServiceInner, nullptr);
}

/**
 * @tc.name: CacheExitInfo_001
 * @tc.desc: CacheExitInfo.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, CacheExitInfo_001, TestSize.Level0)
{
    std::shared_ptr<AppRunningRecord> appRecord = nullptr;
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    appMgrServiceInner->CacheExitInfo(appRecord);

    appRecord = std::make_shared<AppExecFwk::AppRunningRecord>(nullptr, 0, "");
    appRecord->SetReasonExist(true);
    appMgrServiceInner->CacheExitInfo(appRecord);

    appRecord->SetReasonExist(false);
    appMgrServiceInner->CacheExitInfo(appRecord);

    appRecord->SetUid(1);
    appRecord->SetRssValue(1);
    appRecord->SetPssValue(1);
    appRecord->processName_ = "processName";
    appRecord->appInfo_ = std::make_shared<AppExecFwk::ApplicationInfo>();
    appMgrServiceInner->CacheExitInfo(appRecord);

    auto moduleRunningRecord =
        std::make_shared<AppExecFwk::ModuleRunningRecord>(nullptr, nullptr);
    sptr<IRemoteObject> iremoteObject =
        sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    auto abilityRunningRecord =
        std::make_shared<AppExecFwk::AbilityRunningRecord>(nullptr, nullptr, 1);
    abilityRunningRecord->info_ =
        std::make_shared<AppExecFwk::AbilityInfo>();
    abilityRunningRecord->info_->type = AppExecFwk::AbilityType::PAGE;
    abilityRunningRecord->info_->name = "applicationName";
    moduleRunningRecord->abilities_.emplace(iremoteObject, abilityRunningRecord);
    std::vector<std::shared_ptr<AppExecFwk::ModuleRunningRecord>> modulerunningrecordVector;
    modulerunningrecordVector.push_back(moduleRunningRecord);
    appRecord->hapModules_.emplace(std::make_pair("111", modulerunningrecordVector));

    AppMgrServiceInner::AppStateCallbackWithUserId appStateCallbackWithUserId;
    appStateCallbackWithUserId.callback = nullptr;
    appMgrServiceInner->appStateCallbacks_.push_back(appStateCallbackWithUserId);
    appMgrServiceInner->CacheExitInfo(appRecord);

    appMgrServiceInner->appStateCallbacks_.clear();
    appStateCallbackWithUserId.callback = sptr<MockIAppStateCallback>::MakeSptr();
    appMgrServiceInner->appStateCallbacks_.push_back(appStateCallbackWithUserId);
    appMgrServiceInner->CacheExitInfo(appRecord);
    for (auto &item : appMgrServiceInner->appStateCallbacks_) {
        MockIAppStateCallback* rawPtr =
            static_cast<MockIAppStateCallback*>(item.callback.GetRefPtr());
        if (rawPtr) {
            sptr<MockIAppStateCallback> iapp(rawPtr);
            EXPECT_EQ(iapp->dealed, true);
        }   
    }
}

/**
 * @tc.name: HandleConfigurationChange_001
 * @tc.desc: HandleConfigurationChange.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, HandleConfigurationChange_001, TestSize.Level0)
{
    Configuration config;
    int32_t userId = -1;
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    AppMgrServiceInner::AppStateCallbackWithUserId appStateCallbackWithUserId;
    appStateCallbackWithUserId.callback = nullptr;
    appStateCallbackWithUserId.userId = 0;
    appMgrServiceInner->appStateCallbacks_.push_back(appStateCallbackWithUserId);
    appMgrServiceInner->HandleConfigurationChange(config, userId);

    appMgrServiceInner->appStateCallbacks_.clear();
    appStateCallbackWithUserId.userId = -1;
    appMgrServiceInner->appStateCallbacks_.push_back(appStateCallbackWithUserId);
    appMgrServiceInner->HandleConfigurationChange(config, userId);

    appMgrServiceInner->appStateCallbacks_.clear();
    userId = 0;
    appStateCallbackWithUserId.userId = 0;
    appMgrServiceInner->appStateCallbacks_.push_back(appStateCallbackWithUserId);
    appMgrServiceInner->HandleConfigurationChange(config, userId);

    appMgrServiceInner->appStateCallbacks_.clear();
    appStateCallbackWithUserId.userId = -1;
    appMgrServiceInner->appStateCallbacks_.push_back(appStateCallbackWithUserId);
    appMgrServiceInner->HandleConfigurationChange(config, userId);

    appMgrServiceInner->appStateCallbacks_.clear();
    appStateCallbackWithUserId.callback = sptr<MockIAppStateCallback>::MakeSptr();
    userId = 1;
    appStateCallbackWithUserId.userId = 2;
    appMgrServiceInner->appStateCallbacks_.push_back(appStateCallbackWithUserId);
    appMgrServiceInner->HandleConfigurationChange(config, userId);

    appMgrServiceInner->appStateCallbacks_.clear();
    userId = -1;
    appMgrServiceInner->appStateCallbacks_.push_back(appStateCallbackWithUserId);
    appMgrServiceInner->HandleConfigurationChange(config, userId);
    for (auto &item : appMgrServiceInner->appStateCallbacks_) {
        MockIAppStateCallback* rawPtr =
            static_cast<MockIAppStateCallback*>(item.callback.GetRefPtr());
        if (rawPtr) {
            sptr<MockIAppStateCallback> iapp(rawPtr);
            EXPECT_EQ(iapp->dealed, true);
        }
    }
}
} // namespace AppExecFwk
} // namespace OHOS
