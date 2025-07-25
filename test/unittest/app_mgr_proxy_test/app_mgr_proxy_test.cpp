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

#include "ability_foreground_state_observer_interface.h"
#include "app_foreground_state_observer_stub.h"
#include "app_mgr_proxy.h"
#include "hilog_tag_wrapper.h"
#include "mock_ability_foreground_state_observer_stub.h"
#include "mock_app_mgr_service.h"
#include "quick_fix_callback_stub.h"
#include "render_state_observer_stub.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t USER_ID = 100;
constexpr int32_t MAX_BACKGROUND_APP_COUNT = 1000;
} // namespace

class AppForegroundStateObserverMock : public AppForegroundStateObserverStub {
public:
    AppForegroundStateObserverMock() = default;
    virtual ~AppForegroundStateObserverMock() = default;

    void OnAppStateChanged(const AppStateData &appStateData) override
    {}
};

class RenderStateObserverMock : public RenderStateObserverStub {
public:
    RenderStateObserverMock() = default;
    virtual ~RenderStateObserverMock() = default;
    void OnRenderStateChanged(const RenderStateData &renderStateData) override
    {}
};

class QuickFixCallbackImpl : public AppExecFwk::QuickFixCallbackStub {
public:
    QuickFixCallbackImpl() = default;
    virtual ~QuickFixCallbackImpl() = default;

    void OnLoadPatchDone(int32_t resultCode, int32_t recordId) override
    {
        TAG_LOGD(AAFwkTag::TEST, "function called.");
    }

    void OnUnloadPatchDone(int32_t resultCode, int32_t recordId) override
    {
        TAG_LOGD(AAFwkTag::TEST, "function called.");
    }

    void OnReloadPageDone(int32_t resultCode, int32_t recordId) override
    {
        TAG_LOGD(AAFwkTag::TEST, "function called.");
    }
};

class AppMgrProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    sptr<MockAppMgrService> mockAppMgrService_;
    sptr<AppMgrProxy> appMgrProxy_;
};

void AppMgrProxyTest::SetUpTestCase(void)
{}

void AppMgrProxyTest::TearDownTestCase(void)
{}

void AppMgrProxyTest::SetUp()
{
    GTEST_LOG_(INFO) << "AppMgrProxyTest::SetUp()";

    mockAppMgrService_ = new MockAppMgrService();
    appMgrProxy_ = new AppMgrProxy(mockAppMgrService_);
}

void AppMgrProxyTest::TearDown()
{}

/**
 * @tc.name: AppMgrProxy_GetProcessRunningInfosByUserId_0100
 * @tc.desc: GetProcessRunningInfosByUserId
 * @tc.type: FUNC
 * @tc.require: SR000GH1GO
 */
HWTEST_F(AppMgrProxyTest, AppMgrProxy_GetProcessRunningInfosByUserId_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "AppMgrProxy_GetProcessRunningInfosByUserId_0100 start";

    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::vector<RunningProcessInfo> info;
    appMgrProxy_->GetProcessRunningInfosByUserId(info, USER_ID);

    EXPECT_EQ(
        mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::APP_GET_RUNNING_PROCESSES_BY_USER_ID));

    GTEST_LOG_(INFO) << "AppMgrProxy_GetProcessRunningInfosByUserId_0100 end";
}

/**
 * @tc.name: AppMgrProxy_GetAllRenderProcesses_0100
 * @tc.desc: GetAllRenderProcesses
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, AppMgrProxy_GetAllRenderProcesses_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AppMgrProxy_GetAllRenderProcesses_0100 start";

    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::vector<RenderProcessInfo> info;
    appMgrProxy_->GetAllRenderProcesses(info);

    EXPECT_EQ(
        mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::APP_GET_ALL_RENDER_PROCESSES));

    GTEST_LOG_(INFO) << "AppMgrProxy_GetAllRenderProcesses_0100 end";
}

#ifdef SUPPORT_CHILD_PROCESS
/**
 * @tc.name: AppMgrProxy_GetAllChildrenProcesses_0100
 * @tc.desc: GetAllChildrenProcesses
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, AppMgrProxy_GetAllChildrenProcesses_0100, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "AppMgrProxy_GetAllChildrenProcesses_0100 start";

    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::vector<ChildProcessInfo> info;
    appMgrProxy_->GetAllChildrenProcesses(info);

    EXPECT_EQ(
        mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::GET_ALL_CHILDREN_PROCESSES));

    GTEST_LOG_(INFO) << "AppMgrProxy_GetAllChildrenProcesses_0100 end";
}
#endif // SUPPORT_CHILD_PROCESS

/**
 * @tc.name: GetAppRunningStateByBundleName_0100
 * @tc.desc: Get app running state by bundle name.
 * @tc.type: FUNC
 * @tc.require: issueI581VW
 */
HWTEST_F(AppMgrProxyTest, GetAppRunningStateByBundleName_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "%{public}s start.", __func__);

    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "testBundleName";
    appMgrProxy_->GetAppRunningStateByBundleName(bundleName);

    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::GET_APP_RUNNING_STATE));

    TAG_LOGI(AAFwkTag::TEST, "%{public}s end.", __func__);
}

/**
 * @tc.name: NotifyLoadRepairPatch_0100
 * @tc.desc: Notify load repair patch.
 * @tc.type: FUNC
 * @tc.require: issueI581VW
 */
HWTEST_F(AppMgrProxyTest, NotifyLoadRepairPatch_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "%{public}s start.", __func__);

    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "testBundleName";
    sptr<IQuickFixCallback> callback = new QuickFixCallbackImpl();
    appMgrProxy_->NotifyLoadRepairPatch(bundleName, callback);

    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::NOTIFY_LOAD_REPAIR_PATCH));

    TAG_LOGI(AAFwkTag::TEST, "%{public}s end.", __func__);
}

/**
 * @tc.name: NotifyHotReloadPage_0100
 * @tc.desc: Notify ace execute hot reload page.
 * @tc.type: FUNC
 * @tc.require: issueI581VW
 */
HWTEST_F(AppMgrProxyTest, NotifyHotReloadPage_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "%{public}s start", __func__);

    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "testBundleName";
    sptr<IQuickFixCallback> callback = new QuickFixCallbackImpl();
    appMgrProxy_->NotifyHotReloadPage(bundleName, callback);

    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::NOTIFY_HOT_RELOAD_PAGE));

    TAG_LOGI(AAFwkTag::TEST, "%{public}s end", __func__);
}

/**
 * @tc.name: NotifyUnLoadRepairPatch_0100
 * @tc.desc: Notify unload repair patch.
 * @tc.type: FUNC
 * @tc.require: issueI581VW
 */
HWTEST_F(AppMgrProxyTest, NotifyUnLoadRepairPatch_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "%{public}s start.", __func__);

    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "testBundleName";
    sptr<IQuickFixCallback> callback = new QuickFixCallbackImpl();
    appMgrProxy_->NotifyUnLoadRepairPatch(bundleName, callback);

    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::NOTIFY_UNLOAD_REPAIR_PATCH));

    TAG_LOGI(AAFwkTag::TEST, "%{public}s end.", __func__);
}

/**
 * @tc.name: PreStartNWebSpawnProcess_001
 * @tc.desc: prestart nwebspawn process.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrProxyTest, PreStartNWebSpawnProcess_001, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "%{public}s start.", __func__);

    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    appMgrProxy_->PreStartNWebSpawnProcess();
    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::PRE_START_NWEBSPAWN_PROCESS));

    TAG_LOGI(AAFwkTag::TEST, "%{public}s end.", __func__);
}

/**
 * @tc.name: GetProcessMemoryByPid_001
 * @tc.desc: Get memorySize by pid.
 * @tc.type: FUNC
 * @tc.require: issueI76JBF
 */
HWTEST_F(AppMgrProxyTest, GetProcessMemoryByPid_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "%{public}s start.", __func__);

    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    int32_t pid = 0;
    int32_t memorySize = 0;
    appMgrProxy_->GetProcessMemoryByPid(pid, memorySize);
    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::GET_PROCESS_MEMORY_BY_PID));

    TAG_LOGI(AAFwkTag::TEST, "%{public}s end.", __func__);
}

/**
 * @tc.name: GetRunningProcessInformation_001
 * @tc.desc: Get application processes information list by bundleName.
 * @tc.type: FUNC
 * @tc.require: issueI76JBF
 */
HWTEST_F(AppMgrProxyTest, GetRunningProcessInformation_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "%{public}s start.", __func__);

    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "testBundleName";
    int32_t userId = USER_ID;
    std::vector<RunningProcessInfo> info;
    appMgrProxy_->GetRunningProcessInformation(bundleName, userId, info);
    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::GET_PIDS_BY_BUNDLENAME));

    TAG_LOGI(AAFwkTag::TEST, "%{public}s end.", __func__);
}

/**
 * @tc.name: NotifyAppFault_001
 * @tc.desc: Notify app fault.
 * @tc.type: FUNC
 * @tc.require: issueI79RY8
 */
HWTEST_F(AppMgrProxyTest, NotifyAppFault_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));
    FaultData faultData;
    appMgrProxy_->NotifyAppFault(faultData);
    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::NOTIFY_APP_FAULT));
}

/**
 * @tc.name: NotifyAppFaultBySA_001
 * @tc.desc: Notify app fault by SA.
 * @tc.type: FUNC
 * @tc.require: issueI79RY8
 */
HWTEST_F(AppMgrProxyTest, NotifyAppFaultBySA_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));
    AppFaultDataBySA faultData;
    appMgrProxy_->NotifyAppFaultBySA(faultData);
    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::NOTIFY_APP_FAULT_BY_SA));
}

/**
 * @tc.name: SetAppFreezeFilter_001
 * @tc.desc: Set appfreeze filter.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, SetAppFreezeFilter_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));
    int32_t pid = 0; // test value
    appMgrProxy_->SetAppFreezeFilter(pid);
    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::SET_APPFREEZE_FILTER));
}

/**
 * @tc.name: ChangeAppGcState_001
 * @tc.desc: Change app Gc state.
 * @tc.type: FUNC
 * @tc.require: issuesI85VVU
 */
HWTEST_F(AppMgrProxyTest, ChangeAppGcState_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));
    int32_t pid = 0;
    int32_t state = 0;
    appMgrProxy_->ChangeAppGcState(pid, state);
    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::CHANGE_APP_GC_STATE));
}

/**
 * @tc.name: ChangeAppGcState_002
 * @tc.desc: Change app Gc state.
 * @tc.type: FUNC
 * @tc.require: issuesI85VVU
 */
HWTEST_F(AppMgrProxyTest, ChangeAppGcState_002, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));
    int32_t pid = 0;
    int32_t state = 0;
    uint64_t tid = 1;
    appMgrProxy_->ChangeAppGcState(pid, state, tid);
    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::CHANGE_APP_GC_STATE));
}

/**
 * @tc.name: IsApplicationRunning_001
 * @tc.desc: Send request to query the running status of the application.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, IsApplicationRunning_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "testBundleName";
    bool isRunning = false;
    appMgrProxy_->IsApplicationRunning(bundleName, isRunning);
    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::IS_APPLICATION_RUNNING));
}

/**
 * @tc.name: IsAppRunning_001
 * @tc.desc: Send request to query the running status of the application.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, IsAppRunning_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "testBundleName";
    int32_t appCloneIndex = 0;
    bool isRunning = false;

    appMgrProxy_->IsAppRunning(bundleName, appCloneIndex, isRunning);
    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::IS_APP_RUNNING));
}

/**
 * @tc.number: RegisterAbilityForegroundStateObserver_0100
 * @tc.desc: Verify that the RegisterAbilityForegroundStateObserver function is called normally.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, RegisterAbilityForegroundStateObserver_0100, TestSize.Level1)
{
    sptr<IAbilityForegroundStateObserver> observer = new MockAbilityForegroundStateObserverStub();
    EXPECT_NE(observer->AsObject(), nullptr);
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));
    appMgrProxy_->RegisterAbilityForegroundStateObserver(observer);
    EXPECT_EQ(mockAppMgrService_->code_,
        static_cast<uint32_t>(AppMgrInterfaceCode::REGISTER_ABILITY_FOREGROUND_STATE_OBSERVER));
}

/**
 * @tc.number: RegisterAbilityForegroundStateObserver_0200
 * @tc.desc: Verify that the RegisterAbilityForegroundStateObserver parameter of the function is null.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, RegisterAbilityForegroundStateObserver_0200, TestSize.Level1)
{
    sptr<IAbilityForegroundStateObserver> observer = nullptr;
    auto result = appMgrProxy_->RegisterAbilityForegroundStateObserver(observer);
    EXPECT_EQ(result, OHOS::ERR_INVALID_VALUE);
}

/**
 * @tc.number: UnregisterAbilityForegroundStateObserver_0100
 * @tc.desc: Verify that the UnregisterAbilityForegroundStateObserver function is called normally.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, UnregisterAbilityForegroundStateObserver_0100, TestSize.Level1)
{
    sptr<IAbilityForegroundStateObserver> observer = new MockAbilityForegroundStateObserverStub();
    EXPECT_NE(observer->AsObject(), nullptr);
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));
    appMgrProxy_->UnregisterAbilityForegroundStateObserver(observer);
    EXPECT_EQ(mockAppMgrService_->code_,
        static_cast<uint32_t>(AppMgrInterfaceCode::UNREGISTER_ABILITY_FOREGROUND_STATE_OBSERVER));
}

/**
 * @tc.number: RegisterAbilityForegroundStateObserver_0200
 * @tc.desc: Verify that the UnregisterAbilityForegroundStateObserver parameter of the function is null.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, UnregisterAbilityForegroundStateObserver_0200, TestSize.Level1)
{
    sptr<IAbilityForegroundStateObserver> observer = nullptr;
    auto result = appMgrProxy_->UnregisterAbilityForegroundStateObserver(observer);
    EXPECT_EQ(result, OHOS::ERR_INVALID_VALUE);
}

/**
 * @tc.name: RegisterAppForegroundStateObserver_0100
 * @tc.desc: Test when all condition not met.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, RegisterAppForegroundStateObserver_0100, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _)).Times(1);
    sptr<IAppForegroundStateObserver> observer = new (std::nothrow) AppForegroundStateObserverMock();
    auto res = appMgrProxy_->RegisterAppForegroundStateObserver(observer);
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.name: UnregisterAppForegroundStateObserver_0100
 * @tc.desc: Test when all condition not met.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, UnregisterAppForegroundStateObserver_0100, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _)).Times(1);
    sptr<IAppForegroundStateObserver> observer = new (std::nothrow) AppForegroundStateObserverMock();
    auto res = appMgrProxy_->RegisterAppForegroundStateObserver(observer);
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.name: RegisterRenderStateObserver_0100
 * @tc.desc: Test registerRenderStateObserversendRequest.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, RegisterRenderStateObserver_0100, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _)).Times(1);
    sptr<IRenderStateObserver> observer = new (std::nothrow) RenderStateObserverMock();
    auto res = appMgrProxy_->RegisterRenderStateObserver(observer);
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.name: UnregisterRenderStateObserver_0100
 * @tc.desc: Test unregisterRenderStateObserversendRequest.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, UnregisterRenderStateObserver_0100, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _)).Times(1);
    sptr<IRenderStateObserver> observer = new (std::nothrow) RenderStateObserverMock();
    auto res = appMgrProxy_->UnregisterRenderStateObserver(observer);
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.name: UpdateRenderState_0100
 * @tc.desc: Test updateRenderState sendRequest.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, UpdateRenderState_0100, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _)).Times(1);
    pid_t renderPid = 0;
    int32_t state = 0;
    auto res = appMgrProxy_->UpdateRenderState(renderPid, state);
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.name: SignRestartAppFlag_0100
 * @tc.desc: Test SignRestartAppFlag.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, SignRestartAppFlag_0100, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _)).Times(1);
    int32_t uid = 0;
    auto res = appMgrProxy_->SignRestartAppFlag(uid, "");
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.name: NotifyMemorySizeStateChanged_0100
 * @tc.desc: Test NotifyMemorySizeStateChanged.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, NotifyMemorySizeStateChanged_0100, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _)).Times(1);
    int32_t memorySizeState = 1;
    auto res = appMgrProxy_->NotifyMemorySizeStateChanged(memorySizeState);
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.name: NotifyMemorySizeStateChanged_0200
 * @tc.desc: Test NotifyMemorySizeStateChanged.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, NotifyMemorySizeStateChanged_0200, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _)).Times(1);
    int32_t memorySizeState = 0;
    auto res = appMgrProxy_->NotifyMemorySizeStateChanged(memorySizeState);
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.name: GetAllUIExtensionRootHostPid_0100
 * @tc.desc: Get all ui extension root host pid.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, GetAllUIExtensionRootHostPid_0100, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));
    pid_t pid = 0;
    std::vector<pid_t> hostPids;
    auto res = appMgrProxy_->GetAllUIExtensionRootHostPid(pid, hostPids);
    EXPECT_EQ(res, NO_ERROR);
    EXPECT_EQ(mockAppMgrService_->code_,
        static_cast<uint32_t>(AppMgrInterfaceCode::GET_ALL_UI_EXTENSION_ROOT_HOST_PID));
}

/**
 * @tc.name: GetAllUIExtensionProviderPid_0100
 * @tc.desc: Get all ui extension provider pid.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, GetAllUIExtensionProviderPid_0100, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));
    pid_t hostPid = 0;
    std::vector<pid_t> providerPids;
    auto res = appMgrProxy_->GetAllUIExtensionProviderPid(hostPid, providerPids);
    EXPECT_EQ(res, NO_ERROR);
    EXPECT_EQ(mockAppMgrService_->code_,
        static_cast<uint32_t>(AppMgrInterfaceCode::GET_ALL_UI_EXTENSION_PROVIDER_PID));
}

/**
 * @tc.name: PreloadApplication_0100
 * @tc.desc: Preload application.
 * @tc.type: FUNC
 * @tc.Function: PreloadApplication
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppMgrProxyTest, PreloadApplication_0100, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "com.acts.preloadtest";
    int32_t userId = 100;
    PreloadMode preloadMode = PreloadMode::PRE_MAKE;
    int32_t appIndex = 0;
    auto ret = appMgrProxy_->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, NO_ERROR);
    EXPECT_EQ(mockAppMgrService_->code_,
        static_cast<uint32_t>(AppMgrInterfaceCode::PRELOAD_APPLICATION));
}

/**
 * @tc.name: PreloadApplication_0200
 * @tc.desc: Preload application.
 * @tc.type: FUNC
 * @tc.Function: PreloadApplication
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppMgrProxyTest, PreloadApplication_0200, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "";
    int32_t userId = 100;
    PreloadMode preloadMode = PreloadMode::PRE_MAKE;
    int32_t appIndex = 0;
    auto ret = appMgrProxy_->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, NO_ERROR);
    EXPECT_EQ(mockAppMgrService_->code_,
        static_cast<uint32_t>(AppMgrInterfaceCode::PRELOAD_APPLICATION));
}

/**
 * @tc.name: PreloadApplication_0300
 * @tc.desc: Preload application.
 * @tc.type: FUNC
 * @tc.Function: PreloadApplication
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppMgrProxyTest, PreloadApplication_0300, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "com.acts.preloadtest";
    int32_t userId = 100;
    PreloadMode preloadMode = PreloadMode::PRESS_DOWN;
    int32_t appIndex = 0;
    auto ret = appMgrProxy_->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, NO_ERROR);
    EXPECT_EQ(mockAppMgrService_->code_,
        static_cast<uint32_t>(AppMgrInterfaceCode::PRELOAD_APPLICATION));
}

/**
 * @tc.name: PreloadApplication_0400
 * @tc.desc: Preload application.
 * @tc.type: FUNC
 * @tc.Function: PreloadApplication
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppMgrProxyTest, PreloadApplication_0400, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "";
    int32_t userId = 100;
    PreloadMode preloadMode = PreloadMode::PRESS_DOWN;
    int32_t appIndex = 0;
    auto ret = appMgrProxy_->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, NO_ERROR);
    EXPECT_EQ(mockAppMgrService_->code_,
        static_cast<uint32_t>(AppMgrInterfaceCode::PRELOAD_APPLICATION));
}

/**
 * @tc.name: PreloadApplication_0500
 * @tc.desc: Preload application.
 * @tc.type: FUNC
 * @tc.Function: PreloadApplication
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppMgrProxyTest, PreloadApplication_0500, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "com.acts.preloadtest";
    int32_t userId = -1;
    PreloadMode preloadMode = PreloadMode::PRE_MAKE;
    int32_t appIndex = 0;
    auto ret = appMgrProxy_->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, NO_ERROR);
    EXPECT_EQ(mockAppMgrService_->code_,
        static_cast<uint32_t>(AppMgrInterfaceCode::PRELOAD_APPLICATION));
}

/**
 * @tc.name: PreloadApplication_0600
 * @tc.desc: Preload application.
 * @tc.type: FUNC
 * @tc.Function: PreloadApplication
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppMgrProxyTest, PreloadApplication_0600, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "";
    int32_t userId = -1;
    PreloadMode preloadMode = PreloadMode::PRE_MAKE;
    int32_t appIndex = 0;
    auto ret = appMgrProxy_->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, NO_ERROR);
    EXPECT_EQ(mockAppMgrService_->code_,
        static_cast<uint32_t>(AppMgrInterfaceCode::PRELOAD_APPLICATION));
}

/**
 * @tc.name: PreloadApplication_0700
 * @tc.desc: Preload application.
 * @tc.type: FUNC
 * @tc.Function: PreloadApplication
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppMgrProxyTest, PreloadApplication_0700, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "com.acts.preloadtest";
    int32_t userId = -1;
    PreloadMode preloadMode = PreloadMode::PRESS_DOWN;
    int32_t appIndex = 0;
    auto ret = appMgrProxy_->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, NO_ERROR);
    EXPECT_EQ(mockAppMgrService_->code_,
        static_cast<uint32_t>(AppMgrInterfaceCode::PRELOAD_APPLICATION));
}

/**
 * @tc.name: PreloadApplication_0800
 * @tc.desc: Preload application.
 * @tc.type: FUNC
 * @tc.Function: PreloadApplication
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppMgrProxyTest, PreloadApplication_0800, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "";
    int32_t userId = -1;
    PreloadMode preloadMode = PreloadMode::PRESS_DOWN;
    int32_t appIndex = 0;
    auto ret = appMgrProxy_->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, NO_ERROR);
    EXPECT_EQ(mockAppMgrService_->code_,
        static_cast<uint32_t>(AppMgrInterfaceCode::PRELOAD_APPLICATION));
}

/**
 * @tc.name: PreloadModuleFinished_0001
 * @tc.desc: Preload application.
 * @tc.type: FUNC
 * @tc.Function: PreloadModuleFinished
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppMgrProxyTest, PreloadModuleFinished_0001, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    int32_t recordId = 0;
    appMgrProxy_->PreloadModuleFinished(recordId);
}

/**
 * @tc.name: SetSupportedProcessCacheSelf_001
 * @tc.desc: The application sets itself whether or not to support process cache.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, SetSupportedProcessCacheSelf_001, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "%{public}s start.", __func__);

    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));
    bool isSupported = false;
    appMgrProxy_->SetSupportedProcessCacheSelf(isSupported);
    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::SET_SUPPORTED_PROCESS_CACHE_SELF));

    TAG_LOGI(AAFwkTag::TEST, "%{public}s end.", __func__);
}

/**
 * @tc.name: GetRunningMultiAppInfoByBundleName_001
 * @tc.desc: Get multiApp information by bundleName.
 * @tc.type: FUNC
 * @tc.require: issueI9HMAO
 */
HWTEST_F(AppMgrProxyTest, GetRunningMultiAppInfoByBundleName_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "%{public}s start.", __func__);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(AppMgrStub::GetDescriptor());
    std::string bundleName = "testBundleName";
    data.WriteString(bundleName);

    EXPECT_CALL(*mockAppMgrService_, GetRunningMultiAppInfoByBundleName(_, _)).Times(1);

    auto result = mockAppMgrService_->OnRemoteRequest(
        static_cast<uint32_t>(AppMgrInterfaceCode::GET_RUNNING_MULTIAPP_INFO_BY_BUNDLENAME), data, reply, option);
    EXPECT_EQ(result, NO_ERROR);

    TAG_LOGI(AAFwkTag::TEST, "%{public}s end.", __func__);
}

/**
 * @tc.name: GetAllRunningInstanceKeysBySelf_001
 * @tc.desc: GetAllRunningInstanceKeysBySelf.
 * @tc.type: FUNC
 * @tc.require: issueI9HMAO
 */
HWTEST_F(AppMgrProxyTest, GetAllRunningInstanceKeysBySelf_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "%{public}s start.", __func__);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(AppMgrStub::GetDescriptor());

    EXPECT_CALL(*mockAppMgrService_, GetAllRunningInstanceKeysBySelf(_)).Times(1);

    auto result = mockAppMgrService_->OnRemoteRequest(
        static_cast<uint32_t>(AppMgrInterfaceCode::GET_All_RUNNING_INSTANCE_KEYS_BY_SELF), data, reply, option);
    EXPECT_EQ(result, NO_ERROR);

    TAG_LOGI(AAFwkTag::TEST, "%{public}s end.", __func__);
}

/**
 * @tc.name: GetAllRunningInstanceKeysByBundleName_001
 * @tc.desc: GetAllRunningInstanceKeysByBundleName.
 * @tc.type: FUNC
 * @tc.require: issueI9HMAO
 */
HWTEST_F(AppMgrProxyTest, GetAllRunningInstanceKeysByBundleName_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "%{public}s start.", __func__);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(AppMgrStub::GetDescriptor());
    std::string bundleName = "testBundleName";
    data.WriteString(bundleName);
    int32_t userId = -1;
    data.WriteInt32(userId);

    EXPECT_CALL(*mockAppMgrService_, GetAllRunningInstanceKeysByBundleName(_, _, _)).Times(1);

    auto result = mockAppMgrService_->OnRemoteRequest(
        static_cast<uint32_t>(AppMgrInterfaceCode::GET_All_RUNNING_INSTANCE_KEYS_BY_BUNDLENAME), data, reply, option);
    EXPECT_EQ(result, NO_ERROR);

    TAG_LOGI(AAFwkTag::TEST, "%{public}s end.", __func__);
}

/**
 * @tc.name: GetSupportedProcessCachePids_001
 * @tc.desc: Get pids of processes which belong to specific bundle name and support process cache feature.
 * @tc.type: FUNC
 * @tc.require: issueIAGZ7H
 */
HWTEST_F(AppMgrProxyTest, GetSupportedProcessCachePids_001, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "%{public}s start.", __func__);

    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::string bundleName = "testBundleName";
    std::vector<int32_t> pidList;
    appMgrProxy_->GetSupportedProcessCachePids(bundleName, pidList);
    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::GET_SUPPORTED_PROCESS_CACHE_PIDS));

    TAG_LOGI(AAFwkTag::TEST, "%{public}s end.", __func__);
}

/**
 * @tc.name: UpdateConfigurationForBackgroundApp_001
 * @tc.desc: UpdateConfigurationForBackgroundApp.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppMgrProxyTest, UpdateConfigurationForBackgroundApp_001, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "%{public}s start.", __func__);

    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mockAppMgrService_.GetRefPtr(), &MockAppMgrService::InvokeSendRequest));

    std::vector<BackgroundAppInfo> appInfos;
    ConfigurationPolicy policy;
    int32_t userId = -1;

    auto ret = appMgrProxy_->UpdateConfigurationForBackgroundApp(appInfos, policy, userId);
    if (appInfos.size() == 0 || appInfos.size() > MAX_BACKGROUND_APP_COUNT) {
        EXPECT_EQ(ret, ERR_INVALID_DATA);
    }
    BackgroundAppInfo info;
    appInfos.push_back(info);
    appMgrProxy_->UpdateConfigurationForBackgroundApp(appInfos, policy, userId);
    EXPECT_EQ(mockAppMgrService_->code_, static_cast<uint32_t>(AppMgrInterfaceCode::UPDATE_CONFIGURATION_POLICY));

    TAG_LOGI(AAFwkTag::TEST, "%{public}s end.", __func__);
}

/**
 * @tc.name: IsProcessCacheSupported_0100
 * @tc.desc: Test IsProcessCacheSupported.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, IsProcessCacheSupported_0100, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _)).Times(1);
    int32_t pid = 1;
    bool isSupport = false;
    auto ret = appMgrProxy_->IsProcessCacheSupported(pid, isSupport);
    EXPECT_EQ(ret, NO_ERROR);
}

/**
 * @tc.name: SetProcessCacheEnable_0100
 * @tc.desc: Test SetProcessCacheEnable.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, SetProcessCacheEnable_0100, TestSize.Level1)
{
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _)).Times(1);
    int32_t pid = 1;
    bool enable = false;
    auto ret = appMgrProxy_->SetProcessCacheEnable(pid, enable);
    EXPECT_EQ(ret, NO_ERROR);
}

/**
 * @tc.name: QueryRunningSharedBundles_0100
 * @tc.desc: Test QueryRunningSharedBundles.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, QueryRunningSharedBundles_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "QueryRunningSharedBundles_0100 start.");
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_INVALID_VALUE));
    pid_t pid = 1;
    std::map<std::string, uint32_t> sharedBundles;
    auto ret = appMgrProxy_->QueryRunningSharedBundles(pid, sharedBundles);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "QueryRunningSharedBundles_0100 end.");
}

/**
 * @tc.name: QueryRunningSharedBundles_0200
 * @tc.desc: Test QueryRunningSharedBundles.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, QueryRunningSharedBundles_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "QueryRunningSharedBundles_0100 start.");
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce([](uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) {
            reply.WriteInt32(ERR_INVALID_VALUE);
            return NO_ERROR;
        });

    pid_t pid = 1;
    std::map<std::string, uint32_t> sharedBundles;
    auto ret = appMgrProxy_->QueryRunningSharedBundles(pid, sharedBundles);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "QueryRunningSharedBundles_0200 end.");
}

/**
 * @tc.name: QueryRunningSharedBundles_0300
 * @tc.desc: Test QueryRunningSharedBundles.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, QueryRunningSharedBundles_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "QueryRunningSharedBundles_0100 start.");
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce([](uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) {
            reply.WriteInt32(ERR_OK);
            reply.WriteInt32(1001);
            return NO_ERROR;
        });

    pid_t pid = 1;
    std::map<std::string, uint32_t> sharedBundles;
    auto ret = appMgrProxy_->QueryRunningSharedBundles(pid, sharedBundles);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "QueryRunningSharedBundles_0300 end.");
}

/**
 * @tc.name: QueryRunningSharedBundles_0400
 * @tc.desc: Test QueryRunningSharedBundles.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrProxyTest, QueryRunningSharedBundles_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "QueryRunningSharedBundles_0400 start.");
    EXPECT_CALL(*mockAppMgrService_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce([](uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) {
            reply.WriteInt32(ERR_OK);
            reply.WriteInt32(1);
            reply.WriteString("com.test.example");
            reply.WriteUint32(10000);
            return NO_ERROR;
        });

    pid_t pid = 1;
    std::map<std::string, uint32_t> sharedBundles;
    auto ret = appMgrProxy_->QueryRunningSharedBundles(pid, sharedBundles);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(sharedBundles.empty());
    TAG_LOGI(AAFwkTag::TEST, "QueryRunningSharedBundles_0300 end.");
}
} // namespace AppExecFwk
} // namespace OHOS
