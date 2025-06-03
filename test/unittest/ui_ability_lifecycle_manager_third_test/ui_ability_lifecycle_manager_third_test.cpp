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

#include "ability_manager_errors.h"
#include "ability_util.h"
#define private public
#define protected public
#include "ability_record.h"
#include "app_mgr_util.h"
#include "app_utils.h"
#include "scene_board/ui_ability_lifecycle_manager.h"
#undef protected
#undef private
#include "ability_start_setting.h"
#include "app_scheduler.h"
#include "app_mgr_client.h"
#include "display_util.h"
#include "mock_ability_info_callback_stub.h"
#include "process_options.h"
#include "session/host/include/session.h"
#include "session_info.h"
#include "startup_util.h"
#include "status_bar_delegate_interface.h"
#include "scene_board/status_bar_delegate_manager.h"
#include "server_constant.h"
#define private public
#define protected public
#include "ability_manager_service.h"
#undef protected
#undef private
#include "ability_scheduler_mock.h"
#include "hilog_tag_wrapper.h"
#include "mock_my_flag.h"
#include "mock_permission_verification.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
namespace {
#ifdef WITH_DLP
const std::string DLP_INDEX = "ohos.dlp.params.index";
#endif // WITH_DLP
constexpr int32_t TEST_UID = 20010001;
};
class UIAbilityLifecycleManagerThirdTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<AbilityRecord> InitAbilityRecord();
};

void UIAbilityLifecycleManagerThirdTest::SetUpTestCase() {}

void UIAbilityLifecycleManagerThirdTest::TearDownTestCase() {}

void UIAbilityLifecycleManagerThirdTest::SetUp() {}

void UIAbilityLifecycleManagerThirdTest::TearDown() {}

class UIAbilityLifcecycleManagerThirdTestStub : public IRemoteStub<IAbilityConnection> {
public:
    UIAbilityLifcecycleManagerThirdTestStub() {};
    virtual ~UIAbilityLifcecycleManagerThirdTestStub() {};

    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
    {
        return 0;
    };

    virtual void OnAbilityConnectDone(
        const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int resultCode) {};

    /**
     * OnAbilityDisconnectDone, AbilityMs notify caller ability the result of disconnect.
     *
     * @param element, service ability's ElementName.
     * @param resultCode, ERR_OK on success, others on failure.
     */
    virtual void OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode) {};
};

std::shared_ptr<AbilityRecord> UIAbilityLifecycleManagerThirdTest::InitAbilityRecord()
{
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    return abilityRecord;
}

class MockIStatusBarDelegate : public OHOS::AbilityRuntime::IStatusBarDelegate {
public:
    int32_t CheckIfStatusBarItemExists(uint32_t accessTokenId, const std::string &instanceKey,
        bool& isExist)
    {
        return 0;
    }
    int32_t AttachPidToStatusBarItem(uint32_t accessTokenId, int32_t pid, const std::string &instanceKey)
    {
        return 0;
    }
    int32_t DetachPidToStatusBarItem(uint32_t accessTokenId, int32_t pid, const std::string &instanceKey)
    {
        return 0;
    }
    sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    }
};

class MockIRemoteObject : public IRemoteObject {
public:
    MockIRemoteObject() : IRemoteObject(u"mock_i_remote_object") {}

    ~MockIRemoteObject() {}

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }

    bool IsProxyObject() const override
    {
        return true;
    }

    bool CheckObjectLegality() const override
    {
        return true;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }

    sptr<IRemoteBroker> AsInterface() override
    {
        return nullptr;
    }

    int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }

    std::u16string GetObjectDescriptor() const
    {
        std::u16string descriptor = std::u16string();
        return descriptor;
    }
};

class SysMrgClient {
public:
    static SysMrgClient* instance_;

    SysMrgClient* GetInstance()
    {
        return instance_;
    }
};
SysMrgClient* SysMrgClient::instance_ = nullptr;

/**
 * @tc.name: FindRecordFromTmpMap_001
 * @tc.desc: FindRecordFromTmpMap
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, FindRecordFromTmpMap_001, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();
    
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.name = "Name";
    abilityRequest.abilityInfo.bundleName = "BundleName";
    abilityRequest.abilityInfo.moduleName = "ModuleName";
    abilityRequest.want.SetParam(Want::APP_INSTANCE_KEY, std::string("InstanceKey"));
    abilityRequest.want.SetParam(ServerConstant::DLP_INDEX, 5);
    
    auto callerAbilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    callerAbilityRecord->sessionInfo_ = nullptr;
    callerAbilityRecord->SetAppIndex(5);
    callerAbilityRecord->SetInstanceKey("InstanceKey");

    mgr->tmpAbilityMap_ = {{1, callerAbilityRecord}};

    auto ret = mgr->FindRecordFromTmpMap(abilityRequest);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name: CheckSessionInfo_001
 * @tc.desc: CheckSessionInfo
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, CheckSessionInfo_001, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();
    auto currentSessionInfo = sptr<AAFwk::SessionInfo>::MakeSptr();
    Rosen::SessionInfo info;
    sptr<Rosen::ISession> session = sptr<Rosen::Session>::MakeSptr(info);
    currentSessionInfo->sessionToken = session->AsObject();

    AbilityRequest abilityRequest;
    auto callerAbilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    callerAbilityRecord->sessionInfo_ = nullptr;

    auto ret = mgr->CheckSessionInfo(currentSessionInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: UIAbilityLifecycleManager_AbilityWindowConfigTransactionDone_0300
 * @tc.desc: AbilityWindowConfigTransactionDone
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, AbilityWindowConfigTransactionDone_003, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();

    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);

    auto token = sptr<Token>::MakeSptr(abilityRecord);
    abilityRecord->token_ = token;

    mgr->terminateAbilityList_ = { abilityRecord };
    
    WindowConfig windowConfig;

    auto ret = mgr->AbilityWindowConfigTransactionDone(token, windowConfig);

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: UIAbilityLifecycleManager_NotifySCBToStartUIAbility_0300
 * @tc.desc: NotifySCBToStartUIAbility
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, NotifySCBToStartUIAbility_003, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();

    std::map<int32_t, std::vector<int64_t>> startUIAbilityCallerTimestamps;
    std::vector<int64_t> callerTimestamps = {};
    constexpr int32_t START_UI_ABILITY_PER_SECOND_UPPER_LIMIT = 20;
    auto curTimeNs = AbilityUtil::GetSysTimeNs();
    for (int i = 0; i < START_UI_ABILITY_PER_SECOND_UPPER_LIMIT + 2; i++) {
        callerTimestamps.emplace_back(curTimeNs);
    }
    startUIAbilityCallerTimestamps.emplace(2, callerTimestamps);
    mgr->startUIAbilityCallerTimestamps_ = startUIAbilityCallerTimestamps;

    AbilityRequest abilityRequest;
    abilityRequest.want.SetParam(Want::PARAM_RESV_CALLER_UID, 2);

    auto ret = mgr->NotifySCBToStartUIAbility(abilityRequest);

    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: UIAbilityLifecycleManager_DispatchForeground_0200
 * @tc.desc: DispatchForeground
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, DispatchForeground_002, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();

    AbilityState state = AbilityState::ACTIVE;

    std::shared_ptr<TaskHandlerWrap> runner;
    std::weak_ptr<AbilityManagerService> server;
    auto handler = std::make_shared<AbilityEventHandler>(runner, server);
    DelayedSingleton<AbilityManagerService>::GetInstance()->eventHandler_ = handler;

    auto taskHandler = TaskHandlerWrap::CreateQueueHandler("HelloWorld");
    DelayedSingleton<AbilityManagerService>::GetInstance()->taskHandler_ = nullptr;

    std::shared_ptr<AbilityRecord> abilityRecord = nullptr;

    auto ret = mgr->DispatchForeground(abilityRecord, true, state);

    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: UIAbilityLifecycleManager_DispatchForeground_0300
 * @tc.desc: DispatchForeground
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, DispatchForeground_003, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();

    AbilityState state = AbilityState::ACTIVE;

    std::shared_ptr<TaskHandlerWrap> runner;
    std::weak_ptr<AbilityManagerService> server;
    auto handler = std::make_shared<AbilityEventHandler>(runner, server);
    DelayedSingleton<AbilityManagerService>::GetInstance()->eventHandler_ = handler;

    auto taskHandler = TaskHandlerWrap::CreateQueueHandler("HelloWorld");
    DelayedSingleton<AbilityManagerService>::GetInstance()->taskHandler_ = nullptr;

    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->currentState_ = AbilityState::ACTIVATING;

    auto ret = mgr->DispatchForeground(abilityRecord, true, state);

    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: UIAbilityLifecycleManager_DispatchBackground_0200
 * @tc.desc: DispatchBackground
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, DispatchBackground_002, TestSize.Level1)
{
    auto mgr = std::make_shared<UIAbilityLifecycleManager>();
    
    auto taskHandler = TaskHandlerWrap::CreateQueueHandler("HelloWorld");
    DelayedSingleton<AbilityManagerService>::GetInstance()->taskHandler_ = taskHandler;

    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->currentState_ = AbilityState::BACKGROUNDING;

    auto ret = mgr->DispatchBackground(abilityRecord);

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: UIAbilityLifecycleManager_UpdateProcessName_0200
 * @tc.desc: UpdateProcessName
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, UpdateProcessName_002, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);
    sptr<SessionInfo> sessionInfo = new (std::nothrow) SessionInfo();
    sessionInfo->processOptions = std::make_shared<ProcessOptions>();
    EXPECT_NE(sessionInfo->processOptions, nullptr);
    sessionInfo->processOptions->processMode = ProcessMode::NEW_PROCESS_ATTACH_TO_PARENT;
    sessionInfo->processOptions->processName = "HeavenlyMe";
    AbilityRequest abilityRequest;
    abilityRequest.sessionInfo = sessionInfo;
    abilityRequest.abilityInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.moduleName = "entry";
    abilityRequest.abilityInfo.name = "MainAbility";
    std::shared_ptr<AbilityRecord> abilityRecord = InitAbilityRecord();
    uiAbilityLifecycleManager->UpdateProcessName(abilityRequest, abilityRecord);
    EXPECT_EQ("HeavenlyMe", abilityRecord->GetProcessName());
}

/**
 * @tc.name: UIAbilityLifecycleManager_UpdateAbilityRecordLaunchReason_0500
 * @tc.desc: UpdateAbilityRecordLaunchReason
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, UpdateAbilityRecordLaunchReason_005, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();
    EXPECT_NE(mgr, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.want.SetParam(Want::PARM_LAUNCH_REASON_MESSAGE, std::string("HeavenlyMe"));
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->lifeCycleStateInfo_.launchParam.launchReasonMessage = "HelloWorld";

    mgr->UpdateAbilityRecordLaunchReason(abilityRequest, abilityRecord);
    auto message = abilityRecord->lifeCycleStateInfo_.launchParam.launchReasonMessage;
    EXPECT_EQ(message, "HeavenlyMe");
}

/**
 * @tc.name: UIAbilityLifecycleManager_UpdateAbilityRecordLaunchReason_0600
 * @tc.desc: UpdateAbilityRecordLaunchReason
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, UpdateAbilityRecordLaunchReason_006, TestSize.Level1)
{
    auto mgr = std::make_unique<UIAbilityLifecycleManager>();
    EXPECT_NE(mgr, nullptr);
    Want want;
    want.SetParam(Want::PARAM_ABILITY_RECOVERY_RESTART, true);

    AbilityRequest abilityRequest;
    abilityRequest.want.SetParam(Want::PARM_LAUNCH_REASON_MESSAGE, std::string(""));
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->lifeCycleStateInfo_.launchParam.launchReasonMessage = "HelloWorld";

    mgr->UpdateAbilityRecordLaunchReason(abilityRequest, abilityRecord);
    auto message = abilityRecord->lifeCycleStateInfo_.launchParam.launchReasonMessage;
    EXPECT_NE(message, "");
}

/**
 * @tc.name: UIAbilityLifecycleManager_MinimizeUIAbility_0300
 * @tc.desc: MinimizeUIAbility
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, MinimizeUIAbility_003, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    
    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->SetPendingState(AbilityState::FOREGROUND);

    EXPECT_EQ(uiAbilityLifecycleManager->MinimizeUIAbility(abilityRecord, false, 0), ERR_OK);
}

/**
 * @tc.name: UIAbilityLifecycleManager_GetPersistentIdByAbilityRequest_0300
 * @tc.desc: GetPersistentIdByAbilityRequest
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, GetPersistentIdByAbilityRequest_003, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);
    AbilityRequest abilityRequest;
    abilityRequest.collaboratorType = CollaboratorType::OTHERS_TYPE;
    uiAbilityLifecycleManager->sessionAbilityMap_.clear();
    bool reuse = false;
    EXPECT_EQ(uiAbilityLifecycleManager->GetPersistentIdByAbilityRequest(abilityRequest, reuse), 0);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OnStartSpecifiedFailed_0200
 * @tc.desc: OnStartSpecifiedFailed
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, OnStartSpecifiedFailed_002, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    int32_t requestId = 1;
    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);

    uiAbilityLifecycleManager->hookSpecifiedMap_ = {
        {requestId, abilityRecord}
    };

    uiAbilityLifecycleManager->OnStartSpecifiedFailed(requestId);
    EXPECT_EQ(uiAbilityLifecycleManager->hookSpecifiedMap_.size(), 0);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OnStartSpecifiedFailed_0300
 * @tc.desc: OnStartSpecifiedFailed
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, OnStartSpecifiedFailed_003, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    int32_t requestId = 1;
    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);

    uiAbilityLifecycleManager->hookSpecifiedMap_ = {
        {2, abilityRecord}
    };

    uiAbilityLifecycleManager->OnStartSpecifiedFailed(requestId);
    EXPECT_NE(uiAbilityLifecycleManager->hookSpecifiedMap_.size(), 0);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OnStartSpecifiedProcessResponse_0300
 * @tc.desc: OnStartSpecifiedProcessResponse
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, OnStartSpecifiedProcessResponse_003, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    int32_t requestId = 10;
    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);

    abilityRequest.abilityInfo.launchMode == AppExecFwk::LaunchMode::SPECIFIED;
    auto specifiedRequestPtr = std::make_shared<SpecifiedRequest>(requestId, abilityRequest);
    specifiedRequestPtr->specifiedProcessState = SpecifiedProcessState::STATE_PROCESS;
    uiAbilityLifecycleManager->specifiedRequestList_ = {
        { "NewKawasaki", { specifiedRequestPtr } }
    };

    uiAbilityLifecycleManager->OnStartSpecifiedProcessResponse("HeavenlyMe", requestId);

    auto listMap = uiAbilityLifecycleManager->specifiedRequestList_.find("NewKawasaki");
    EXPECT_EQ(listMap, uiAbilityLifecycleManager->specifiedRequestList_.end());
}

/**
 * @tc.name: UIAbilityLifecycleManager_OnStartSpecifiedProcessResponse_0400
 * @tc.desc: OnStartSpecifiedProcessResponse
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, OnStartSpecifiedProcessResponse_004, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    int32_t requestId = 10;
    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);

    abilityRequest.abilityInfo.launchMode = AppExecFwk::LaunchMode::SINGLETON;
    auto specifiedRequestPtr = std::make_shared<SpecifiedRequest>(requestId, abilityRequest);
    specifiedRequestPtr->specifiedProcessState = SpecifiedProcessState::STATE_PROCESS;
    uiAbilityLifecycleManager->specifiedRequestList_ = {
        {"NewKawasaki", {specifiedRequestPtr}}
    };

    uiAbilityLifecycleManager->OnStartSpecifiedProcessResponse("HeavenlyMe", requestId);

    auto listMap = uiAbilityLifecycleManager->specifiedRequestList_.find("NewKawasaki");
    EXPECT_EQ(listMap, uiAbilityLifecycleManager->specifiedRequestList_.end());
}

/**
 * @tc.name: UIAbilityLifecycleManager_IsSupportStatusBar_0400
 * @tc.desc: IsSupportStatusBar
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, IsSupportStatusBar_004, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_unique<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);
    
    uiAbilityLifecycleManager->statusBarDelegateManager_ = uiAbilityLifecycleManager->GetStatusBarDelegateManager();
    auto delegate = sptr<MockIStatusBarDelegate>::MakeSptr();
    uiAbilityLifecycleManager->statusBarDelegateManager_->RegisterStatusBarDelegate(delegate);

    auto ret = uiAbilityLifecycleManager->IsSupportStatusBar();

    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OnAcceptWantResponse_0100
 * @tc.desc: OnAcceptWantResponse
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, OnAcceptWantResponse_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);
    
    AAFwk::Want want;
    std::string flag = "";
    int32_t requestId = 1;

    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->sessionInfo_ = sptr<AAFwk::SessionInfo>::MakeSptr();

    uiAbilityLifecycleManager->hookSpecifiedMap_ = {
        {requestId, abilityRecord}
    };

    uiAbilityLifecycleManager->OnAcceptWantResponse(want, flag, requestId);

    auto size = uiAbilityLifecycleManager->hookSpecifiedMap_.size();
    EXPECT_EQ(size, 0);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OnAcceptWantResponse_0200
 * @tc.desc: OnAcceptWantResponse
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, OnAcceptWantResponse_002, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);
    
    AAFwk::Want want;
    std::string flag = "";
    int32_t requestId = 1;

    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);

    uiAbilityLifecycleManager->hookSpecifiedMap_ = {
        {requestId, abilityRecord}
    };

    uiAbilityLifecycleManager->OnAcceptWantResponse(want, flag, 2);

    auto size = uiAbilityLifecycleManager->hookSpecifiedMap_.size();
    EXPECT_EQ(size, 1);
}

/**
 * @tc.name: UIAbilityLifecycleManager_MoveAbilityToFront_0100
 * @tc.desc: MoveAbilityToFront
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, MoveAbilityToFront_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.processOptions = std::make_shared<ProcessOptions>();
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->sessionInfo_ = sptr<AAFwk::SessionInfo>::MakeSptr();
    abilityRequest.abilityInfo.launchMode = AppExecFwk::LaunchMode::SPECIFIED;

    AppUtils::isStartOptionsWithAnimation_ = true;

    uiAbilityLifecycleManager->MoveAbilityToFront(abilityRequest, abilityRecord, abilityRecord, nullptr, 0);

    auto sessionInfo = abilityRecord->GetSessionInfo();
    EXPECT_NE(sessionInfo->processOptions, nullptr);
}

/**
 * @tc.name: UIAbilityLifecycleManager_MoveAbilityToFront_0200
 * @tc.desc: MoveAbilityToFront
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, MoveAbilityToFront_002, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.processOptions = std::make_shared<ProcessOptions>();
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->sessionInfo_ = sptr<AAFwk::SessionInfo>::MakeSptr();
    abilityRequest.abilityInfo.launchMode = AppExecFwk::LaunchMode::SPECIFIED;

    AppUtils::isStartOptionsWithAnimation_ = false;

    uiAbilityLifecycleManager->MoveAbilityToFront(abilityRequest, abilityRecord, abilityRecord, nullptr, 0);

    auto sessionInfo = abilityRecord->GetSessionInfo();
    EXPECT_EQ(sessionInfo->processOptions, nullptr);
}

/**
 * @tc.name: UIAbilityLifecycleManager_MoveAbilityToFront_0300
 * @tc.desc: MoveAbilityToFront
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, MoveAbilityToFront_003, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.processOptions = std::make_shared<ProcessOptions>();
    abilityRequest.abilityInfo.launchMode = AppExecFwk::LaunchMode::SPECIFIED;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->sessionInfo_ = sptr<AAFwk::SessionInfo>::MakeSptr();
    abilityRecord->want_.SetParam(Want::PARAM_RESV_WINDOW_MODE,
        AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_UNDEFINED);

    AppUtils::isStartOptionsWithAnimation_ = false;

    auto startOptions = std::make_shared<StartOptions>();
    startOptions->windowMode_ = AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_SECONDARY;

    uiAbilityLifecycleManager->MoveAbilityToFront(abilityRequest, abilityRecord, abilityRecord, startOptions, 0);

    auto ret = abilityRecord->want_.GetIntParam(Want::PARAM_RESV_WINDOW_MODE, -1);
    EXPECT_EQ(ret, AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_SECONDARY);
}

/**
 * @tc.name: UIAbilityLifecycleManager_MoveAbilityToFront_0400
 * @tc.desc: MoveAbilityToFront
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, MoveAbilityToFront_004, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.processOptions = std::make_shared<ProcessOptions>();
    abilityRequest.abilityInfo.launchMode = AppExecFwk::LaunchMode::SPECIFIED;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->sessionInfo_ = sptr<AAFwk::SessionInfo>::MakeSptr();
    abilityRecord->want_.SetParam(Want::PARAM_RESV_WINDOW_MODE,
        AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_UNDEFINED);

    AppUtils::isStartOptionsWithAnimation_ = false;

    auto startOptions = std::make_shared<StartOptions>();
    startOptions->windowMode_ = AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_SECONDARY;

    uiAbilityLifecycleManager->MoveAbilityToFront(abilityRequest, abilityRecord, abilityRecord, nullptr, 0);

    auto ret = abilityRecord->want_.GetIntParam(Want::PARAM_RESV_WINDOW_MODE, -1);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: UIAbilityLifecycleManager_CallRequestDone_0100
 * @tc.desc: CallRequestDone
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, CallRequestDone_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);

    auto mockCallStub = sptr<MockIRemoteObject>::MakeSptr();

    uiAbilityLifecycleManager->callRequestCache_ = {
        {abilityRecord, {abilityRequest}}
    };

    uiAbilityLifecycleManager->CallRequestDone(abilityRecord, mockCallStub);

    EXPECT_EQ(uiAbilityLifecycleManager->callRequestCache_.size(), 0);
}

/**
 * @tc.name: UIAbilityLifecycleManager_CallRequestDone_0200
 * @tc.desc: CallRequestDone
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, CallRequestDone_002, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    AbilityRequest abilityRequest;
    auto abilityRecord1 = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    
    auto abilityRecord2 = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);


    auto mockCallStub = sptr<MockIRemoteObject>::MakeSptr();

    uiAbilityLifecycleManager->callRequestCache_ = {
        {abilityRecord1, {abilityRequest}}
    };

    uiAbilityLifecycleManager->CallRequestDone(abilityRecord2, mockCallStub);

    EXPECT_NE(uiAbilityLifecycleManager->callRequestCache_.size(), 0);
}

/**
 * @tc.name: UIAbilityLifecycleManager_MoveMissionToFront_0100
 * @tc.desc: MoveMissionToFront
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, MoveMissionToFront_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    int32_t sessionId = 1;
    auto startOptions = std::make_shared<StartOptions>();

    startOptions->windowMode_ = AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_PRIMARY;

    Rosen::SessionInfo info;
    sptr<Rosen::ISession> session = sptr<Rosen::Session>::MakeSptr(info);
    EXPECT_NE(session, nullptr);
    sptr<IRemoteObject> rootSceneSession = session->AsObject();
    uiAbilityLifecycleManager->rootSceneSession_ = rootSceneSession;

    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->sessionInfo_ = sptr<AAFwk::SessionInfo>::MakeSptr();

    uiAbilityLifecycleManager->sessionAbilityMap_ = {
        {sessionId, abilityRecord}
    };

    uiAbilityLifecycleManager->MoveMissionToFront(sessionId, startOptions);
    
    auto ret = abilityRecord->want_.GetIntParam(Want::PARAM_RESV_WINDOW_MODE, -1);
    
    EXPECT_EQ(ret, AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_PRIMARY);
}

/**
 * @tc.name: UIAbilityLifecycleManager_MoveMissionToFront_0200
 * @tc.desc: MoveMissionToFront
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, MoveMissionToFront_002, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    int32_t sessionId = 1;

    Rosen::SessionInfo info;
    sptr<Rosen::ISession> session = sptr<Rosen::Session>::MakeSptr(info);
    EXPECT_NE(session, nullptr);
    sptr<IRemoteObject> rootSceneSession = session->AsObject();
    uiAbilityLifecycleManager->rootSceneSession_ = rootSceneSession;

    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->sessionInfo_ = sptr<AAFwk::SessionInfo>::MakeSptr();

    uiAbilityLifecycleManager->sessionAbilityMap_ = {
        {sessionId, abilityRecord}
    };

    uiAbilityLifecycleManager->MoveMissionToFront(sessionId, nullptr);
    
    auto ret = abilityRecord->want_.GetIntParam(Want::PARAM_RESV_WINDOW_MODE, -1);
    
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: UIAbilityLifecycleManager_MoveMissionToFront_0300
 * @tc.desc: MoveMissionToFront
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, MoveMissionToFront_003, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    int32_t sessionId = 1;
    auto startOptions = std::make_shared<StartOptions>();

    startOptions->windowMode_ = AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_PRIMARY;
    startOptions->displayId_ = 0;

    Rosen::SessionInfo info;
    sptr<Rosen::ISession> session = sptr<Rosen::Session>::MakeSptr(info);
    EXPECT_NE(session, nullptr);
    sptr<IRemoteObject> rootSceneSession = session->AsObject();
    uiAbilityLifecycleManager->rootSceneSession_ = rootSceneSession;

    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->sessionInfo_ = sptr<AAFwk::SessionInfo>::MakeSptr();
    abilityRecord->sessionInfo_->want.RemoveParam(Want::PARAM_RESV_DISPLAY_ID);

    uiAbilityLifecycleManager->sessionAbilityMap_ = {
        {sessionId, abilityRecord}
    };

    uiAbilityLifecycleManager->MoveMissionToFront(sessionId, startOptions);
    
    auto ret = abilityRecord->sessionInfo_->want.GetIntParam(Want::PARAM_RESV_DISPLAY_ID, -1);
    
    EXPECT_EQ(ret, DisplayUtil::GetDefaultDisplayId());
}

/**
 * @tc.name: UIAbilityLifecycleManager_MoveMissionToFront_0400
 * @tc.desc: MoveMissionToFront
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, MoveMissionToFront_004, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    int32_t sessionId = 1;
    auto startOptions = std::make_shared<StartOptions>();

    startOptions->windowMode_ = AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_PRIMARY;
    startOptions->displayId_ = 1;

    Rosen::SessionInfo info;
    sptr<Rosen::ISession> session = sptr<Rosen::Session>::MakeSptr(info);
    EXPECT_NE(session, nullptr);
    sptr<IRemoteObject> rootSceneSession = session->AsObject();
    uiAbilityLifecycleManager->rootSceneSession_ = rootSceneSession;

    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->sessionInfo_ = sptr<AAFwk::SessionInfo>::MakeSptr();
    abilityRecord->sessionInfo_->want.RemoveParam(Want::PARAM_RESV_DISPLAY_ID);

    uiAbilityLifecycleManager->sessionAbilityMap_ = {
        {sessionId, abilityRecord}
    };

    uiAbilityLifecycleManager->MoveMissionToFront(sessionId, startOptions);
    
    auto ret = abilityRecord->sessionInfo_->want.GetIntParam(Want::PARAM_RESV_DISPLAY_ID, -1);
    
    EXPECT_EQ(ret, 1);
    EXPECT_NE(ret, DisplayUtil::GetDefaultDisplayId());
}

/**
 * @tc.name: UIAbilityLifecycleManager_CheckPrepareTerminateTokens_0100
 * @tc.desc: CheckPrepareTerminateTokens
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, CheckPrepareTerminateTokens_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    std::vector<sptr<IRemoteObject>> tokens = {};
    uint32_t tokenId = 0;
    std::map<std::string, std::vector<sptr<IRemoteObject>>> tokensPerModuleName = {};

    auto ret = uiAbilityLifecycleManager->CheckPrepareTerminateTokens(tokens, tokenId, tokensPerModuleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: UIAbilityLifecycleManager_UpdateSessionInfoBySCB_0100
 * @tc.desc: UpdateSessionInfoBySCB
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, UpdateSessionInfoBySCB_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    SessionInfo sessionInfo;
    sessionInfo.persistentId = 1;
    std::list<SessionInfo> sessionInfos = {
        sessionInfo
    };
    std::vector<int32_t> sessionIds = {};

    auto ret = uiAbilityLifecycleManager->UpdateSessionInfoBySCB(sessionInfos, sessionIds);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(sessionIds.size(), 0);
    EXPECT_EQ(*sessionIds.rbegin(), 1);
}

/**
 * @tc.name: UIAbilityLifecycleManager_UpdateSessionInfoBySCB_0200
 * @tc.desc: UpdateSessionInfoBySCB
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, UpdateSessionInfoBySCB_002, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    SessionInfo sessionInfo;
    sessionInfo.persistentId = 1;
    std::list<SessionInfo> sessionInfos = {
        sessionInfo
    };
    std::vector<int32_t> sessionIds = {};

    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->sessionInfo_ = sptr<AAFwk::SessionInfo>::MakeSptr();
    uiAbilityLifecycleManager->sessionAbilityMap_ = {
        {1, abilityRecord}
    };

    auto ret = uiAbilityLifecycleManager->UpdateSessionInfoBySCB(sessionInfos, sessionIds);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sessionIds.size(), 0);
}

/**
 * @tc.name: UIAbilityLifecycleManager_RemoveAbilityRequest_0100
 * @tc.desc: RemoveAbilityRequest
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, RemoveAbilityRequest_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    int32_t requestId = 0;
    auto abilityRequest = std::make_shared<AbilityRequest>();

    uiAbilityLifecycleManager->startAbilityCheckMap_ = {
        {0, abilityRequest}
    };

    uiAbilityLifecycleManager->RemoveAbilityRequest(requestId);

    EXPECT_NE(uiAbilityLifecycleManager->startAbilityCheckMap_.size(), 0);
}

/**
 * @tc.name: UIAbilityLifecycleManager_RemoveAbilityRequest_0200
 * @tc.desc: RemoveAbilityRequest
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, RemoveAbilityRequest_002, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    int32_t requestId = 1;
    auto abilityRequest = std::make_shared<AbilityRequest>();

    uiAbilityLifecycleManager->startAbilityCheckMap_ = {
        {1, abilityRequest}
    };

    uiAbilityLifecycleManager->RemoveAbilityRequest(requestId);

    EXPECT_EQ(uiAbilityLifecycleManager->startAbilityCheckMap_.size(), 0);
}

/**
 * @tc.name: UIAbilityLifecycleManager_AddSpecifiedRequest_0200
 * @tc.desc: AddSpecifiedRequest
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, AddSpecifiedRequest_002, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    uiAbilityLifecycleManager->specifiedRequestList_.clear();

    uiAbilityLifecycleManager->AddSpecifiedRequest(nullptr);

    EXPECT_EQ(uiAbilityLifecycleManager->specifiedRequestList_.size(), 0);
}

/**
 * @tc.name: UIAbilityLifecycleManager_PopAndGetNextSpecified_0100
 * @tc.desc: PopAndGetNextSpecified
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, PopAndGetNextSpecified_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    int32_t requestId1 = 1;
    int32_t requestId2 = 2;

    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);

    auto specifiedRequestPtr = std::make_shared<SpecifiedRequest>(requestId1, abilityRequest);
    specifiedRequestPtr->requestId = 1;
    auto specifiedRequest2Ptr = std::make_shared<SpecifiedRequest>(requestId2, abilityRequest);
    specifiedRequest2Ptr->requestId = 2;

    uiAbilityLifecycleManager->specifiedRequestList_ = {
        {"NewKawasaki", {specifiedRequestPtr, specifiedRequest2Ptr}}
    };

    auto ret = uiAbilityLifecycleManager->PopAndGetNextSpecified(1);

    EXPECT_EQ(ret, specifiedRequest2Ptr);
}

/**
 * @tc.name: UIAbilityLifecycleManager_IsSpecifiedModuleLoaded_0100
 * @tc.desc: IsSpecifiedModuleLoaded
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, IsSpecifiedModuleLoaded_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    AbilityRequest abilityRequest;

    AppMgrUtil::appMgr_ = nullptr;
    SysMrgClient::instance_ = nullptr;

    auto ret = uiAbilityLifecycleManager->IsSpecifiedModuleLoaded(abilityRequest);

    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: UIAbilityLifecycleManager_HandleColdAcceptWantDone_0100
 * @tc.desc: HandleColdAcceptWantDone
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, HandleColdAcceptWantDone_001, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    AAFwk::Want want;

    int32_t requestId1 = 1;
    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);

    auto specifiedRequestPtr = std::make_shared<SpecifiedRequest>(requestId1, abilityRequest);

    uiAbilityLifecycleManager->sessionAbilityMap_.clear();

    auto ret = uiAbilityLifecycleManager->HandleColdAcceptWantDone(want, "", *specifiedRequestPtr);

    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: UIAbilityLifecycleManager_HandleColdAcceptWantDone_0200
 * @tc.desc: HandleColdAcceptWantDone
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, HandleColdAcceptWantDone_002, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    AAFwk::Want want;

    int32_t requestId1 = 1;
    AbilityRequest abilityRequest;

    auto specifiedRequestPtr = std::make_shared<SpecifiedRequest>(requestId1, abilityRequest);
    specifiedRequestPtr->persistentId = 1;

    uiAbilityLifecycleManager->sessionAbilityMap_ = {
        {1, nullptr}
    };

    auto ret = uiAbilityLifecycleManager->HandleColdAcceptWantDone(want, "", *specifiedRequestPtr);

    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: UIAbilityLifecycleManager_HandleColdAcceptWantDone_0300
 * @tc.desc: HandleColdAcceptWantDone
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, HandleColdAcceptWantDone_003, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    AAFwk::Want want;

    int32_t requestId1 = 1;
    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->specifiedFlag_ = "HeavenlyMe";

    auto specifiedRequestPtr = std::make_shared<SpecifiedRequest>(requestId1, abilityRequest);
    specifiedRequestPtr->persistentId = 1;

    uiAbilityLifecycleManager->sessionAbilityMap_ = {
        {1, abilityRecord}
    };

    auto ret = uiAbilityLifecycleManager->HandleColdAcceptWantDone(want, "", *specifiedRequestPtr);

    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: UIAbilityLifecycleManager_HandleColdAcceptWantDone_0400
 * @tc.desc: HandleColdAcceptWantDone
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityLifecycleManagerThirdTest, HandleColdAcceptWantDone_004, TestSize.Level1)
{
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_NE(uiAbilityLifecycleManager, nullptr);

    AAFwk::Want want;

    int32_t requestId1 = 1;
    AbilityRequest abilityRequest;
    auto abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    abilityRecord->specifiedFlag_.clear();

    auto specifiedRequestPtr = std::make_shared<SpecifiedRequest>(requestId1, abilityRequest);
    specifiedRequestPtr->persistentId = 1;

    uiAbilityLifecycleManager->sessionAbilityMap_ = {
        {1, abilityRecord}
    };

    auto ret = uiAbilityLifecycleManager->HandleColdAcceptWantDone(want, "", *specifiedRequestPtr);

    EXPECT_EQ(ret, true);
}
}  // namespace AAFwk
}  // namespace OHOS