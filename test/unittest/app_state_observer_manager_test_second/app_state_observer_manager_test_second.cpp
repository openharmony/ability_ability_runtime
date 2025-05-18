/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "ability_foreground_state_observer_proxy.h"
#define private public
#include "app_state_observer_manager.h"
#undef private
#include "app_foreground_state_observer_proxy.h"
#include "app_foreground_state_observer_stub.h"
#include "application_state_observer_stub.h"
#include "iapplication_state_observer.h"
#include "iremote_broker.h"
#include "mock_ability_foreground_state_observer_server_stub.h"
#include "mock_i_remote_object.h"
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
const int BUNDLE_NAME_LIST_MAX_SIZE = 128;
}
class MockApplicationStateObserver : public IApplicationStateObserver {
public:
    MockApplicationStateObserver() = default;
    virtual ~MockApplicationStateObserver() = default;
    MOCK_METHOD(void, OnForegroundApplicationChanged, (const AppStateData &appStateData), (override));
    MOCK_METHOD(void, OnAbilityStateChanged, (const AbilityStateData &abilityStateData), (override));
    MOCK_METHOD(void, OnExtensionStateChanged, (const AbilityStateData &abilityStateData), (override));
    MOCK_METHOD(void, OnProcessCreated, (const ProcessData &processData), (override));
    MOCK_METHOD(void, OnProcessStateChanged, (const ProcessData &processData), (override));
    MOCK_METHOD(void, OnProcessDied, (const ProcessData &processData), (override));
    MOCK_METHOD(void, OnApplicationStateChanged, (const AppStateData &appStateData), (override));
    MOCK_METHOD(void, OnAppStateChanged, (const AppStateData &appStateData), (override));
    MOCK_METHOD(void, OnAppStopped, (const AppStateData &appStateData), (override));
    MOCK_METHOD(void, OnAppStarted, (const AppStateData &appStateData), (override));
    MOCK_METHOD(void, OnProcessReused, (const ProcessData &processData), (override));
    MOCK_METHOD(void, OnWindowHidden, (const ProcessData &processData), (override));
    MOCK_METHOD(void, OnWindowShow, (const ProcessData &processData), (override));
    sptr<IRemoteObject> AsObject() override
    {
        return {};
    }
};
class MockTaskHandlerWrap : public AAFwk::TaskHandlerWrap {
public:
    explicit MockTaskHandlerWrap(const std::string& queueName = "") : TaskHandlerWrap(queueName) {};

    virtual ~MockTaskHandlerWrap() {};
    std::shared_ptr<AAFwk::InnerTaskHandle> SubmitTaskInner(
        std::function<void()>&& task, const AAFwk::TaskAttribute& taskAttr) override
        {
            task();
            return nullptr;
        }
    bool CancelTaskInner(const std::shared_ptr<AAFwk::InnerTaskHandle>& taskHandle) override
    {
        return false;
    }

    void WaitTaskInner(const std::shared_ptr<AAFwk::InnerTaskHandle>& taskHandle) override
    {
        return;
    }

    uint64_t GetTaskCount() override
    {
        return tasks_.size();
    }
};
class AppForegroundStateObserver : public AppForegroundStateObserverStub {
public:
    AppForegroundStateObserver() = default;
    virtual ~AppForegroundStateObserver() = default;
    void OnAppStateChanged(const AppStateData &appStateData) override
    {}
};
class AppStateObserverManagerTestSecond : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<AppRunningRecord> MockAppRecord();
    sptr<IApplicationStateObserver> observer_ {nullptr};
};

void AppStateObserverManagerTestSecond::SetUpTestCase()
{}

void AppStateObserverManagerTestSecond::TearDownTestCase()
{}

void AppStateObserverManagerTestSecond::SetUp()
{
    sptr<IApplicationStateObserver> observer_ = new MockApplicationStateObserver();
}

void AppStateObserverManagerTestSecond::TearDown()
{}

std::shared_ptr<AppRunningRecord> AppStateObserverManagerTestSecond::MockAppRecord()
{
    ApplicationInfo appInfo;
    appInfo.accessTokenId = 1;
    std::shared_ptr<ApplicationInfo> info = std::make_shared<ApplicationInfo>(appInfo);
    info->accessTokenId = 1;
    std::shared_ptr<AppRunningRecord> appRecord = std::make_shared<AppRunningRecord>(info, 0, "process");
    std::shared_ptr<PriorityObject> priorityObject = std::make_shared<PriorityObject>();
    priorityObject->SetPid(1);
    appRecord->priorityObject_ = priorityObject;
    appRecord->SetUid(1);
    appRecord->SetState(ApplicationState::APP_STATE_CREATE);
    appRecord->SetContinuousTaskAppState(false);
    appRecord->SetKeepAliveEnableState(false);
    appRecord->SetKeepAliveDkv(false);
    appRecord->SetEmptyKeepAliveAppState(false);
    appRecord->SetRequestProcCode(1);
    appRecord->isFocused_ = false;
    return appRecord;
}


/*
 * Feature: AppStateObserverManager
 * Function: OnAppStarted
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager OnAppStarted
 * EnvConditions: NA
 * CaseDescription: Verify OnAppStarted
 */
HWTEST_F(AppStateObserverManagerTestSecond, OnAppStarted_001, TestSize.Level2)
{
    auto manager = std::make_shared<AppStateObserverManager>();

    auto mockHandler = std::make_shared<MockTaskHandlerWrap>();
    manager->handler_ = mockHandler;

    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";
    std::vector<std::string> bundleNames;
    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, bundleNames});
    EXPECT_CALL(*mockObserver, OnAppStarted(_)).Times(1);
    manager->OnAppStarted(appRecord);
}

/*
 * Feature: AppStateObserverManager
 * Function: OnAppStopped
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager OnAppStopped
 * EnvConditions: NA
 * CaseDescription: Verify OnAppStopped
 */
HWTEST_F(AppStateObserverManagerTestSecond, OnAppStopped_001, TestSize.Level2)
{
    auto manager = std::make_shared<AppStateObserverManager>();

    auto mockHandler = std::make_shared<MockTaskHandlerWrap>();
    manager->handler_ = mockHandler;

    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";
    std::vector<std::string> bundleNames;
    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, bundleNames});
    EXPECT_CALL(*mockObserver, OnAppStopped(_)).Times(1);
    manager->OnAppStopped(appRecord);
}

/*
 * Feature: AppStateObserverManager
 * Function: OnAppStateChanged
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager OnAppStateChanged
 * EnvConditions: NA
 * CaseDescription: Verify OnAppStateChanged
 */
HWTEST_F(AppStateObserverManagerTestSecond, OnAppStateChanged_001, TestSize.Level2)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    auto mockHandler = std::make_shared<MockTaskHandlerWrap>();
    manager->handler_ = mockHandler;

    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";
    ApplicationState state = ApplicationState::APP_STATE_FOREGROUND;

    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, {"com.ohos.unittest"}});

    EXPECT_CALL(*mockObserver, OnForegroundApplicationChanged(_)).Times(1);
    EXPECT_CALL(*mockObserver, OnAppStateChanged(_)).Times(1);

    manager->OnAppStateChanged(appRecord, state, true, false);
}

/*
 * Feature: AppStateObserverManager
 * Function: OnProcessDied
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager OnProcessDied
 * EnvConditions: NA
 * CaseDescription: Verify OnProcessDied
 */
HWTEST_F(AppStateObserverManagerTestSecond, OnProcessDied_001, TestSize.Level2)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    auto mockHandler = std::make_shared<MockTaskHandlerWrap>();
    manager->handler_ = mockHandler;

    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";

    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, {"com.ohos.unittest"}});

    EXPECT_CALL(*mockObserver, OnProcessDied(_)).Times(1);

    manager->OnProcessDied(appRecord);
}

/*
 * Feature: AppStateObserverManager
 * Function: OnWindowShow
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager OnWindowShow
 * EnvConditions: NA
 * CaseDescription: Verify OnWindowShow
 */
HWTEST_F(AppStateObserverManagerTestSecond, OnWindowShow_001, TestSize.Level2)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    auto mockHandler = std::make_shared<MockTaskHandlerWrap>();
    manager->handler_ = mockHandler;

    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";

    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, {"com.ohos.unittest"}});

    EXPECT_CALL(*mockObserver, OnWindowShow(_)).Times(1);

    manager->OnWindowShow(appRecord);
}

/*
 * Feature: AppStateObserverManager
 * Function: OnWindowHidden
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager OnWindowHidden
 * EnvConditions: NA
 * CaseDescription: Verify OnWindowHidden
 */
HWTEST_F(AppStateObserverManagerTestSecond, OnWindowHidden_001, TestSize.Level2)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    auto mockHandler = std::make_shared<MockTaskHandlerWrap>();
    manager->handler_ = mockHandler;

    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";

    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, {"com.ohos.unittest"}});

    EXPECT_CALL(*mockObserver, OnWindowHidden(_)).Times(1);

    manager->OnWindowHidden(appRecord);
}

/*
 * Feature: AppStateObserverManager
 * Function: OnProcessCreated
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager OnProcessCreated
 * EnvConditions: NA
 * CaseDescription: Verify OnProcessCreated
 */
HWTEST_F(AppStateObserverManagerTestSecond, OnProcessCreated_001, TestSize.Level2)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    auto mockHandler = std::make_shared<MockTaskHandlerWrap>();
    manager->handler_ = mockHandler;

    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";

    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, {"com.ohos.unittest"}});


    EXPECT_CALL(*mockObserver, OnProcessCreated(_)).Times(1);

    manager->OnProcessCreated(appRecord, false);
}

/*
 * Feature: AppStateObserverManager
 * Function: OnChildProcessDied
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager OnChildProcessDied
 * EnvConditions: NA
 * CaseDescription: Verify OnChildProcessDied
 */
HWTEST_F(AppStateObserverManagerTestSecond, OnChildProcessDied_001, TestSize.Level1)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    auto mockHandler = std::make_shared<MockTaskHandlerWrap>();
    manager->handler_ = mockHandler;
    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";
    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, {"com.ohos.unittest"}});
    ChildProcessRequest request;
    request.srcEntry = "test.js";
    request.childProcessType = CHILD_PROCESS_TYPE_JS;
    request.childProcessCount = 1;
    std::shared_ptr<ChildProcessRecord> childRecord =
        std::make_shared<ChildProcessRecord>(1, request, appRecord);
    EXPECT_CALL(*mockObserver, OnProcessDied(_)).Times(1);
    manager->OnChildProcessDied(childRecord);
}

/*
 * Feature: AppStateObserverManager
 * Function: OnChildProcessDied
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager OnChildProcessDied
 * EnvConditions: NA
 * CaseDescription: Verify OnChildProcessDied
 */
HWTEST_F(AppStateObserverManagerTestSecond, OnChildProcessDied_002, TestSize.Level1)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    manager->handler_ = nullptr;
    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";
    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, {"com.ohos.unittest"}});
    ChildProcessRequest request;
    request.srcEntry = "test.js";
    request.childProcessType = CHILD_PROCESS_TYPE_JS;
    request.childProcessCount = 1;
    std::shared_ptr<ChildProcessRecord> childRecord =
        std::make_shared<ChildProcessRecord>(1, request, appRecord);
    EXPECT_CALL(*mockObserver, OnProcessDied(_)).Times(0);
    manager->OnChildProcessDied(childRecord);
}

/*
 * Feature: AppStateObserverManager
 * Function: OnChildProcessCreated
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager OnChildProcessCreated
 * EnvConditions: NA
 * CaseDescription: Verify OnChildProcessCreated
 */
HWTEST_F(AppStateObserverManagerTestSecond, OnChildProcessCreated_001, TestSize.Level1)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    auto mockHandler = std::make_shared<MockTaskHandlerWrap>();
    manager->handler_ = mockHandler;
    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";
    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, {"com.ohos.unittest"}});
    ChildProcessRequest request;
    request.srcEntry = "test.js";
    request.childProcessType = CHILD_PROCESS_TYPE_JS;
    request.childProcessCount = 1;
    std::shared_ptr<ChildProcessRecord> childRecord =
        std::make_shared<ChildProcessRecord>(1, request, appRecord);
    EXPECT_CALL(*mockObserver, OnProcessCreated(_)).Times(1);
    manager->OnChildProcessCreated(childRecord);
}

/*
 * Feature: AppStateObserverManager
 * Function: OnChildProcessCreated
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager OnChildProcessCreated
 * EnvConditions: NA
 * CaseDescription: Verify OnChildProcessCreated
 */
HWTEST_F(AppStateObserverManagerTestSecond, OnChildProcessCreated_002, TestSize.Level1)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    manager->handler_ = nullptr;
    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";
    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, {"com.ohos.unittest"}});
    ChildProcessRequest request;
    request.srcEntry = "test.js";
    request.childProcessType = CHILD_PROCESS_TYPE_JS;
    request.childProcessCount = 1;
    std::shared_ptr<ChildProcessRecord> childRecord =
        std::make_shared<ChildProcessRecord>(1, request, appRecord);
    EXPECT_CALL(*mockObserver, OnProcessCreated(_)).Times(0);
    manager->OnChildProcessCreated(childRecord);
}
/*
 * Feature: AppStateObserverManager
 * Function: HandleOnChildProcessCreated
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager HandleOnChildProcessCreated
 * EnvConditions: NA
 * CaseDescription: Verify HandleOnChildProcessCreated
 */
HWTEST_F(AppStateObserverManagerTestSecond, HandleOnChildProcessCreated_001, TestSize.Level1)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";
    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, {"com.ohos.unittest"}});
    ChildProcessRequest request;
    request.srcEntry = "test.js";
    request.childProcessType = CHILD_PROCESS_TYPE_JS;
    request.childProcessCount = 1;
    std::shared_ptr<ChildProcessRecord> childRecord =
        std::make_shared<ChildProcessRecord>(1, request, appRecord);
    EXPECT_CALL(*mockObserver, OnProcessCreated(_)).Times(1);
    manager->HandleOnChildProcessCreated(childRecord);
}

/*
 * Feature: AppStateObserverManager
 * Function: HandleOnChildProcessDied
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager HandleOnChildProcessDied
 * EnvConditions: NA
 * CaseDescription: Verify HandleOnChildProcessDied
 */
HWTEST_F(AppStateObserverManagerTestSecond, HandleOnChildProcessDied_001, TestSize.Level1)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";
    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, {"com.ohos.unittest"}});
    ChildProcessRequest request;
    request.srcEntry = "test.js";
    request.childProcessType = CHILD_PROCESS_TYPE_JS;
    request.childProcessCount = 1;
    std::shared_ptr<ChildProcessRecord> childRecord =
        std::make_shared<ChildProcessRecord>(1, request, appRecord);
    EXPECT_CALL(*mockObserver, OnProcessDied(_)).Times(1);
    manager->HandleOnChildProcessDied(childRecord);
}

/*
 * Feature: AppStateObserverManager
 * Function: WrapChildProcessData
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager WrapChildProcessData
 * EnvConditions: NA
 * CaseDescription: Verify WrapChildProcessData
 */
HWTEST_F(AppStateObserverManagerTestSecond, WrapChildProcessData_001, TestSize.Level1)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    std::shared_ptr<ChildProcessRecord> nullChildRecord = nullptr;
    ProcessData processData;
    EXPECT_EQ(manager->WrapChildProcessData(processData, nullChildRecord), ERR_INVALID_VALUE);
}

/*
 * Feature: AppStateObserverManager
 * Function: DecreaseObserverCount
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager DecreaseObserverCount
 * EnvConditions: NA
 * CaseDescription: Verify DecreaseObserverCount
 */
HWTEST_F(AppStateObserverManagerTestSecond, DecreaseObserverCount_001, TestSize.Level2)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    sptr<IApplicationStateObserver> obs = new MockApplicationStateObserver();
    int32_t uid = 1000;
    int32_t del_uid = 1001;
    manager->AddObserverCount(uid);
    EXPECT_EQ(manager->observerAmount_, 1);
    
    manager->DecreaseObserverCount(del_uid);
    EXPECT_EQ(manager->observerAmount_, 1);
}

/*
 * Feature: AppStateObserverManager
 * Function: AddObserverCount
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager AddObserverCount
 * EnvConditions: NA
 * CaseDescription: Verify AddObserverCount
 */
HWTEST_F(AppStateObserverManagerTestSecond, AddObserverCount_001, TestSize.Level2)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    sptr<IApplicationStateObserver> obs = new MockApplicationStateObserver();
    int32_t uid = 1000;
    manager->observerCountMap_.emplace(uid, 1);
    manager->AddObserverCount(uid);
    EXPECT_EQ(manager->observerCountMap_[uid], 2);
}

/*
 * Feature: AppStateObserverManager
 * Function: OnProcessReused
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager OnProcessReused
 * EnvConditions: NA
 * CaseDescription: Verify OnProcessReused with mock handler
 */
HWTEST_F(AppStateObserverManagerTestSecond, OnProcessReused_001, TestSize.Level2)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    auto mockHandler = std::make_shared<MockTaskHandlerWrap>();
    manager->handler_ = mockHandler;

    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";

    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, {"com.ohos.unittest"}});

    EXPECT_CALL(*mockObserver, OnProcessReused(_)).Times(1);

    manager->OnProcessReused(appRecord);
}

/*
 * Feature: AppStateObserverManager
 * Function: OnProcessReused
 * SubFunction: NA
 * FunctionPoints: AppStateObserverManager OnProcessReused
 * EnvConditions: NA
 * CaseDescription: Verify OnProcessReused with null handler
 */
HWTEST_F(AppStateObserverManagerTestSecond, OnProcessReused_002, TestSize.Level2)
{
    auto manager = std::make_shared<AppStateObserverManager>();
    manager->handler_ = nullptr;
    auto mockObserver = new MockApplicationStateObserver();
    sptr<IApplicationStateObserver> observer(mockObserver);
    std::shared_ptr<AppRunningRecord> appRecord = MockAppRecord();
    appRecord->mainBundleName_ = "com.ohos.unittest";
    manager->appStateObserverMap_.emplace(observer, AppStateObserverInfo{0, {"com.ohos.unittest"}});

    EXPECT_CALL(*mockObserver, OnProcessReused(_)).Times(0);
    manager->OnProcessReused(appRecord);
}
} // namespace AppExecFwk
} // namespace OHOS
