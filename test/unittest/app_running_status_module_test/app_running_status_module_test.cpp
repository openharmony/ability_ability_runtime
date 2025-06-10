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
#include "appexecfwk_errors.h"
#define private public
#include "app_running_status_module.h"
#include "appmgr/app_running_status_stub.h"
#undef private
#include "hilog_tag_wrapper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {

class MockAppRunningStatusListener : public AppRunningStatusStub {
public:
    void NotifyAppRunningStatus(const std::string &bundle, int32_t uid, RunningStatus runningStatus) override
    {
        bundle_ = bundle;
        uid_ = uid;
        runningStatus_ = runningStatus;
        notifyCount_++;
    }

    std::string bundle_;
    int32_t uid_ = 0;
    RunningStatus runningStatus_ = RunningStatus::APP_RUNNING_STOP;
    int32_t notifyCount_ = 0;
};

class AppRunningStatusModuleTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

protected:
    std::shared_ptr<AppRunningStatusModule> appRunningStatusModule_ = nullptr;
};

void AppRunningStatusModuleTest::SetUp()
{
    appRunningStatusModule_ = std::make_shared<AppRunningStatusModule>();
}

void AppRunningStatusModuleTest::TearDown()
{
    appRunningStatusModule_ = nullptr;
}

/**
 * @tc.number: AppRunningStatusModuleTest_RegisterListener_0100
 * @tc.desc: Test RegisterListener with null listener
 * @tc.type: FUNC
 * @tc.function: RegisterListener
 * @tc.subfunction: NA
 * @tc.envConditions: NA
 */
HWTEST_F(AppRunningStatusModuleTest, AppRunningStatusModuleTest_RegisterListener_0100, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppRunningStatusModuleTest_RegisterListener_0100 start.");
    sptr<AppRunningStatusListenerInterface> listener;
    auto ret = appRunningStatusModule_->RegisterListener(listener);
    EXPECT_EQ(ret, ERR_INVALID_OPERATION);
}

/**
 * @tc.number: AppRunningStatusModuleTest_RegisterListener_0200
 * @tc.desc: Test RegisterListener with valid listener
 * @tc.type: FUNC
 * @tc.function: RegisterListener
 * @tc.subfunction: NA
 * @tc.envConditions: NA
 */
HWTEST_F(AppRunningStatusModuleTest, AppRunningStatusModuleTest_RegisterListener_0200, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppRunningStatusModuleTest_RegisterListener_0200 start.");
    sptr<MockAppRunningStatusListener> listener = new MockAppRunningStatusListener();
    auto ret = appRunningStatusModule_->RegisterListener(listener);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AppRunningStatusModuleTest_RegisterListener_0300
 * @tc.desc: Test RegisterListener with same listener twice
 * @tc.type: FUNC
 * @tc.function: RegisterListener
 * @tc.subfunction: NA
 * @tc.envConditions: NA
 */
HWTEST_F(AppRunningStatusModuleTest, AppRunningStatusModuleTest_RegisterListener_0300, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppRunningStatusModuleTest_RegisterListener_0300 start.");
    sptr<MockAppRunningStatusListener> listener = new MockAppRunningStatusListener();
    auto ret = appRunningStatusModule_->RegisterListener(listener);
    EXPECT_EQ(ret, ERR_OK);
    ret = appRunningStatusModule_->RegisterListener(listener);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AppRunningStatusModuleTest_UnregisterListener_0100
 * @tc.desc: Test UnregisterListener with null listener
 * @tc.type: FUNC
 * @tc.function: UnregisterListener
 * @tc.subfunction: NA
 * @tc.envConditions: NA
 */
HWTEST_F(AppRunningStatusModuleTest, AppRunningStatusModuleTest_UnregisterListener_0100, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppRunningStatusModuleTest_UnregisterListener_0100 start.");
    sptr<AppRunningStatusListenerInterface> listener;
    auto ret = appRunningStatusModule_->UnregisterListener(listener);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.number: AppRunningStatusModuleTest_UnregisterListener_0200
 * @tc.desc: Test UnregisterListener with unregistered listener
 * @tc.type: FUNC
 * @tc.function: UnregisterListener
 * @tc.subfunction: NA
 * @tc.envConditions: NA
 */
HWTEST_F(AppRunningStatusModuleTest, AppRunningStatusModuleTest_UnregisterListener_0200, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppRunningStatusModuleTest_UnregisterListener_0200 start.");
    sptr<MockAppRunningStatusListener> listener = new MockAppRunningStatusListener();
    auto ret = appRunningStatusModule_->UnregisterListener(listener);
    EXPECT_EQ(ret, ERR_INVALID_OPERATION);
}

/**
 * @tc.number: AppRunningStatusModuleTest_UnregisterListener_0300
 * @tc.desc: Test UnregisterListener with registered listener
 * @tc.type: FUNC
 * @tc.function: UnregisterListener
 * @tc.subfunction: NA
 * @tc.envConditions: NA
 */
HWTEST_F(AppRunningStatusModuleTest, AppRunningStatusModuleTest_UnregisterListener_0300, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppRunningStatusModuleTest_UnregisterListener_0300 start.");
    sptr<MockAppRunningStatusListener> listener = new MockAppRunningStatusListener();
    
    auto ret = appRunningStatusModule_->RegisterListener(listener);
    EXPECT_EQ(ret, ERR_OK);
    ret = appRunningStatusModule_->UnregisterListener(listener);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AppRunningStatusModuleTest_NotifyAppRunningStatusEvent_0100
 * @tc.desc: Test NotifyAppRunningStatusEvent with no listeners
 * @tc.type: FUNC
 * @tc.function: NotifyAppRunningStatusEvent
 * @tc.subfunction: NA
 * @tc.envConditions: NA
 */
HWTEST_F(AppRunningStatusModuleTest, AppRunningStatusModuleTest_NotifyAppRunningStatusEvent_0100, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppRunningStatusModuleTest_NotifyAppRunningStatusEvent_0100 start.");
    std::string bundleName = "com.test.bundle";
    int32_t uid = 1000;
    RunningStatus runningStatus = RunningStatus::APP_RUNNING_START;
    
    // Verify no listeners are registered initially
    {
        std::lock_guard<std::mutex> lock(appRunningStatusModule_->listenerMutex_);
        EXPECT_TRUE(appRunningStatusModule_->listeners_.empty());
    }
    
    // Call NotifyAppRunningStatusEvent with no listeners - should complete without errors
    appRunningStatusModule_->NotifyAppRunningStatusEvent(bundleName, uid, runningStatus);
    
    // Verify listeners container remains empty after the call
    {
        std::lock_guard<std::mutex> lock(appRunningStatusModule_->listenerMutex_);
        EXPECT_TRUE(appRunningStatusModule_->listeners_.empty());
    }
}

/**
 * @tc.number: AppRunningStatusModuleTest_NotifyAppRunningStatusEvent_0200
 * @tc.desc: Test NotifyAppRunningStatusEvent with registered listener
 * @tc.type: FUNC
 * @tc.function: NotifyAppRunningStatusEvent
 * @tc.subfunction: NA
 * @tc.envConditions: NA
 */
HWTEST_F(AppRunningStatusModuleTest, AppRunningStatusModuleTest_NotifyAppRunningStatusEvent_0200, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppRunningStatusModuleTest_NotifyAppRunningStatusEvent_0200 start.");
    sptr<MockAppRunningStatusListener> listener = new MockAppRunningStatusListener();
    
    // Register listener
    auto ret = appRunningStatusModule_->RegisterListener(listener);
    EXPECT_EQ(ret, ERR_OK);
    
    std::string bundleName = "com.test.bundle";
    int32_t uid = 1000;
    RunningStatus runningStatus = RunningStatus::APP_RUNNING_START;
    
    // Notify event
    appRunningStatusModule_->NotifyAppRunningStatusEvent(bundleName, uid, runningStatus);
    
    // Check if listener was notified
    EXPECT_EQ(listener->notifyCount_, 1);
    EXPECT_EQ(listener->bundle_, bundleName);
    EXPECT_EQ(listener->uid_, uid);
    EXPECT_EQ(listener->runningStatus_, runningStatus);
}

/**
 * @tc.number: AppRunningStatusModuleTest_NotifyAppRunningStatusEvent_0300
 * @tc.desc: Test NotifyAppRunningStatusEvent with multiple listeners
 * @tc.type: FUNC
 * @tc.function: NotifyAppRunningStatusEvent
 * @tc.subfunction: NA
 * @tc.envConditions: NA
 */
HWTEST_F(AppRunningStatusModuleTest, AppRunningStatusModuleTest_NotifyAppRunningStatusEvent_0300, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppRunningStatusModuleTest_NotifyAppRunningStatusEvent_0300 start.");
    sptr<MockAppRunningStatusListener> listener1 = new MockAppRunningStatusListener();
    sptr<MockAppRunningStatusListener> listener2 = new MockAppRunningStatusListener();
    
    // Register listeners
    auto ret = appRunningStatusModule_->RegisterListener(listener1);
    EXPECT_EQ(ret, ERR_OK);
    ret = appRunningStatusModule_->RegisterListener(listener2);
    EXPECT_EQ(ret, ERR_OK);
    
    std::string bundleName = "com.test.bundle";
    int32_t uid = 1000;
    RunningStatus runningStatus = RunningStatus::APP_RUNNING_STOP;
    
    // Notify event
    appRunningStatusModule_->NotifyAppRunningStatusEvent(bundleName, uid, runningStatus);
    
    // Check if both listeners were notified
    EXPECT_EQ(listener1->notifyCount_, 1);
    EXPECT_EQ(listener1->bundle_, bundleName);
    EXPECT_EQ(listener1->uid_, uid);
    EXPECT_EQ(listener1->runningStatus_, runningStatus);
    
    EXPECT_EQ(listener2->notifyCount_, 1);
    EXPECT_EQ(listener2->bundle_, bundleName);
    EXPECT_EQ(listener2->uid_, uid);
    EXPECT_EQ(listener2->runningStatus_, runningStatus);
}

/**
 * @tc.number: AppRunningStatusModuleTest_RemoveListenerAndDeathRecipient_0100
 * @tc.desc: Test RemoveListenerAndDeathRecipient with null remote object
 * @tc.type: FUNC
 * @tc.function: RemoveListenerAndDeathRecipient
 * @tc.subfunction: NA
 * @tc.envConditions: NA
 */
HWTEST_F(AppRunningStatusModuleTest, AppRunningStatusModuleTest_RemoveListenerAndDeathRecipient_0100, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppRunningStatusModuleTest_RemoveListenerAndDeathRecipient_0100 start.");
    wptr<IRemoteObject> remote;
    auto ret = appRunningStatusModule_->RemoveListenerAndDeathRecipient(remote);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.number: AppRunningStatusModuleTest_RemoveListenerAndDeathRecipient_0200
 * @tc.desc: Test RemoveListenerAndDeathRecipient with valid remote object that exists
 * @tc.type: FUNC
 * @tc.function: RemoveListenerAndDeathRecipient
 * @tc.subfunction: NA
 * @tc.envConditions: NA
 */
HWTEST_F(AppRunningStatusModuleTest, AppRunningStatusModuleTest_RemoveListenerAndDeathRecipient_0200, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppRunningStatusModuleTest_RemoveListenerAndDeathRecipient_0200 start.");
    sptr<MockAppRunningStatusListener> listener = new MockAppRunningStatusListener();
    
    // Register listener first
    auto ret = appRunningStatusModule_->RegisterListener(listener);
    EXPECT_EQ(ret, ERR_OK);
    
    // Remove listener using remote object
    wptr<IRemoteObject> remote = listener->AsObject();
    ret = appRunningStatusModule_->RemoveListenerAndDeathRecipient(remote);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AppRunningStatusModuleTest_RemoveListenerAndDeathRecipient_0300
 * @tc.desc: Test RemoveListenerAndDeathRecipient with remote object that doesn't exist in listeners
 * @tc.type: FUNC
 * @tc.function: RemoveListenerAndDeathRecipient
 * @tc.subfunction: NA
 * @tc.envConditions: NA
 */
HWTEST_F(AppRunningStatusModuleTest, AppRunningStatusModuleTest_RemoveListenerAndDeathRecipient_0300, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppRunningStatusModuleTest_RemoveListenerAndDeathRecipient_0300 start.");
    sptr<MockAppRunningStatusListener> listener = new MockAppRunningStatusListener();
    
    // Don't register listener, directly try to remove
    wptr<IRemoteObject> remote = listener->AsObject();
    auto ret = appRunningStatusModule_->RemoveListenerAndDeathRecipient(remote);
    EXPECT_EQ(ret, ERR_INVALID_OPERATION);
}

/**
 * @tc.number: AppRunningStatusModuleTest_NotifyAppRunningStatusEvent_0400
 * @tc.desc: Test NotifyAppRunningStatusEvent with null listener in listeners list
 * @tc.type: FUNC
 * @tc.function: NotifyAppRunningStatusEvent
 * @tc.subfunction: NA
 * @tc.envConditions: NA
 */
HWTEST_F(AppRunningStatusModuleTest, AppRunningStatusModuleTest_NotifyAppRunningStatusEvent_0400, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppRunningStatusModuleTest_NotifyAppRunningStatusEvent_0400 start.");
    sptr<MockAppRunningStatusListener> listener = new MockAppRunningStatusListener();
    
    // Register listener
    auto ret = appRunningStatusModule_->RegisterListener(listener);
    EXPECT_EQ(ret, ERR_OK);
    
    {
        std::lock_guard<std::mutex> lock(appRunningStatusModule_->listenerMutex_);
        sptr<AppRunningStatusListenerInterface> nullListener = nullptr;
        sptr<IRemoteObject::DeathRecipient> nullRecipient = nullptr;
        appRunningStatusModule_->listeners_.emplace(nullListener, nullRecipient);
    }
    
    std::string bundleName = "com.test.bundle";
    int32_t uid = 1000;
    RunningStatus runningStatus = RunningStatus::APP_RUNNING_START;
    
    appRunningStatusModule_->NotifyAppRunningStatusEvent(bundleName, uid, runningStatus);
    
    EXPECT_EQ(listener->notifyCount_, 1);
    EXPECT_EQ(listener->bundle_, bundleName);
    EXPECT_EQ(listener->uid_, uid);
    EXPECT_EQ(listener->runningStatus_, runningStatus);
}

/**
 * @tc.number: AppRunningStatusModuleTest_ClientDeathRecipient_0200
 * @tc.desc: Test ClientDeathRecipient OnRemoteDied with valid appRunningStatus
 * @tc.type: FUNC
 * @tc.function: ClientDeathRecipient::OnRemoteDied
 * @tc.subfunction: NA
 * @tc.envConditions: NA
 */
HWTEST_F(AppRunningStatusModuleTest, AppRunningStatusModuleTest_ClientDeathRecipient_0100, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppRunningStatusModuleTest_ClientDeathRecipient_0100 start.");
    sptr<MockAppRunningStatusListener> listener = new MockAppRunningStatusListener();
    
    auto ret = appRunningStatusModule_->RegisterListener(listener);
    EXPECT_EQ(ret, ERR_OK);
    
    sptr<IRemoteObject::DeathRecipient> deathRecipient;
    {
        std::lock_guard<std::mutex> lock(appRunningStatusModule_->listenerMutex_);
        auto it = appRunningStatusModule_->listeners_.find(listener);
        EXPECT_NE(it, appRunningStatusModule_->listeners_.end());
        deathRecipient = it->second;
    }
    
    wptr<IRemoteObject> remote = listener->AsObject();
    
    deathRecipient->OnRemoteDied(remote);
    {
        std::lock_guard<std::mutex> lock(appRunningStatusModule_->listenerMutex_);
        auto it2 = appRunningStatusModule_->listeners_.find(listener);
        EXPECT_EQ(it2, appRunningStatusModule_->listeners_.end());
    }
}

} // namespace AbilityRuntime
} // namespace OHOS
