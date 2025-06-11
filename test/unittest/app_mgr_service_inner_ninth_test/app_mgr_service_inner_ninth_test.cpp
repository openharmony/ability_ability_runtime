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
#include "ability_util.h"  // Mock header to override CHECK_POINTER_AND_RETURN_LOG
#include "mock_task_handler_wrap.h"  // Mock TaskHandlerWrap for testing
#define private public
#include "app_mgr_service_inner.h"
#include "app_running_record.h"
#include "app_spawn_client.h"
#include "app_utils.h"
#include "render_record.h"
#include "child_process_record.h"
#include "cache_process_manager.h"
#undef private
#include "user_record_manager.h"
#include "mock_my_status.h"
#include "ability_manager_errors.h"
#include "overlay_manager_proxy.h"
#include "ability_connect_callback_stub.h"
#include "app_scheduler_const.h"
#include "want.h"
#include "application_info.h"
#include "mock_app_scheduler.h"
#include "parameters.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using OHOS::AppExecFwk::ExtensionAbilityType;
constexpr int32_t FOUNDATION_UID = 5523;
constexpr int32_t QUICKFIX_UID = 5524;
constexpr int32_t SHADER_CACHE_GROUPID = 3099;
constexpr int32_t RESOURCE_MANAGER_UID = 1096;
constexpr int32_t DEFAULT_USER_ID = 0;
constexpr const char* DEVELOPER_MODE_STATE = "const.security.developermode.state";
constexpr const char* DEBUG_APP = "debugApp";
constexpr const char* DLP_PARAMS_SECURITY_FLAG = "ohos.dlp.params.securityFlag";
static int g_scheduleLoadChildCall = 0;
constexpr const char* UIEXTENSION_ABILITY_ID = "ability.want.params.uiExtensionAbilityId";
constexpr const char* UIEXTENSION_ROOT_HOST_PID = "ability.want.params.uiExtensionRootHostPid";
constexpr const char* UIEXTENSION_HOST_PID = "ability.want.params.uiExtensionHostPid";
constexpr const char* UIEXTENSION_HOST_UID = "ability.want.params.uiExtensionHostUid";
constexpr const char* UIEXTENSION_HOST_BUNDLENAME = "ability.want.params.uiExtensionHostBundleName";
constexpr const char* UIEXTENSION_BIND_ABILITY_ID = "ability.want.params.uiExtensionBindAbilityId";
constexpr const char* UIEXTENSION_NOTIFY_BIND = "ohos.uiextension.params.notifyProcessBind";
namespace OHOS {
namespace AppExecFwk {
class AppMgrServiceInnerNinthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

class MyAbilityDebugResponse : public IAbilityDebugResponse {
public:
    void OnAbilitysDebugStarted(const std::vector<sptr<IRemoteObject>> &tokens) override
    {}

    void OnAbilitysDebugStoped(const std::vector<sptr<IRemoteObject>> &tokens) override
    {}

    void OnAbilitysAssertDebugChange(const std::vector<sptr<IRemoteObject>> &tokens,
        bool isAssertDebug) override {}

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

class MyStartSpecifiedAbilityResponse : public IStartSpecifiedAbilityResponse {
public:
    void OnAcceptWantResponse(const AAFwk::Want &want, const std::string &flag, int32_t requestId) override
    {}
    void OnTimeoutResponse(int32_t requestId) override
    {}
    void OnNewProcessRequestResponse(const std::string &flag, int32_t requestId) override
    {}
    void OnNewProcessRequestTimeoutResponse(int32_t requestId) override
    {}
    void OnStartSpecifiedFailed(int32_t requestId) override
    {}
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

class MockIAppStateCallback : public IAppStateCallback {
public:
    MockIAppStateCallback() = default;
    virtual ~MockIAppStateCallback() = default;
    MOCK_METHOD1(OnAppStateChanged, void(const AppProcessData &appProcessData));
    MOCK_METHOD2(OnAbilityRequestDone, void(const sptr<IRemoteObject> &token, const AbilityState state));
    void NotifyAppPreCache(int32_t pid, int32_t userId) override
    {
        AAFwk::MyStatus::GetInstance().notifyAppPreCacheCalled_ = true;
    }
    void NotifyStartResidentProcess(std::vector<AppExecFwk::BundleInfo> &bundleInfos) override
    {
        AAFwk::MyStatus::GetInstance().notifyStartResidentProcessCalled_ = true;
    }
    void NotifyStartKeepAliveProcess(std::vector<AppExecFwk::BundleInfo> &bundleInfos) override
    {
        AAFwk::MyStatus::GetInstance().notifyStartKeepAliveProcessCalled_ = true;
    }
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};
void AppMgrServiceInnerNinthTest::SetUpTestCase() {}

void AppMgrServiceInnerNinthTest::TearDownTestCase() {}

void AppMgrServiceInnerNinthTest::SetUp() {}

void AppMgrServiceInnerNinthTest::TearDown() {}

/**
 * @tc.name: PreloadApplication_001
 * @tc.desc: test PreloadApplication with null appPreloader
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerNinthTest, PreloadApplication_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PreloadApplication_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    ASSERT_NE(appMgrServiceInner, nullptr);
    AAFwk::MyStatus::GetInstance().judgeCallerIsAllowed_ = true;
    AAFwk::MyStatus::GetInstance().verifyCallingPermission_ = true;
    AAFwk::MyStatus::GetInstance().isSACall_ = true;
    appMgrServiceInner->appPreloader_ = nullptr;

    std::string bundleName = "com.test.preload";
    int32_t userId = 100;
    PreloadMode preloadMode = PreloadMode::PRE_MAKE;
    int32_t appIndex = 0;
    
    int32_t ret = appMgrServiceInner->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "PreloadApplication_001 end");
}

/**
 * @tc.name: PreloadApplication_002
 * @tc.desc: test PreloadApplication with permission denied
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerNinthTest, PreloadApplication_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PreloadApplication_002 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    ASSERT_NE(appMgrServiceInner, nullptr);
    AAFwk::MyStatus::GetInstance().judgeCallerIsAllowed_ = true;
    AAFwk::MyStatus::GetInstance().verifyCallingPermission_ = false;
    AAFwk::MyStatus::GetInstance().isSACall_ = true;

    std::string bundleName = "com.test.preload";
    int32_t userId = 100;
    PreloadMode preloadMode = PreloadMode::PRE_MAKE;
    int32_t appIndex = 0;
    
    int32_t ret = appMgrServiceInner->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, ERR_PERMISSION_DENIED);
    TAG_LOGI(AAFwkTag::TEST, "PreloadApplication_002 end");
}

/**
 * @tc.name: PreloadApplication_003
 * @tc.desc: test PreloadApplication with current user ID
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerNinthTest, PreloadApplication_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PreloadApplication_003 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    ASSERT_NE(appMgrServiceInner, nullptr);
    AAFwk::MyStatus::GetInstance().judgeCallerIsAllowed_ = true;
    AAFwk::MyStatus::GetInstance().verifyCallingPermission_ = true;
    AAFwk::MyStatus::GetInstance().isSACall_ = true;
    appMgrServiceInner->appPreloader_ = nullptr;
    appMgrServiceInner->currentUserId_ = 200;

    std::string bundleName = "com.test.preload";
    int32_t userId = -2; // CURRENT_USER_ID
    PreloadMode preloadMode = PreloadMode::PRE_MAKE;
    int32_t appIndex = 0;
    
    int32_t ret = appMgrServiceInner->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, ERR_INVALID_VALUE); // Due to null appPreloader
    TAG_LOGI(AAFwkTag::TEST, "PreloadApplication_003 end");
}

/**
 * @tc.name: PreloadApplication_004
 * @tc.desc: test PreloadApplication with logout user
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerNinthTest, PreloadApplication_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PreloadApplication_004 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    ASSERT_NE(appMgrServiceInner, nullptr);
    AAFwk::MyStatus::GetInstance().judgeCallerIsAllowed_ = true;
    AAFwk::MyStatus::GetInstance().verifyCallingPermission_ = true;
    AAFwk::MyStatus::GetInstance().isSACall_ = true;
    AAFwk::MyStatus::GetInstance().isLogoutUser_ = true;
    appMgrServiceInner->appPreloader_ = std::make_shared<AppPreloader>(nullptr);

    std::string bundleName = "com.test.preload";
    int32_t userId = 100;
    PreloadMode preloadMode = PreloadMode::PRE_MAKE;
    int32_t appIndex = 0;
    
    int32_t ret = appMgrServiceInner->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, ERR_INVALID_OPERATION);
    TAG_LOGI(AAFwkTag::TEST, "PreloadApplication_004 end");
}

/**
 * @tc.name: PreloadApplication_005
 * @tc.desc: test PreloadApplication with preload not allowed
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerNinthTest, PreloadApplication_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PreloadApplication_005 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    ASSERT_NE(appMgrServiceInner, nullptr);
    AAFwk::MyStatus::GetInstance().judgeCallerIsAllowed_ = true;
    AAFwk::MyStatus::GetInstance().verifyCallingPermission_ = true;
    AAFwk::MyStatus::GetInstance().isSACall_ = true;
    AAFwk::MyStatus::GetInstance().isLogoutUser_ = false;
    AAFwk::MyStatus::GetInstance().allowPreload_ = false;
    appMgrServiceInner->appPreloader_ = std::make_shared<AppPreloader>(nullptr);

    std::string bundleName = "com.test.preload";
    int32_t userId = 100;
    PreloadMode preloadMode = PreloadMode::PRESS_DOWN;
    int32_t appIndex = 0;
    
    int32_t ret = appMgrServiceInner->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, AAFwk::ERR_NOT_ALLOW_PRELOAD_BY_RSS);
    TAG_LOGI(AAFwkTag::TEST, "PreloadApplication_005 end");
}

/**
 * @tc.name: PreloadApplication_006
 * @tc.desc: test PreloadApplication
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerNinthTest, PreloadApplication_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PreloadApplication_006 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    
    AAFwk::MyStatus::GetInstance().judgeCallerIsAllowed_ = false;
    AAFwk::MyStatus::GetInstance().verifyCallingPermission_ = true;
    AAFwk::MyStatus::GetInstance().isSACall_ = false;
    AAFwk::MyStatus::GetInstance().isLogoutUser_ = false;
    AAFwk::MyStatus::GetInstance().allowPreload_ = true;
    AAFwk::MyStatus::GetInstance().generatePreloadRequestRet_ = ERR_INVALID_VALUE;
    appMgrServiceInner->appPreloader_ = std::make_shared<AppPreloader>(nullptr);

    std::string bundleName = "com.test.preload";
    int32_t userId = 100;
    PreloadMode preloadMode = PreloadMode::PRE_MAKE;
    int32_t appIndex = 0;
    
    int32_t ret = appMgrServiceInner->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, AAFwk::ERR_NOT_SYSTEM_APP);
    TAG_LOGI(AAFwkTag::TEST, "PreloadApplication_006 end");
}
}  // namespace AppExecFwk
}  // namespace OHOS

