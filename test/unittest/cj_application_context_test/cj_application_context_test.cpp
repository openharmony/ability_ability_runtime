/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#define private public
#include "cj_ability_delegator.h"
#include "cj_ability_lifecycle_callback.h"
#include "cj_ability_runtime_error.h"
#include "cj_application_context.h"
#include "ability_delegator_registry.h"
#include "application_context.h"
#include "cj_utils_ffi.h"
#include "window_stage_impl.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::FFI;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace ApplicationContextCJ {

// Mock类
class MockCjAbilityLifecycleCallback : public CjAbilityLifecycleCallbackImpl {
public:
    MOCK_METHOD(void, OnAbilityCreate, (const int64_t &ability));
    MOCK_METHOD(void, OnWindowStageCreate, (const int64_t &ability, WindowStagePtr windowStage));
    MOCK_METHOD(void, OnWindowStageActive, (const int64_t &ability, WindowStagePtr windowStage));
    MOCK_METHOD(void, OnWindowStageInactive, (const int64_t &ability, WindowStagePtr windowStage));
    MOCK_METHOD(void, OnWindowStageDestroy, (const int64_t &ability, WindowStagePtr windowStage));
    MOCK_METHOD(void, OnAbilityDestroy, (const int64_t &ability));
    MOCK_METHOD(void, OnAbilityForeground, (const int64_t &ability));
    MOCK_METHOD(void, OnAbilityBackground, (const int64_t &ability));
    MOCK_METHOD(void, OnAbilityContinue, (const int64_t &ability));

    MOCK_METHOD(void, OnAbilityWillCreate, (const int64_t &ability));
    MOCK_METHOD(void, OnWindowStageWillCreate, (const int64_t &ability, WindowStagePtr windowStage));
    MOCK_METHOD(void, OnWindowStageWillDestroy, (const int64_t &ability, WindowStagePtr windowStage));
    MOCK_METHOD(void, OnAbilityWillDestroy, (const int64_t &ability));
    MOCK_METHOD(void, OnAbilityWillForeground, (const int64_t &ability));
    MOCK_METHOD(void, OnAbilityWillBackground, (const int64_t &ability));
    MOCK_METHOD(void, OnNewWant, (const int64_t &ability));
    MOCK_METHOD(void, OnWillNewWant, (const int64_t &ability));
    MOCK_METHOD(void, OnAbilityWillContinue, (const int64_t &ability));
    MOCK_METHOD(void, OnWindowStageWillRestore, (const int64_t &ability, WindowStagePtr windowStage));
    MOCK_METHOD(void, OnWindowStageRestore, (const int64_t &ability, WindowStagePtr windowStage));
    MOCK_METHOD(void, OnAbilityWillSaveState, (const int64_t &ability));
    MOCK_METHOD(void, OnAbilitySaveState, (const int64_t &ability));
};

class CjApplicationContextTest : public testing::Test {
public:
    CjApplicationContextTest()
    {}
    ~CjApplicationContextTest()
    {}
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
protected:
    std::shared_ptr<AbilityRuntime::ApplicationContext> appContext_;
    std::shared_ptr<CJApplicationContext> cjAppContext_;
};

void CjApplicationContextTest::SetUpTestCase()
{}

void CjApplicationContextTest::TearDownTestCase()
{}

void CjApplicationContextTest::SetUp()
{
    // Create an ApplicationContext object
    appContext_ = std::make_shared<AbilityRuntime::ApplicationContext>();
    // Create an CJApplicationContext object
    cjAppContext_ = std::make_shared<CJApplicationContext>(appContext_);
}

void CjApplicationContextTest::TearDown()
{}

/**
 * @tc.name: CJApplicationContextTestGetArea_001
 * @tc.desc: CjApplicationContextTest test for GetArea.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestGetArea_001, TestSize.Level1)
{
    // 测试 GetArea 函数
    int area = cjAppContext_->GetArea();
    EXPECT_EQ(area, 1);
}

/**
 * @tc.name: CJApplicationContextTestGetApplicationInfo_001
 * @tc.desc: CjApplicationContextTest test for GetApplicationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestGetApplicationInfo_001, TestSize.Level1)
{
    std::shared_ptr<ContextImpl> contextImpl = std::make_shared<ContextImpl>();
    appContext_->AttachContextImpl(contextImpl);
    auto appInfo = std::make_shared<AppExecFwk::ApplicationInfo>();
    appInfo->name = "TestApp";
    appInfo->bundleName = "com.example.testapp";
    appContext_->SetApplicationInfo(appInfo);
    EXPECT_NE(appInfo, nullptr);

    cjAppContext_ = std::make_shared<CJApplicationContext>(appContext_);
    // 测试 GetApplicationInfo 函数
    auto appInfoResult = cjAppContext_->GetApplicationInfo();
    EXPECT_NE(appInfoResult, nullptr);
}

/**
 * @tc.name: CJApplicationContextTestIsA
 * bilityLifecycleCallbackEmpty_001
 * @tc.desc: CjApplicationContextTest test for IsAbilityLifecycleCallbackEmpty.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestIsAbilityLifecycleCallbackEmpty_001, TestSize.Level1)
{
    bool result = cjAppContext_->IsAbilityLifecycleCallbackEmpty();
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: CJApplicationContextTestOnOnEnvironment_001
 * @tc.desc: CjApplicationContextTest test for OnOnEnvironment.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestOnOnEnvironment_001, TestSize.Level1)
{
    auto cfgCallback = [](AbilityRuntime::CConfiguration) {};
    auto memCallback = [](int32_t) {};
    EXPECT_EQ(cjAppContext_->OnOnEnvironment(cfgCallback, memCallback, true, nullptr), -1);

    cjAppContext_->envCallback_ = nullptr;
    EXPECT_EQ(cjAppContext_->OnOnEnvironment(cfgCallback, memCallback, true, nullptr), -1);
}

/**
 * @tc.name: CJApplicationContextTestOnOnAbilityLifecycle_001
 * @tc.desc: CjApplicationContextTest test for OnOnAbilityLifecycle.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestOnOnAbilityLifecycle_001, TestSize.Level1)
{
    CArrI64 cFuncIds;
    bool isSync = true;
    int32_t err = 0;
    int32_t *errCode = &err;
    cjAppContext_->applicationContext_.reset();
    cjAppContext_->callback_ = std::make_shared<AbilityRuntime::CjAbilityLifecycleCallbackImpl>();
    EXPECT_EQ(cjAppContext_->OnOnAbilityLifecycle(cFuncIds, isSync, errCode), -1);

    cjAppContext_->applicationContext_ = std::make_shared<AbilityRuntime::ApplicationContext>();
    EXPECT_EQ(cjAppContext_->OnOnAbilityLifecycle(cFuncIds, isSync, errCode), -1);
}

/**
 * @tc.name: CJApplicationContextTestOnOnApplicationStateChange_001
 * @tc.desc: CjApplicationContextTest test for OnOnApplicationStateChange.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestOnOnApplicationStateChange_001, TestSize.Level1)
{
    auto foregroundCallback = []() {};
    auto backgroundCallback = []() {};
    int32_t *errCode = nullptr;
    EXPECT_EQ(cjAppContext_->OnOnApplicationStateChange(foregroundCallback, backgroundCallback, errCode), 0);

    cjAppContext_->applicationStateCallback_ = nullptr;
    EXPECT_EQ(cjAppContext_->OnOnApplicationStateChange(foregroundCallback, backgroundCallback, errCode), 1);
}

/**
 * @tc.name: CJApplicationContextTestOnOffEnvironment_001
 * @tc.desc: CjApplicationContextTest test for OnOffEnvironment.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestOnOffEnvironment_001, TestSize.Level1)
{
    int32_t callbackId = 10;
    int32_t err = 0;
    int32_t *errCode = &err;
    cjAppContext_->applicationContext_.reset();
    cjAppContext_->envCallback_ = std::make_shared<CjEnvironmentCallback>();
    cjAppContext_->OnOffEnvironment(callbackId, errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);

    cjAppContext_->applicationContext_ = std::make_shared<AbilityRuntime::ApplicationContext>();
    cjAppContext_->OnOffEnvironment(callbackId, errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);

    cjAppContext_->envCallback_ = nullptr;
    cjAppContext_->OnOffEnvironment(callbackId, errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
}

/**
 * @tc.name: CJApplicationContextTestOnOffAbilityLifecycle_001
 * @tc.desc: CjApplicationContextTest test for OnOffAbilityLifecycle.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestOnOffAbilityLifecycle_001, TestSize.Level1)
{
    int32_t callbackId = 10;
    int32_t err = 0;
    int32_t *errCode = &err;
    cjAppContext_->applicationContext_.reset();
    cjAppContext_->callback_ = std::make_shared<AbilityRuntime::CjAbilityLifecycleCallbackImpl>();
    cjAppContext_->OnOffAbilityLifecycle(callbackId, errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);

    cjAppContext_->applicationContext_ = std::make_shared<AbilityRuntime::ApplicationContext>();
    cjAppContext_->OnOffAbilityLifecycle(callbackId, errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);

    cjAppContext_->callback_ = nullptr;
    cjAppContext_->OnOffAbilityLifecycle(callbackId, errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
}

/**
 * @tc.name: CJApplicationContextTestOnOffApplicationStateChange_001
 * @tc.desc: CjApplicationContextTest test for OnOffApplicationStateChange.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestOnOffApplicationStateChange_001, TestSize.Level1)
{
    int32_t callbackId = 10;
    int32_t err = 0;
    int32_t *errCode = &err;
    cjAppContext_->applicationContext_.reset();
    cjAppContext_->OnOffApplicationStateChange(callbackId, errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);

    cjAppContext_->applicationContext_ = std::make_shared<AbilityRuntime::ApplicationContext>();
    cjAppContext_->applicationStateCallback_ = std::make_shared<CjApplicationStateChangeCallback>();
    cjAppContext_->OnOffApplicationStateChange(callbackId, errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);

    cjAppContext_->applicationStateCallback_ = nullptr;
    cjAppContext_->OnOffApplicationStateChange(callbackId, errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnAbilityCreate_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnAbilityCreate.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnAbilityCreate_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnAbilityCreate(_)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    cjAppContext_->DispatchOnAbilityCreate(10);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnWindowStageCreate_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnWindowStageCreate.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnWindowStageCreate_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnWindowStageCreate(_, _)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    auto win = std::make_shared<Rosen::WindowScene>();
    auto winStage = new Rosen::CJWindowStageImpl(win);
    WindowStagePtr windowStage = reinterpret_cast<WindowStagePtr>(winStage);
    cjAppContext_->DispatchOnWindowStageCreate(10, windowStage);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchWindowStageFocus_001
 * @tc.desc: CjApplicationContextTest test for DispatchWindowStageFocus.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchWindowStageFocus_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnWindowStageActive(_, _)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    auto win = std::make_shared<Rosen::WindowScene>();
    auto winStage = new Rosen::CJWindowStageImpl(win);
    WindowStagePtr windowStage = reinterpret_cast<WindowStagePtr>(winStage);
    cjAppContext_->DispatchWindowStageFocus(10, windowStage);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchWindowStageUnfocus_001
 * @tc.desc: CjApplicationContextTest test for DispatchWindowStageUnfocus.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchWindowStageUnfocus_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnWindowStageInactive(_, _)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    auto win = std::make_shared<Rosen::WindowScene>();
    auto winStage = new Rosen::CJWindowStageImpl(win);
    WindowStagePtr windowStage = reinterpret_cast<WindowStagePtr>(winStage);
    cjAppContext_->DispatchWindowStageUnfocus(10, windowStage);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnWindowStageDestroy_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnWindowStageDestroy.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnWindowStageDestroy_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnWindowStageDestroy(_, _)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    auto win = std::make_shared<Rosen::WindowScene>();
    auto winStage = new Rosen::CJWindowStageImpl(win);
    WindowStagePtr windowStage = reinterpret_cast<WindowStagePtr>(winStage);
    cjAppContext_->DispatchOnWindowStageDestroy(10, windowStage);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnAbilityDestroy_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnAbilityDestroy.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnAbilityDestroy_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnAbilityDestroy(_)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    cjAppContext_->DispatchOnAbilityDestroy(10);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnAbilityForeground_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnAbilityForeground.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnAbilityForeground_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnAbilityForeground(_)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    cjAppContext_->DispatchOnAbilityForeground(10);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnAbilityBackground_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnAbilityBackground.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnAbilityBackground_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnAbilityBackground(_)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    cjAppContext_->DispatchOnAbilityBackground(10);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextDispatchOnAbilityContinue_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnAbilityContinue.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextDispatchOnAbilityContinue_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnAbilityContinue(_)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    cjAppContext_->DispatchOnAbilityContinue(10);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnAbilityWillCreate_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnAbilityWillCreate.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnAbilityWillCreate_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnAbilityWillCreate(_)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    cjAppContext_->DispatchOnAbilityWillCreate(10);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnWindowStageWillCreate_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnWindowStageWillCreate.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnWindowStageWillCreate_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnWindowStageWillCreate(_, _)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    auto win = std::make_shared<Rosen::WindowScene>();
    auto winStage = new Rosen::CJWindowStageImpl(win);
    WindowStagePtr windowStage = reinterpret_cast<WindowStagePtr>(winStage);
    cjAppContext_->DispatchOnWindowStageWillCreate(10, windowStage);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnWindowStageWillDestroy_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnWindowStageWillDestroy.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnWindowStageWillDestroy_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnWindowStageWillDestroy(_, _)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    auto win = std::make_shared<Rosen::WindowScene>();
    auto winStage = new Rosen::CJWindowStageImpl(win);
    WindowStagePtr windowStage = reinterpret_cast<WindowStagePtr>(winStage);
    cjAppContext_->DispatchOnWindowStageWillDestroy(10, windowStage);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnAbilityWillDestroy_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnAbilityWillDestroy.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnAbilityWillDestroy_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnAbilityWillDestroy(_)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    cjAppContext_->DispatchOnAbilityWillDestroy(10);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnAbilityWillForeground_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnAbilityWillForeground.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnAbilityWillForeground_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnAbilityWillForeground(_)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    cjAppContext_->DispatchOnAbilityWillForeground(10);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnAbilityWillBackground_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnAbilityWillBackground.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnAbilityWillBackground_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnAbilityWillBackground(_)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    cjAppContext_->DispatchOnAbilityWillBackground(10);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnNewWant_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnNewWant.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnNewWant_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnNewWant(_)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    cjAppContext_->DispatchOnNewWant(10);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnNewWant_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnNewWant.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnWillNewWant_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnWillNewWant(_)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    cjAppContext_->DispatchOnWillNewWant(10);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnAbilityWillContinue_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnAbilityWillContinue.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnAbilityWillContinue_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnAbilityWillContinue(_)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    cjAppContext_->DispatchOnAbilityWillContinue(10);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnWindowStageWillRestore_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnWindowStageWillRestore.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnWindowStageWillRestore_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnWindowStageWillRestore(_, _)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    auto win = std::make_shared<Rosen::WindowScene>();
    auto winStage = new Rosen::CJWindowStageImpl(win);
    WindowStagePtr windowStage = reinterpret_cast<WindowStagePtr>(winStage);
    cjAppContext_->DispatchOnWindowStageWillRestore(10, windowStage);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnWindowStageRestore_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnWindowStageRestore.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnWindowStageRestore_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnWindowStageRestore(_, _)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    auto win = std::make_shared<Rosen::WindowScene>();
    auto winStage = new Rosen::CJWindowStageImpl(win);
    WindowStagePtr windowStage = reinterpret_cast<WindowStagePtr>(winStage);
    cjAppContext_->DispatchOnWindowStageRestore(10, windowStage);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnAbilityWillSaveState_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnAbilityWillSaveState.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnAbilityWillSaveState_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnAbilityWillSaveState(_)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    cjAppContext_->DispatchOnAbilityWillSaveState(10);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestDispatchOnAbilitySaveState_001
 * @tc.desc: CjApplicationContextTest test for DispatchOnAbilitySaveState.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestDispatchOnAbilitySaveState_001, TestSize.Level1)
{
    std::shared_ptr<MockCjAbilityLifecycleCallback> mock = std::make_shared<MockCjAbilityLifecycleCallback>();
    EXPECT_CALL(*mock, OnAbilitySaveState(_)).Times(1);
    cjAppContext_->RegisterAbilityLifecycleCallback(mock);
    cjAppContext_->DispatchOnAbilitySaveState(10);
    cjAppContext_->UnregisterAbilityLifecycleCallback(mock);
}

/**
 * @tc.name: CJApplicationContextTestOnGetRunningProcessInformation_001
 * @tc.desc: CjApplicationContextTest test for OnGetRunningProcessInformation.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestOnGetRunningProcessInformation_001, TestSize.Level1)
{
    cjAppContext_->applicationContext_.reset();
    int err = 0;
    int* errorCode = &err;
    auto info = cjAppContext_->OnGetRunningProcessInformation(errorCode);
    EXPECT_EQ(*errorCode, ERR_ABILITY_RUNTIME_EXTERNAL_CONTEXT_NOT_EXIST);
    EXPECT_EQ(info, nullptr);
}

/**
 * @tc.name: CJApplicationContextTestOnOnKillProcessBySelf_001
 * @tc.desc: CjApplicationContextTest test for OnKillProcessBySelf.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestOnOnKillProcessBySelf_001, TestSize.Level1)
{
    cjAppContext_->applicationContext_.reset();
    int err = 0;
    int* errorCode = &err;
    cjAppContext_->OnKillProcessBySelf(true, errorCode);
    EXPECT_EQ(*errorCode, ERR_ABILITY_RUNTIME_EXTERNAL_CONTEXT_NOT_EXIST);

    auto applicationContext = std::make_shared<ApplicationContext>();
    cjAppContext_ = std::make_shared<CJApplicationContext>(applicationContext);
    err = 0;
    cjAppContext_->OnKillProcessBySelf(true, errorCode);
    EXPECT_EQ(*errorCode, 0);
}

/**
 * @tc.name: CJApplicationContextTestOnGetCurrentAppCloneIndex_001
 * @tc.desc: CjApplicationContextTest test for OnGetCurrentAppCloneIndex.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestOnGetCurrentAppCloneIndex_001, TestSize.Level1)
{
    cjAppContext_->applicationContext_.reset();
    int err = 0;
    int* errorCode = &err;
    auto index = cjAppContext_->OnGetCurrentAppCloneIndex(errorCode);
    EXPECT_EQ(*errorCode, ERR_ABILITY_RUNTIME_EXTERNAL_CONTEXT_NOT_EXIST);

    auto applicationContext = std::make_shared<ApplicationContext>();
    cjAppContext_ = std::make_shared<CJApplicationContext>(applicationContext);
    index = cjAppContext_->OnGetCurrentAppCloneIndex(errorCode);
    EXPECT_EQ(*errorCode, ERR_ABILITY_RUNTIME_EXTERNAL_NOT_APP_CLONE);
    EXPECT_EQ(index, -1);
}

/**
 * @tc.name: CJApplicationContextTestOnRestartApp_001
 * @tc.desc: CjApplicationContextTest test for OnRestartApp.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestOnRestartApp_001, TestSize.Level1)
{
    cjAppContext_->applicationContext_.reset();
    int err = 0;
    int* errorCode = &err;
    cjAppContext_->OnRestartApp(AAFwk::Want(), errorCode);
    EXPECT_EQ(*errorCode, ERR_ABILITY_RUNTIME_EXTERNAL_CONTEXT_NOT_EXIST);

    auto applicationContext = std::make_shared<ApplicationContext>();
    cjAppContext_ = std::make_shared<CJApplicationContext>(applicationContext);
    cjAppContext_->OnRestartApp(AAFwk::Want(), errorCode);
    EXPECT_EQ(*errorCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
}

/**
 * @tc.name: CJApplicationContextTestOnClearUpApplicationData_001
 * @tc.desc: CjApplicationContextTest test for OnClearUpApplicationData.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestOnClearUpApplicationData_001, TestSize.Level1)
{
    cjAppContext_->applicationContext_.reset();
    int err = 0;
    int* errorCode = &err;
    cjAppContext_->OnClearUpApplicationData(errorCode);
    EXPECT_EQ(*errorCode, ERR_ABILITY_RUNTIME_EXTERNAL_CONTEXT_NOT_EXIST);

    auto applicationContext = std::make_shared<ApplicationContext>();
    cjAppContext_ = std::make_shared<CJApplicationContext>(applicationContext);
    err = 0;
    cjAppContext_->OnClearUpApplicationData(errorCode);
    EXPECT_EQ(*errorCode, 0);
}

/**
 * @tc.name: CJApplicationContextTestOnSetSupportedProcessCacheSelf_001
 * @tc.desc: CjApplicationContextTest test for OnSetSupportedProcessCacheSelf.
 * @tc.type: FUNC
 */
HWTEST_F(CjApplicationContextTest, CJApplicationContextTestOnSetSupportedProcessCacheSelf_001, TestSize.Level1)
{
    cjAppContext_->applicationContext_.reset();
    int err = 0;
    int* errorCode = &err;
    cjAppContext_->OnSetSupportedProcessCacheSelf(true, errorCode);
    EXPECT_EQ(*errorCode, ERR_ABILITY_RUNTIME_EXTERNAL_CONTEXT_NOT_EXIST);

    auto applicationContext = std::make_shared<ApplicationContext>();
    cjAppContext_ = std::make_shared<CJApplicationContext>(applicationContext);
    cjAppContext_->OnSetSupportedProcessCacheSelf(true, errorCode);
    EXPECT_EQ(*errorCode, ERR_ABILITY_RUNTIME_EXTERNAL_INTERNAL_ERROR);
}
}  // namespace AbilityRuntime
}  // namespace OHOS