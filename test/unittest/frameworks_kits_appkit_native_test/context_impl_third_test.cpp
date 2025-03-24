/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include <singleton.h>

#define private public
#include "context_impl.h"
#undef private

#include "constants.h"
#include "ability_local_record.h"
#include "application_context.h"
#include "context.h"
#include "hap_module_info.h"
#include "hilog_tag_wrapper.h"
#include "iremote_object.h"
#include "mock_ability_token.h"
#include "mock_bundle_manager.h"
#include "system_ability_definition.h"
#include "sys_mgr_client.h"
#include "running_process_info.h"

namespace OHOS {
namespace AppExecFwk {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const int64_t CONTEXT_CREATE_BY_SYSTEM_APP(0x00000001);
#ifdef SUPPORT_GRAPHICS
const uint64_t INVALID_DISPLAY_ID = 500000;
#endif
const uint64_t DEFAULT_DISPLAY_ID = 0;
const float DENSITY = 1.5;
constexpr const char* DIRECTION_HORIZONTAL = "horizontal";
} // namespace

class ContextImplTest : public testing::Test {
public:
    ContextImplTest() : contextImpl_(nullptr)
    {}
    ~ContextImplTest()
    {}
    std::shared_ptr<AbilityRuntime::ContextImpl> contextImpl_ = nullptr;
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ContextImplTest::SetUpTestCase(void)
{}

void ContextImplTest::TearDownTestCase(void)
{}

void ContextImplTest::SetUp(void)
{
    contextImpl_ = std::make_shared<AbilityRuntime::ContextImpl>();
    auto config = std::make_shared<AppExecFwk::Configuration>();
    EXPECT_NE(config, nullptr);
    contextImpl_->SetConfiguration(config);
    sptr<IRemoteObject> bundleObject = new (std::nothrow) BundleMgrService();
    DelayedSingleton<SysMrgClient>::GetInstance()->RegisterSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID,
        bundleObject);
}

void ContextImplTest::TearDown(void)
{}

/**
 * @tc.number: AppExecFwk_ContextImpl_SetMcc_004
 * @tc.name: SetMcc
 * @tc.desc: SetMcc success
 * @tc.type: FUNC
 */
HWTEST_F(ContextImplTest, AppExecFwk_ContextImpl_SetMcc_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContextImpl_SetMcc_001 start";
    auto contextImpl = std::make_shared<AbilityRuntime::ContextImpl>();
    auto config = std::make_shared<AppExecFwk::Configuration>();
    contextImpl->SetConfiguration(config);
    contextImpl->SetMcc("zh");
    EXPECT_EQ(contextImpl->config_->GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_MCC), "zh");
    GTEST_LOG_(INFO) << "AppExecFwk_ContextImpl_SetMcc_001 end";
}

/**
 * @tc.number: AppExecFwk_ContextImpl_SetMnc_004
 * @tc.name: SetMnc
 * @tc.desc: SetMnc success
 * @tc.type: FUNC
 */
HWTEST_F(ContextImplTest, AppExecFwk_ContextImpl_SetMnc_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContextImpl_SetMnc_004 start";
    auto contextImpl = std::make_shared<AbilityRuntime::ContextImpl>();
    auto config = std::make_shared<AppExecFwk::Configuration>();
    contextImpl->SetConfiguration(config);
    contextImpl->SetMnc("ENG");
    EXPECT_EQ(contextImpl->config_->GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_MNC), "ENG");
    GTEST_LOG_(INFO) << "AppExecFwk_ContextImpl_SetMnc_004 end";
}

/**
 * @tc.number: AppExecFwk_ContextImpl_CreateModuleContext_004
 * @tc.name: CreateModuleContext
 * @tc.desc: CreateModuleContext success
 * @tc.type: FUNC
 */
HWTEST_F(ContextImplTest, AppExecFwk_ContextImpl_CreateModuleContext_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_ContextImpl_CreateModuleContext_004 start";
    AbilityRuntime::ContextImpl contextImpl;
    auto inputContextImpl = std::make_shared<AbilityRuntime::ContextImpl>();
    std::string moduleName = "";
    auto ref = contextImpl.CreateModuleContext(moduleName, inputContextImpl);
    EXPECT_EQ(ref, nullptr);
    GTEST_LOG_(INFO) << "AppExecFwk_ContextImpl_CreateModuleContext_004 end";
}

/**
 * @tc.number: AppExecFwk_ContextImpl_CreateBundleContext_004
 * @tc.name: CreateBundleContext
 * @tc.desc: CreateBundleContext success
 * @tc.type: FUNC
 */
HWTEST_F(ContextImplTest, AppExecFwk_ContextImpl_CreateBundleContext_001, Function | MediumTest | Level1)
{
    std::shared_ptr<AbilityRuntime::Context> context = std::make_shared<AbilityRuntime::ContextImpl>();
    std::string bundleName = "";
    std::shared_ptr<AbilityRuntime::Context> inputContext = std::make_shared<AbilityRuntime::ContextImpl>();
    AbilityRuntime::ContextImpl contextImpl;
    auto ret = contextImpl.CreateBundleContext(context, bundleName, inputContext);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    bundleName = "com.ohos.example.bundleName";
    ret = contextImpl.CreateBundleContext(context, bundleName, inputContext);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.number: AppExecFwk_ContextImpl_KillProcessBySelf_004
 * @tc.name: KillProcessBySelf
 * @tc.desc: KillProcessBySelf success
 * @tc.type: FUNC
 */
HWTEST_F(ContextImplTest, AppExecFwk_ContextImpl_KillProcessBySelf_001, Function | MediumTest | Level1)
{
    bool clearPageStack = false;
    auto contextImpl = std::make_shared<AbilityRuntime::ContextImpl>();
    contextImpl->KillProcessBySelf(clearPageStack);
    EXPECT_NE(contextImpl, nullptr);
}

/**
 * @tc.number: AppExecFwk_ContextImpl_GetProcessRunningInformation_004
 * @tc.name: GetProcessRunningInformation
 * @tc.desc: GetProcessRunningInformation success
 * @tc.type: FUNC
 */
HWTEST_F(ContextImplTest, AppExecFwk_ContextImpl_GetProcessRunningInformation_001, Function | MediumTest | Level1)
{
    AppExecFwk::RunningProcessInfo info;
    AbilityRuntime::ContextImpl contextImpl;
    EXPECT_NE(contextImpl.GetProcessRunningInformation(info), ERR_OK);
}

/**
 * @tc.number: AppExecFwk_ContextImpl_GetAllRunningInstanceKeys_004
 * @tc.name: GetAllRunningInstanceKeys
 * @tc.desc: GetAllRunningInstanceKeys success
 * @tc.type: FUNC
 */
HWTEST_F(ContextImplTest, AppExecFwk_ContextImpl_GetAllRunningInstanceKeys_001, Function | MediumTest | Level1)
{
    std::vector<std::string> instanceKeys;
    AbilityRuntime::ContextImpl contextImpl;
    EXPECT_NE(contextImpl.GetAllRunningInstanceKeys(instanceKeys), ERR_OK);
}

/**
 * @tc.number: AppExecFwk_ContextImpl_RestartApp_004
 * @tc.name: RestartApp
 * @tc.desc: RestartApp success
 * @tc.type: FUNC
 */
HWTEST_F(ContextImplTest, AppExecFwk_ContextImpl_RestartApp_001, Function | MediumTest | Level1)
{
    AAFwk::Want want;
    AbilityRuntime::ContextImpl contextImpl;
    EXPECT_NE(contextImpl.RestartApp(want), ERR_OK);
}

/**
 * @tc.number: AppExecFwk_ContextImpl_SetSupportedProcessCacheSelf_004
 * @tc.name: SetSupportedProcessCacheSelf
 * @tc.desc: SetSupportedProcessCacheSelf success
 * @tc.type: FUNC
 */
HWTEST_F(ContextImplTest, AppExecFwk_ContextImpl_SetSupportedProcessCacheSelf_001, Function | MediumTest | Level1)
{
    bool isSupport = true;
    AbilityRuntime::ContextImpl contextImpl;
    EXPECT_NE(contextImpl.SetSupportedProcessCacheSelf(isSupport), ERR_OK);
}
} // namespace AppExecFwk
} // namespace OHOS