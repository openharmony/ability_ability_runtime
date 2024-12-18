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
#include <singleton.h>

#define private public
#include "context_impl.h"
#include "bundle_mgr_helper.h"
#undef private

#include "constants.h"
#include "ability_local_record.h"
#include "application_context.h"
#include "ability_stage_context.h"
#include "context.h"
#include "hap_module_info.h"
#include "hilog_tag_wrapper.h"
#include "iremote_object.h"
#include "system_ability_definition.h"
#include "sys_mgr_client.h"

namespace OHOS {
namespace AppExecFwk {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

class ContextImplSecondTest : public testing::Test {
public:
    ContextImplSecondTest()
    {}
    ~ContextImplSecondTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ContextImplSecondTest::SetUpTestCase(void)
{}

void ContextImplSecondTest::TearDownTestCase(void)
{}

void ContextImplSecondTest::SetUp(void)
{}

void ContextImplSecondTest::TearDown(void)
{}

/**
 * @tc.number: AppExecFwk_AppContext_CreateHspResourceManager_001
 * @tc.name: CreateHspResourceManager
 * @tc.desc: Test whether CreateHspResourceManager is called normally.
 * @tc.type: FUNC
 * @tc.require: issueI5HQEM
 */
HWTEST_F(ContextImplSecondTest, AppExecFwk_AppContext_CreateHspResourceManager_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_AppContext_CreateHspResourceManager_001 start";

    std::shared_ptr<AbilityRuntime::ContextImpl> contextImpl_ = std::make_shared<AbilityRuntime::ContextImpl>();
    auto config = std::make_shared<AppExecFwk::Configuration>();
    contextImpl_->SetConfiguration(config);
    AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.name = "com.example.myapplication";
    bundleInfo.applicationInfo.name = "applicationName";
    AppExecFwk::HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "com.test.moduleName";

    std::shared_ptr<AppExecFwk::ApplicationInfo> applicationInfo = std::make_shared<AppExecFwk::ApplicationInfo>();
    applicationInfo->bundleName = "com.example.myapplication";
    contextImpl_->SetApplicationInfo(applicationInfo);
    contextImpl_->InitHapModuleInfo(hapModuleInfo);
    contextImpl_->InitResourceManager(bundleInfo, contextImpl_, true, "com.test.moduleName");

    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    ASSERT_NE(resConfig, nullptr);
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager = nullptr;
    resourceManager = contextImpl_->GetResourceManager();
    if (resourceManager != nullptr) {
        resourceManager->GetResConfig(*resConfig);
        resConfig->SetMcc(11);
        resConfig->SetMnc(22);
        resourceManager->UpdateResConfig(*resConfig);
    }

    std::unique_ptr<Global::Resource::ResConfig> resConfig2(Global::Resource::CreateResConfig());
    ASSERT_NE(resConfig2, nullptr);
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager2 = nullptr;
    auto ret = contextImpl_->CreateHspModuleResourceManager(
        "com.example.myapplication", "com.test.moduleName", resourceManager2);
    if (resourceManager2 != nullptr) {
        resourceManager2->GetResConfig(*resConfig2);
        EXPECT_EQ(resConfig2->GetMcc(), 11);
        EXPECT_EQ(resConfig2->GetMnc(), 22);
        GTEST_LOG_(INFO) << "AppExecFwk_AppContext_CreateHspResourceManager_001 create resourceManager successfully";
    }
    ret = contextImpl_->CreateHspModuleResourceManager("com.example.myapplication", "*&%@#$%^&*()", resourceManager2);
    if (ret == 0) {
        EXPECT_NE(resourceManager2, nullptr);
    }
    
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager3 = nullptr;
    ret = contextImpl_->CreateHspModuleResourceManager("com.example.myapplication", "", resourceManager3);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    ret = contextImpl_->CreateHspModuleResourceManager("", "com.test.moduleName", resourceManager3);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    ret = contextImpl_->CreateHspModuleResourceManager(
        "com.test.myapplication", "com.test.moduleName", resourceManager2);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    GTEST_LOG_(INFO) << "AppExecFwk_AppContext_CreateHspResourceManager_001 end";
}

/**
 * @tc.number: AppExecFwk_AppContext_CreateHspResourceManager_002
 * @tc.name: CreateHspResourceManager
 * @tc.desc: Test whether CreateHspResourceManager is called normally.
 * @tc.type: FUNC
 * @tc.require: issueI5HQEM
 */
HWTEST_F(ContextImplSecondTest, AppExecFwk_AppContext_CreateHspResourceManager_002, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_AppContext_CreateHspResourceManager_002 start";

    std::shared_ptr<AbilityRuntime::ContextImpl> contextImpl_ = std::make_shared<AbilityRuntime::ContextImpl>();
    auto config = std::make_shared<AppExecFwk::Configuration>();
    contextImpl_->SetConfiguration(config);
    AppExecFwk::BundleInfo bundleInfo;
    //Same name as HSP
    bundleInfo.name = "com.example.myapplication";
    bundleInfo.applicationInfo.name = "applicationName";
    AppExecFwk::HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "com.test.moduleName";

    std::shared_ptr<AppExecFwk::ApplicationInfo> applicationInfo = std::make_shared<AppExecFwk::ApplicationInfo>();
    applicationInfo->bundleName = "com.test.myapplication";
    contextImpl_->SetApplicationInfo(applicationInfo);
    contextImpl_->InitHapModuleInfo(hapModuleInfo);
    contextImpl_->InitResourceManager(bundleInfo, contextImpl_, true, "com.test.moduleName");

    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    ASSERT_NE(resConfig, nullptr);
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager = nullptr;
    resourceManager = contextImpl_->GetResourceManager();
    uint32_t mcc, mnc, thrmeid;
    bool themeIcon;
    if (resourceManager != nullptr) {
        resourceManager->GetResConfig(*resConfig);
        mcc = resConfig->GetMcc();
        mnc =resConfig->GetMnc();
        thrmeid = resConfig->GetThemeId();
        themeIcon = resConfig->GetThemeIcon();
    }

    std::unique_ptr<Global::Resource::ResConfig> resConfig2(Global::Resource::CreateResConfig());
    ASSERT_NE(resConfig2, nullptr);
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager2 = nullptr;
    auto ret = contextImpl_->CreateHspModuleResourceManager(
        "com.example.myapplication", "com.test.moduleName", resourceManager2);
    if (resourceManager2 != nullptr) {
        resourceManager2->GetResConfig(*resConfig2);
        EXPECT_EQ(resConfig2->GetMcc(), mcc);
        EXPECT_EQ(resConfig2->GetMnc(), mnc);
        EXPECT_EQ(resConfig2->GetThemeId(), thrmeid);
        EXPECT_TRUE(resConfig2->GetThemeIcon() == themeIcon);
        GTEST_LOG_(INFO) << "AppExecFwk_AppContext_CreateHspResourceManager_002 create resourceManager successfully";
    }

    ret = contextImpl_->CreateHspModuleResourceManager(
        "com.example.myapplication", "*&%@#$%^&*()", resourceManager2);
    if (ret == 0) {
        EXPECT_EQ(resourceManager2, nullptr);
    }

    GTEST_LOG_(INFO) << "AppExecFwk_AppContext_CreateHspResourceManager_002 end";
}

/**
 * @tc.number: AppExecFwk_AppContext_CreateHspResourceManager_003
 * @tc.name: CreateHspResourceManager
 * @tc.desc: Test whether CreateHspResourceManager is called normally.
 * @tc.type: FUNC
 * @tc.require: issueI5HQEM
 */
HWTEST_F(ContextImplSecondTest, AppExecFwk_AppContext_CreateHspResourceManager_003, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_AppContext_CreateHspResourceManager_003 start";

    std::shared_ptr<AbilityRuntime::ContextImpl> contextImpl_ = std::make_shared<AbilityRuntime::ContextImpl>();
    auto config = std::make_shared<AppExecFwk::Configuration>();
    contextImpl_->SetConfiguration(config);
    AppExecFwk::BundleInfo bundleInfo;

    bundleInfo.name = "com.example.myapplication";
    bundleInfo.applicationInfo.name = "applicationName";
    AppExecFwk::HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "com.test.moduleName";

    std::shared_ptr<AppExecFwk::ApplicationInfo> applicationInfo = std::make_shared<AppExecFwk::ApplicationInfo>();
    applicationInfo->bundleName = "com.test.myapplication";
    contextImpl_->SetApplicationInfo(applicationInfo);
    contextImpl_->InitHapModuleInfo(hapModuleInfo);
    contextImpl_->InitResourceManager(bundleInfo, contextImpl_, true, "com.test.moduleName");

    std::shared_ptr<Global::Resource::ResourceManager> resourceManager3 = nullptr;
    auto ret = contextImpl_->CreateHspModuleResourceManager("com.example.myapplication", "", resourceManager3);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    ret = contextImpl_->CreateHspModuleResourceManager("", "com.test.moduleName", resourceManager3);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    ret = contextImpl_->CreateHspModuleResourceManager(
        "com.test.myapplication", "com.test.moduleName", resourceManager3);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    GTEST_LOG_(INFO) << "AppExecFwk_AppContext_CreateHspResourceManager_003 end";
}
}  // namespace AppExecFwk
}
