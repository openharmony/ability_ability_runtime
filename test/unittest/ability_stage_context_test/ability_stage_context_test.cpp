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

#include "hilog_tag_wrapper.h"
#include "ability_stage_context.h"
#include "application_context.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class AbilityStageContextTest : public testing::Test {
public:

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AbilityStageContextTest::SetUpTestCase(void)
{}

void AbilityStageContextTest::TearDownTestCase(void)
{}

void AbilityStageContextTest::SetUp()
{}

void AbilityStageContextTest::TearDown()
{}

/**
 * @tc.name: AbilityStageContextTest_0100
 * @tc.desc: Ability stage basic func test.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AbilityStageContextTest, AbilityStageContextTest_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    auto context = AbilityRuntime::ApplicationContext::GetInstance();
    auto abilityStageContext = std::make_shared<AbilityStageContext>();
    abilityStageContext->SetParentContext(context);

    auto abilityInfo = std::make_shared<AppExecFwk::AbilityInfo>();
    abilityStageContext->InitHapModuleInfo(abilityInfo);

    AppExecFwk::HapModuleInfo hapModuleInfo;
    abilityStageContext->InitHapModuleInfo(hapModuleInfo);

    auto gotHapModuleInfo = abilityStageContext->GetHapModuleInfo();
    EXPECT_NE(gotHapModuleInfo, nullptr);

    auto config = std::make_shared<AppExecFwk::Configuration>();
    abilityStageContext->SetConfiguration(config);

    auto gotConfig = abilityStageContext->GetConfiguration();
    EXPECT_NE(gotConfig, nullptr);

    std::shared_ptr<Global::Resource::ResourceManager> resMgr(Global::Resource::CreateResourceManager());
    abilityStageContext->SetResourceManager(resMgr);
    auto gotResMgr = abilityStageContext->GetResourceManager();
    EXPECT_NE(gotResMgr, nullptr);

    auto gotBundleName = abilityStageContext->GetBundleName();
    EXPECT_EQ(gotBundleName, "");

    auto gotAppInfo = abilityStageContext->GetApplicationInfo();
    EXPECT_EQ(gotAppInfo, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: AbilityStageContextTest_0200
 * @tc.desc: Ability stage basic func test.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AbilityStageContextTest, AbilityStageContextTest_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    auto context = AbilityRuntime::ApplicationContext::GetInstance();
    auto abilityStageContext = std::make_shared<AbilityStageContext>();
    abilityStageContext->SetParentContext(context);

    auto bundleContext = abilityStageContext->CreateBundleContext("com.test.bundleName");
    EXPECT_EQ(bundleContext, nullptr);

    auto moduleContext1 = abilityStageContext->CreateModuleContext("moudleName");
    EXPECT_EQ(moduleContext1, nullptr);

    auto moduleContext2 = abilityStageContext->CreateModuleContext("com.test.bundleName", "moudleName");
    EXPECT_EQ(moduleContext2, nullptr);

    auto moduleResMgr = abilityStageContext->CreateModuleResourceManager("com.test.bundleName", "moudleName");
    EXPECT_EQ(moduleResMgr, nullptr);

    std::shared_ptr<Global::Resource::ResourceManager> hspResMgr(Global::Resource::CreateResourceManager());
    auto ret = abilityStageContext->CreateSystemHspModuleResourceManager("com.test.bundleName", "moudleName",
        hspResMgr);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_NE(hspResMgr, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: AbilityStageContextTest_0300
 * @tc.desc: Ability stage basic func test.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AbilityStageContextTest, AbilityStageContextTest_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    auto context = AbilityRuntime::ApplicationContext::GetInstance();
    auto abilityStageContext = std::make_shared<AbilityStageContext>();
    abilityStageContext->SetParentContext(context);

    EXPECT_EQ(abilityStageContext->GetBundleCodePath(), "");
    EXPECT_EQ(abilityStageContext->GetBundleCodeDir(), "");
    EXPECT_EQ(abilityStageContext->GetCacheDir(), "/data/storage/el2/base/haps//cache");
    EXPECT_EQ(abilityStageContext->GetTempDir(), "/data/storage/el2/base/haps//temp");
    EXPECT_EQ(abilityStageContext->GetResourceDir(), "");
    EXPECT_EQ(abilityStageContext->GetFilesDir(), "/data/storage/el2/base/haps//files");
    EXPECT_EQ(abilityStageContext->GetDatabaseDir(), "/data/storage/el2/database/");
    EXPECT_EQ(abilityStageContext->GetPreferencesDir(), "/data/storage/el2/base/haps//preferences");
    EXPECT_EQ(abilityStageContext->GetGroupDir("1"), "");

    std::string sysDatabaseDir;
    auto ret = abilityStageContext->GetSystemDatabaseDir("1", false, sysDatabaseDir);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_EQ(sysDatabaseDir, "");

    std::string sysPreferencesDir;
    ret = abilityStageContext->GetSystemPreferencesDir("1", false, sysPreferencesDir);
    EXPECT_EQ(sysDatabaseDir, "");

    EXPECT_EQ(abilityStageContext->GetDistributedFilesDir(), "/data/storage/el2/distributedfiles");
    EXPECT_EQ(abilityStageContext->GetCloudFileDir(), "/data/storage/el2/cloud");
    EXPECT_EQ(abilityStageContext->GetBaseDir(), "/data/storage/el2/base/haps/");
    TAG_LOGI(AAFwkTag::TEST, "end.");
}


/**
 * @tc.name: AbilityStageContextTest_0400
 * @tc.desc: Ability stage basic func test.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AbilityStageContextTest, AbilityStageContextTest_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    auto context = AbilityRuntime::ApplicationContext::GetInstance();
    auto abilityStageContext = std::make_shared<AbilityStageContext>();
    abilityStageContext->SetParentContext(context);

    EXPECT_EQ(abilityStageContext->IsUpdatingConfigurations(), false);
    EXPECT_EQ(abilityStageContext->PrintDrawnCompleted(), false);

    auto token = abilityStageContext->GetToken();
    abilityStageContext->SetToken(token);

    abilityStageContext->SwitchArea(1);
    EXPECT_EQ(abilityStageContext->GetArea(), 1);

    EXPECT_EQ(abilityStageContext->GetDeviceType(), Global::Resource::DeviceType::DEVICE_PHONE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}
} // namespace AbilityRuntime
} // namespace OHOS
