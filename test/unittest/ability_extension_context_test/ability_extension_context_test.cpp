/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define protected public
#include "extension_base.h"
#undef private
#undef protected

#include "ability_handler.h"
#include "configuration.h"
#include "hilog_tag_wrapper.h"
#include "iremote_object.h"
#include "mock_ability_token.h"
#include "ohos_application.h"
#include "extension_context.h"
#include "want.h"

using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class AbilityExtensionContextTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AbilityExtensionContextTest::SetUpTestCase(void)
{}

void AbilityExtensionContextTest::TearDownTestCase(void)
{}

void AbilityExtensionContextTest::SetUp()
{}

void AbilityExtensionContextTest::TearDown()
{}

/**
 * @tc.name: GetAbilityInfo_0100
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityExtensionContextTest, GetAbilityInfo_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAbilityInfo start");

    std::shared_ptr<AppExecFwk::AbilityInfo> info = std::make_shared<AppExecFwk::AbilityInfo>();
    info->name = "ExtensionContextTest";
    auto record = std::make_shared<AppExecFwk::AbilityLocalRecord>(info, nullptr, nullptr, 0);
    std::shared_ptr<AppExecFwk::OHOSApplication> application = std::make_shared<AppExecFwk::OHOSApplication>();
    std::shared_ptr<AppExecFwk::AbilityHandler> handler = std::make_shared<AppExecFwk::AbilityHandler>(nullptr);
    sptr<IRemoteObject> token = new AppExecFwk::MockAbilityToken();

    std::shared_ptr<AbilityRuntime::ContextImpl> contextImpl = std::make_shared<AbilityRuntime::ContextImpl>();
    std::shared_ptr<AbilityRuntime::ApplicationContext> applicationContext =
        AbilityRuntime::ApplicationContext::GetInstance();
    applicationContext->AttachContextImpl(contextImpl);
    application->SetApplicationContext(applicationContext);

    ExtensionBase<ExtensionContext> extensionBase;
    extensionBase.Init(record, application, handler, token);
    std::shared_ptr<ExtensionContext> context = extensionBase.GetContext();

    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = context->GetAbilityInfo();
    EXPECT_STREQ(abilityInfo->name.c_str(), "ExtensionContextTest");

    TAG_LOGI(AAFwkTag::TEST, "GetAbilityInfo end");
}

/**
 * @tc.name: SetAbilityInfo_0100
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityExtensionContextTest, SetAbilityInfo_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetAbilityInfo start");

    std::shared_ptr<AppExecFwk::AbilityInfo> info = std::make_shared<AppExecFwk::AbilityInfo>();
    info->name = "ExtensionContextTest";
    auto record = std::make_shared<AppExecFwk::AbilityLocalRecord>(info, nullptr, nullptr, 0);
    std::shared_ptr<AppExecFwk::OHOSApplication> application = std::make_shared<AppExecFwk::OHOSApplication>();
    std::shared_ptr<AppExecFwk::AbilityHandler> handler = std::make_shared<AppExecFwk::AbilityHandler>(nullptr);
    sptr<IRemoteObject> token = new AppExecFwk::MockAbilityToken();

    std::shared_ptr<AbilityRuntime::ContextImpl> contextImpl = std::make_shared<AbilityRuntime::ContextImpl>();
    std::shared_ptr<AbilityRuntime::ApplicationContext> applicationContext =
        AbilityRuntime::ApplicationContext::GetInstance();
    applicationContext->AttachContextImpl(contextImpl);
    application->SetApplicationContext(applicationContext);

    ExtensionBase<ExtensionContext> extensionBase;
    extensionBase.Init(record, application, handler, token);
    std::shared_ptr<ExtensionContext> context = extensionBase.GetContext();

    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = context->GetAbilityInfo();
    EXPECT_STREQ(abilityInfo->name.c_str(), "ExtensionContextTest");

    info->name = "NewExtensionContextTest";
    context->SetAbilityInfo(info);

    abilityInfo = context->GetAbilityInfo();
    EXPECT_STREQ(abilityInfo->name.c_str(), "NewExtensionContextTest");

    TAG_LOGI(AAFwkTag::TEST, "SetAbilityInfo end");
}

/**
 * @tc.number: SetAbilityInfo_0200
 * @tc.name: SetAbilityInfo
 * @tc.desc: Set AbilityInfo Failed
 */
HWTEST_F(AbilityExtensionContextTest, SetAbilityInfo_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetAbilityInfo start");

    std::shared_ptr<AppExecFwk::AbilityInfo> info = std::make_shared<AppExecFwk::AbilityInfo>();
    info->name = "ExtensionContextTest";
    auto record = std::make_shared<AppExecFwk::AbilityLocalRecord>(info, nullptr, nullptr, 0);
    std::shared_ptr<AppExecFwk::OHOSApplication> application = std::make_shared<AppExecFwk::OHOSApplication>();
    std::shared_ptr<AppExecFwk::AbilityHandler> handler = std::make_shared<AppExecFwk::AbilityHandler>(nullptr);
    sptr<IRemoteObject> token = new AppExecFwk::MockAbilityToken();

    std::shared_ptr<AbilityRuntime::ContextImpl> contextImpl = std::make_shared<AbilityRuntime::ContextImpl>();
    std::shared_ptr<AbilityRuntime::ApplicationContext> applicationContext =
        AbilityRuntime::ApplicationContext::GetInstance();
    applicationContext->AttachContextImpl(contextImpl);
    application->SetApplicationContext(applicationContext);

    ExtensionBase<ExtensionContext> extensionBase;
    extensionBase.Init(record, application, handler, token);
    std::shared_ptr<ExtensionContext> context = extensionBase.GetContext();

    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = context->GetAbilityInfo();
    EXPECT_STREQ(abilityInfo->name.c_str(), "ExtensionContextTest");

    info = nullptr;
    context->SetAbilityInfo(info);

    abilityInfo = context->GetAbilityInfo();
    EXPECT_NE(abilityInfo, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "SetAbilityInfo end");
}
} // namespace AbilityRuntime
} // namespace OHOS
