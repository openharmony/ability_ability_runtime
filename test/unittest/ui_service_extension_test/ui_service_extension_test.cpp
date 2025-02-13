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
#include "ui_service_extension.h"
#include "ui_service_extension_module_loader.h"
#include "ui_service_extension_context.h"
#include "ability_manager_client.h"
#undef private
#undef protected

#include "mock_ability_token.h"
#include "mock_ability_manager_service.h"
#include "ability_handler.h"
#include "ohos_application.h"
#include "runtime.h"

using namespace testing::ext;
using namespace OHOS::Rosen;

namespace OHOS {
namespace AbilityRuntime {
class MockWindow : public Rosen::Window {
public:
    virtual Ace::UIContent* GetUIContent() const
    {
        return uiContent_.get();
    }

    std::unique_ptr<Ace::UIContent> uiContent_ = Ace::UIContent::Create(nullptr, nullptr);
};

class UIServiceExtensionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void UIServiceExtensionTest::SetUpTestCase(void)
{}

void UIServiceExtensionTest::TearDownTestCase(void)
{}

void UIServiceExtensionTest::SetUp()
{}

void UIServiceExtensionTest::TearDown()
{}

/**
 * @tc.number: Create_0100
 * @tc.name: UIServiceExtension Create
 * @tc.desc: UIServiceExtension Create.
 */
HWTEST_F(UIServiceExtensionTest, Create_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "Create_0100 start");

    std::unique_ptr<Runtime> runtime{nullptr};
    auto uIServiceExtensionPtr = UIServiceExtension::Create(runtime);
    EXPECT_TRUE(uIServiceExtensionPtr != nullptr);

    TAG_LOGI(AAFwkTag::TEST, "Create_0100 end");
}

/**
 * @tc.number: CreateAndInitContext_0100
 * @tc.name: UIServiceExtension CreateAndInitContext
 * @tc.desc: UIServiceExtension CreateAndInitContext.
 */
HWTEST_F(UIServiceExtensionTest, CreateAndInitContext_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CreateAndInitContext_0100 start");

    Runtime::Options options;
    options.lang = Runtime::Language::JS;
    auto runtime = Runtime::Create(options);
    auto uIServiceExtensionPtr = UIServiceExtension::Create(runtime);

    std::shared_ptr<AppExecFwk::AbilityInfo> info = std::make_shared<AppExecFwk::AbilityInfo>();
    info->name = "UIServiceExtensionTest";
    auto record = std::make_shared<AppExecFwk::AbilityLocalRecord>(info, nullptr, nullptr, 0);
    std::shared_ptr<AppExecFwk::OHOSApplication> application = std::make_shared<AppExecFwk::OHOSApplication>();
    std::shared_ptr<AppExecFwk::AbilityHandler> handler = std::make_shared<AppExecFwk::AbilityHandler>(nullptr);
    sptr<IRemoteObject> token = new AppExecFwk::MockAbilityToken();

    auto result = uIServiceExtensionPtr->CreateAndInitContext(record, application, handler, token);
    EXPECT_NE(result, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "CreateAndInitContext_0100 end");
}

/**
 * @tc.number: Init_0100
 * @tc.name: UIServiceExtension Init
 * @tc.desc: UIServiceExtension Init.
 */
HWTEST_F(UIServiceExtensionTest, Init_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "Init_0100 start");

    Runtime::Options options;
    options.lang = Runtime::Language::JS;
    auto runtime = Runtime::Create(options);
    auto uIServiceExtensionPtr = UIServiceExtension::Create(runtime);

    std::shared_ptr<AppExecFwk::AbilityInfo> info = std::make_shared<AppExecFwk::AbilityInfo>();
    info->name = "UIServiceExtensionTest";
    auto record = std::make_shared<AppExecFwk::AbilityLocalRecord>(info, nullptr, nullptr, 0);
    std::shared_ptr<AppExecFwk::OHOSApplication> application = std::make_shared<AppExecFwk::OHOSApplication>();
    std::shared_ptr<AppExecFwk::AbilityHandler> handler = std::make_shared<AppExecFwk::AbilityHandler>(nullptr);
    sptr<IRemoteObject> token = new AppExecFwk::MockAbilityToken();

    uIServiceExtensionPtr->Init(record, application, handler, token);
    EXPECT_TRUE(uIServiceExtensionPtr != nullptr);

    TAG_LOGI(AAFwkTag::TEST, "Init_0100 end");
}

/**
 * @tc.number: StartAbility_0100
 * @tc.name: UIServiceExtension StartAbility
 * @tc.desc: UIServiceExtension StartAbility.
 */
HWTEST_F(UIServiceExtensionTest, StartAbility_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "StartAbility_0100 start");

    AAFwk::Want want;
    AAFwk::StartOptions startOptions;

    sptr<AAFwk::MockAbilityManagerService> porxyNew = new (std::nothrow) AAFwk::MockAbilityManagerService();
    AbilityManagerClient::GetInstance()->proxy_ = porxyNew;

    UIServiceExtensionContext uiServiceExtensionContext;
    auto result = uiServiceExtensionContext.StartAbility(want, startOptions);
    EXPECT_EQ(result, ERR_OK);

    TAG_LOGI(AAFwkTag::TEST, "StartAbility_0100 end");
}

/**
 * @tc.number: TerminateSelf_0100
 * @tc.name: UIServiceExtension TerminateSelf
 * @tc.desc: UIServiceExtension TerminateSelf.
 */
HWTEST_F(UIServiceExtensionTest, TerminateSelf_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "TerminateSelf_0100 start");

    UIServiceExtensionContext uiServiceExtensionContext;
    auto result = uiServiceExtensionContext.TerminateSelf();
    EXPECT_EQ(result, ERR_OK);

    TAG_LOGI(AAFwkTag::TEST, "TerminateSelf_0100 end");
}

/**
 * @tc.number: GetWindow_0100
 * @tc.name: UIServiceExtension GetWindow
 * @tc.desc: UIServiceExtension GetWindow.
 */
HWTEST_F(UIServiceExtensionTest, GetWindow_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetWindow_0100 start");

    UIServiceExtensionContext uiServiceExtensionContext;
    auto result = uiServiceExtensionContext.GetWindow();
    EXPECT_TRUE(result == nullptr);

    TAG_LOGI(AAFwkTag::TEST, "GetWindow_0100 end");
}

/**
 * @tc.number: GetUIContent_0100
 * @tc.name: UIServiceExtension GetUIContent
 * @tc.desc: UIServiceExtension GetUIContent.
 */
HWTEST_F(UIServiceExtensionTest, GetUIContent_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIContent_0100 start");

    UIServiceExtensionContext uiServiceExtensionContext;
    uiServiceExtensionContext.SetWindow(nullptr);
    auto result = uiServiceExtensionContext.GetUIContent();
    EXPECT_EQ(result, nullptr);

    sptr<Rosen::Window> window = new Rosen::Window();
    uiServiceExtensionContext.SetWindow(window);
    uiServiceExtensionContext.GetUIContent();

    TAG_LOGI(AAFwkTag::TEST, "GetUIContent_0100 end");
}

/**
 * @tc.number: StartAbilityByType_0100
 * @tc.name: UIServiceExtension StartAbilityByType
 * @tc.desc: UIServiceExtension StartAbilityByType.
 */
HWTEST_F(UIServiceExtensionTest, StartAbilityByType_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "StartAbilityByType_0100 start");

    std::string type;
    AAFwk::WantParams wantParam;
    std::shared_ptr<JsUIExtensionCallback> uiExtensionCallbacks{nullptr};

    UIServiceExtensionContext uiServiceExtensionContext;
    auto result = uiServiceExtensionContext.StartAbilityByType(type, wantParam, uiExtensionCallbacks);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "StartAbilityByType_0100 end");
}

/**
 * @tc.number: StartAbilityByType_0200
 * @tc.name: UIServiceExtension StartAbilityByType
 * @tc.desc: UIServiceExtension StartAbilityByType.
 */
HWTEST_F(UIServiceExtensionTest, StartAbilityByType_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "StartAbilityByType_0200 start");

    std::string type;
    AAFwk::WantParams wantParam;
    napi_env env;
    std::shared_ptr<JsUIExtensionCallback> uiExtensionCallbacks = std::make_shared<JsUIExtensionCallback>(env);

    UIServiceExtensionContext uiServiceExtensionContext;
    uiServiceExtensionContext.SetWindow(nullptr);
    auto result = uiServiceExtensionContext.StartAbilityByType(type, wantParam, uiExtensionCallbacks);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "StartAbilityByType_0200 end");
}

/**
 * @tc.number: StartAbilityByType_0300
 * @tc.name: UIServiceExtension StartAbilityByType
 * @tc.desc: UIServiceExtension StartAbilityByType.
 */
HWTEST_F(UIServiceExtensionTest, StartAbilityByType_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "StartAbilityByType_0300 start");

    std::string type;
    AAFwk::WantParams wantParam;
    napi_env env;
    std::shared_ptr<JsUIExtensionCallback> uiExtensionCallbacks = std::make_shared<JsUIExtensionCallback>(env);
    sptr<Rosen::Window> window = new MockWindow();

    UIServiceExtensionContext uiServiceExtensionContext;
    uiServiceExtensionContext.SetWindow(window);
    auto result = uiServiceExtensionContext.StartAbilityByType(type, wantParam, uiExtensionCallbacks);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "StartAbilityByType_0300 end");
}

/**
 * @tc.number: StartAbilityByType_0400
 * @tc.name: UIServiceExtension StartAbilityByType
 * @tc.desc: UIServiceExtension StartAbilityByType.
 */
HWTEST_F(UIServiceExtensionTest, StartAbilityByType_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "StartAbilityByType_0400 start");

    std::string type;
    AAFwk::WantParams wantParam;
    const std::string FLAG_AUTH_READ_URI_PERMISSION = "ability.want.params.uriPermissionFlag";
    wantParam.SetParam(FLAG_AUTH_READ_URI_PERMISSION, 0);
    napi_env env;
    std::shared_ptr<JsUIExtensionCallback> uiExtensionCallbacks = std::make_shared<JsUIExtensionCallback>(env);
    sptr<Rosen::Window> window = new MockWindow();

    UIServiceExtensionContext uiServiceExtensionContext;
    uiServiceExtensionContext.SetWindow(window);
    auto result = uiServiceExtensionContext.StartAbilityByType(type, wantParam, uiExtensionCallbacks);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "StartAbilityByType_0400 end");
}

/**
 * @tc.number: GetWindowOption_0100
 * @tc.name: UIServiceExtension GetWindowOption
 * @tc.desc: UIServiceExtension GetWindowOption.
 */
HWTEST_F(UIServiceExtensionTest, GetWindowOption_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetWindowOption_0100 start");

    std::shared_ptr<Rosen::ExtensionWindowConfig> extensionWindowConfig
        = std::make_shared<Rosen::ExtensionWindowConfig>();
    extensionWindowConfig->windowAttribute = Rosen::ExtensionWindowAttribute::SUB_WINDOW;
    extensionWindowConfig->subWindowOptions.isModal = true;
    extensionWindowConfig->subWindowOptions.isTopmost = true;
    int32_t hostWindowId{1};

    Runtime::Options options;
    auto runtime = Runtime::Create(options);
    auto uIServiceExtensionPtr = UIServiceExtension::Create(runtime);
    auto result = uIServiceExtensionPtr->GetWindowOption(extensionWindowConfig, hostWindowId);
    EXPECT_NE(result, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "GetWindowOption_0100 end");
}

/**
 * @tc.number: GetWindowOption_0200
 * @tc.name: UIServiceExtension GetWindowOption
 * @tc.desc: UIServiceExtension GetWindowOption.
 */
HWTEST_F(UIServiceExtensionTest, GetWindowOption_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetWindowOption_0200 start");

    std::shared_ptr<Rosen::ExtensionWindowConfig> extensionWindowConfig
        = std::make_shared<Rosen::ExtensionWindowConfig>();
    extensionWindowConfig->windowAttribute = Rosen::ExtensionWindowAttribute::SUB_WINDOW;
    extensionWindowConfig->subWindowOptions.isModal = false;
    extensionWindowConfig->subWindowOptions.isTopmost = true;
    int32_t hostWindowId{100};

    Runtime::Options options;
    auto runtime = Runtime::Create(options);
    auto uIServiceExtensionPtr = UIServiceExtension::Create(runtime);
    auto result = uIServiceExtensionPtr->GetWindowOption(extensionWindowConfig, hostWindowId);
    EXPECT_NE(result, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "GetWindowOption_0200 end");
}

/**
 * @tc.number: GetWindowOption_0300
 * @tc.name: UIServiceExtension GetWindowOption
 * @tc.desc: UIServiceExtension GetWindowOption.
 */
HWTEST_F(UIServiceExtensionTest, GetWindowOption_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetWindowOption_0300 start");

    std::shared_ptr<Rosen::ExtensionWindowConfig> extensionWindowConfig
        = std::make_shared<Rosen::ExtensionWindowConfig>();
    extensionWindowConfig->windowAttribute = Rosen::ExtensionWindowAttribute::SUB_WINDOW;
    extensionWindowConfig->subWindowOptions.isModal = true;
    extensionWindowConfig->subWindowOptions.isTopmost = false;
    int32_t hostWindowId{100};

    Runtime::Options options;
    auto runtime = Runtime::Create(options);
    auto uIServiceExtensionPtr = UIServiceExtension::Create(runtime);
    auto result = uIServiceExtensionPtr->GetWindowOption(extensionWindowConfig, hostWindowId);
    EXPECT_NE(result, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "GetWindowOption_0300 end");
}

/**
 * @tc.number: GetWindowOption_0400
 * @tc.name: UIServiceExtension GetWindowOption
 * @tc.desc: UIServiceExtension GetWindowOption.
 */
HWTEST_F(UIServiceExtensionTest, GetWindowOption_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetWindowOption_0400 start");

    std::shared_ptr<Rosen::ExtensionWindowConfig> extensionWindowConfig
        = std::make_shared<Rosen::ExtensionWindowConfig>();
    extensionWindowConfig->windowAttribute = Rosen::ExtensionWindowAttribute::SYSTEM_WINDOW;
    int32_t hostWindowId{0};

    Runtime::Options options;
    auto runtime = Runtime::Create(options);
    auto uIServiceExtensionPtr = UIServiceExtension::Create(runtime);
    auto result = uIServiceExtensionPtr->GetWindowOption(extensionWindowConfig, hostWindowId);
    EXPECT_EQ(result, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "GetWindowOption_0400 end");
}

/**
 * @tc.number: SetWindow_0100
 * @tc.name: UIServiceExtension SetWindow
 * @tc.desc: UIServiceExtension SetWindow.
 */
HWTEST_F(UIServiceExtensionTest, SetWindow_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetWindow_0100 start");

    sptr<Rosen::Window> window = new Rosen::Window();

    UIServiceExtensionContext uiServiceExtensionContext;
    uiServiceExtensionContext.SetWindow(window);
    EXPECT_TRUE(window != nullptr);

    TAG_LOGI(AAFwkTag::TEST, "SetWindow_0100 end");
}


} // namespace AbilityRuntime
} // namespace OHOS
