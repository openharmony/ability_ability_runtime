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

#define private public
#define protected public
#include "ability_manager_errors.h"
#include "auto_fill_extension_context.h"
#undef private
#undef protected
#include "hilog_tag_wrapper.h"
#include "js_auto_fill_extension_util.h"
#include "mock_window.h"

using namespace testing::ext;
using namespace OHOS::Rosen;

namespace OHOS {
namespace AbilityRuntime {
class AutoFillExtensionContextTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

class MockIAutoFillExtensionCallback : public IAutoFillExtensionCallback {
public:
    MockIAutoFillExtensionCallback()
    {}
    virtual ~MockIAutoFillExtensionCallback()
    {}
    int32_t OnReloadInModal(const sptr<AAFwk::SessionInfo> &sessionInfo, const CustomData &customData) override
    {
        return 0;
    }
};

void AutoFillExtensionContextTest::SetUpTestCase(void)
{}

void AutoFillExtensionContextTest::TearDownTestCase(void)
{}

void AutoFillExtensionContextTest::SetUp()
{}

void AutoFillExtensionContextTest::TearDown()
{}

class AutoFillMockWindow : public MockWindow {
public:
    AutoFillMockWindow() = default;
    ~AutoFillMockWindow() = default;

    virtual Ace::UIContent* GetUIContent() const override
    {
        return (Ace::UIContent*)0x12345678;
    }
};

/**
 * @tc.number: GetWidow_0100
 * @tc.name: GetWidow
 * @tc.desc: GetWidow.
 */
HWTEST_F(AutoFillExtensionContextTest, GetWidow_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetWidow_0100 start");

    auto context = std::make_shared<AutoFillExtensionContext>();
    sptr<AutoFillMockWindow> window(new (std::nothrow) AutoFillMockWindow());
    context->SetWindow(window);
    EXPECT_TRUE(context->GetWindow() != nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetWidow_0100 end");
}

/**
 * @tc.number: GetUIContent_0100
 * @tc.name: GetUIContent
 * @tc.desc: GetUIContent.
 */
HWTEST_F(AutoFillExtensionContextTest, GetUIContent_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIContent_0100 start");

    auto context = std::make_shared<AutoFillExtensionContext>();
    sptr<AutoFillMockWindow> window(new (std::nothrow) AutoFillMockWindow());
    context->SetWindow(window);
    Ace::UIContent* content = context->GetUIContent();
    EXPECT_TRUE(content == (Ace::UIContent*)0x12345678);
    TAG_LOGI(AAFwkTag::TEST, "GetUIContent_0100 end");
}

/**
 * @tc.number: IsContext_0100
 * @tc.name: IsContext
 * @tc.desc: IsContext.
 */
HWTEST_F(AutoFillExtensionContextTest, IsContext_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsContext_0100 start");
    auto context = std::make_shared<AutoFillExtensionContext>();
    auto ret = context->IsContext(AutoFillExtensionContext::CONTEXT_TYPE_ID);
    EXPECT_TRUE(ret);
    ret = context->IsContext(UIExtensionContext::CONTEXT_TYPE_ID);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "IsContext_0100 end");
}

/**
 * @tc.number: ConvertTo_0100
 * @tc.name: ConvertTo
 * @tc.desc: ConvertTo.
 */
HWTEST_F(AutoFillExtensionContextTest, ConvertTo_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ConvertTo_0100 start");
    std::shared_ptr<Context> context = std::make_shared<AutoFillExtensionContext>();
    auto uiHolderExtensionContext = Context::ConvertTo<UIHolderExtensionContext>(context);
    EXPECT_NE(uiHolderExtensionContext, nullptr);
    auto uiExtensionContext = Context::ConvertTo<UIExtensionContext>(context);
    EXPECT_NE(uiExtensionContext, nullptr);
    auto autoFillExtensionContext = Context::ConvertTo<AutoFillExtensionContext>(context);
    EXPECT_NE(autoFillExtensionContext, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "ConvertTo_0100 end");
}

/**
 * @tc.number: ConvertTo_0200
 * @tc.name: ConvertTo
 * @tc.desc: ConvertTo.
 */
HWTEST_F(AutoFillExtensionContextTest, ConvertTo_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ConvertTo_0200 start");
    std::shared_ptr<Context> context = std::make_shared<UIExtensionContext>();
    auto autoFillExtensionContext = Context::ConvertTo<AutoFillExtensionContext>(context);
    EXPECT_EQ(autoFillExtensionContext, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "ConvertTo_0200 end");
}

/**
 * @tc.number: SetAutoFillExtensionCallback_0100
 * @tc.name: SetAutoFillExtensionCallback
 * @tc.desc: SetAutoFillExtensionCallback.
 */
HWTEST_F(AutoFillExtensionContextTest, SetAutoFillExtensionCallback_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetAutoFillExtensionCallback_0100 start");
    std::shared_ptr<AutoFillExtensionContext> context = std::make_shared<AutoFillExtensionContext>();
    ASSERT_NE(context, nullptr);
    auto autoFillExtension = std::make_shared<MockIAutoFillExtensionCallback>();
    context->SetAutoFillExtensionCallback(autoFillExtension);
    ASSERT_NE(context->autoFillExtensionCallback_.lock(), nullptr);
    TAG_LOGI(AAFwkTag::TEST, "SetAutoFillExtensionCallback_0100 end");
}

/**
 * @tc.number: SetSessionInfo_0100
 * @tc.name: SetSessionInfo
 * @tc.desc: SetSessionInfo.
 */
HWTEST_F(AutoFillExtensionContextTest, SetSessionInfo_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SetSessionInfo_0100 start");
    sptr<AAFwk::SessionInfo> sessionInfo = new (std::nothrow) AAFwk::SessionInfo();
    ASSERT_NE(sessionInfo, nullptr);
    std::shared_ptr<AutoFillExtensionContext> context = std::make_shared<AutoFillExtensionContext>();
    ASSERT_NE(context, nullptr);
    context->SetSessionInfo(sessionInfo);
    ASSERT_NE(context->sessionInfo_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "SetSessionInfo_0100 end");
}

/**
 * @tc.number: ReloadInModal_0100
 * @tc.name: ReloadInModal
 * @tc.desc: ReloadInModal.
 */
HWTEST_F(AutoFillExtensionContextTest, ReloadInModal_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ReloadInModal_0100 start");
    sptr<AAFwk::SessionInfo> sessionInfo = new (std::nothrow) AAFwk::SessionInfo();
    ASSERT_NE(sessionInfo, nullptr);
    std::shared_ptr<AutoFillExtensionContext> context = std::make_shared<AutoFillExtensionContext>();
    ASSERT_NE(context, nullptr);
    context->SetSessionInfo(sessionInfo);
    ASSERT_NE(context->sessionInfo_, nullptr);

    auto autoFillExtension = std::make_shared<MockIAutoFillExtensionCallback>();
    context->SetAutoFillExtensionCallback(autoFillExtension);
    ASSERT_NE(context->autoFillExtensionCallback_.lock(), nullptr);

    struct OHOS::AbilityRuntime::CustomData data;
    auto ret = context->ReloadInModal(data);
    EXPECT_EQ(ret, 0);
    TAG_LOGI(AAFwkTag::TEST, "ReloadInModal_0100 end");
}

/**
 * @tc.number: ConnectUIServiceExtensionAbility_0100
 * @tc.name: ConnectUIServiceExtensionAbility
 * @tc.desc: ConnectUIServiceExtensionAbility.
 */
HWTEST_F(AutoFillExtensionContextTest, ConnectUIServiceExtensionAbility_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ConnectUIServiceExtensionAbility_0100 start");

    std::shared_ptr<AutoFillExtensionContext> context = std::make_shared<AutoFillExtensionContext>();
    ASSERT_NE(context, nullptr);
    AAFwk::Want want;
    sptr<AbilityConnectCallback> connectCallback = nullptr;
    EXPECT_EQ(context->ConnectUIServiceExtensionAbility(want, connectCallback), AAFwk::ERR_INVALID_CALLER);

    TAG_LOGI(AAFwkTag::TEST, "ConnectUIServiceExtensionAbility_0100 end");
}
} // namespace AbilityRuntime
} // namespace OHOS
