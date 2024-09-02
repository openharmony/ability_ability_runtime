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
#include <gtest/hwext/gtest-multithread.h>
#define private public
#include "js_ui_service_extension_context.cpp"
#undef private
#include "ability_business_error.h"
#include "errors.h"
#include "hilog_wrapper.h"
#include "ability_record.h"
#include "mock_ability_token.h"
#include "runtime.h"
#include "hilog_tag_wrapper.h"
#include "native_engine/impl/ark/ark_native_engine.h"
#include "native_engine/native_engine.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AbilityRuntime {
namespace {
const int64_t  COMMECTION_ID = 100;
}  // namespace

class JsUiServiceExtensionContextSecondTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    napi_env env_ = nullptr;
    panda::ecmascript::EcmaVM* vm_ = nullptr;
};

void JsUiServiceExtensionContextSecondTest::SetUpTestCase()
{
}

void JsUiServiceExtensionContextSecondTest::TearDownTestCase()
{
}

void JsUiServiceExtensionContextSecondTest::SetUp()
{
    panda::RuntimeOption pandaOption;
    vm_ = panda::JSNApi::CreateJSVM(pandaOption);
    if (vm_ == nullptr) {
        TAG_LOGE(AAFwkTag::TEST, "Create vm failed.");
        return;
    }

    env_ = reinterpret_cast<napi_env>(new ArkNativeEngine(vm_, nullptr));
}

void JsUiServiceExtensionContextSecondTest::TearDown()
{
    if (env_ != nullptr) {
        delete reinterpret_cast<NativeEngine*>(env_);
        env_ = nullptr;
    }

    if (vm_ != nullptr) {
        panda::JSNApi::DestroyJSVM(vm_);
        vm_ = nullptr;
    }
}

/**
 * @tc.name: CheckConnectionParam_0100
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(JsUiServiceExtensionContextSecondTest, CheckConnectionParam_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckConnectionParam_0100 start");
    napi_value value{nullptr};
    std::shared_ptr<UIServiceExtensionContext> uiServiceExtensionContext =
        std::make_shared<UIServiceExtensionContext>();
    JSUIServiceExtensionContext jsUIServiceExtensionContext(uiServiceExtensionContext);
    sptr<JSUIServiceExtensionConnection> connection =  new JSUIServiceExtensionConnection(env_);
    Want want;
    int32_t accountId = 10;
    auto result = jsUIServiceExtensionContext.CheckConnectionParam(env_, value, connection, want, accountId);
    EXPECT_EQ(result, false);
    TAG_LOGI(AAFwkTag::TEST, "CheckConnectionParam_0100 end");
}

/**
 * @tc.name: CheckConnectionParam_0200
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(JsUiServiceExtensionContextSecondTest, CheckConnectionParam_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckConnectionParam_0200 start");
    napi_value value;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_create_string_utf8(env_, "Hello, Service Extension!",
        NAPI_AUTO_LENGTH, &value);
    EXPECT_EQ(status, napi_ok);
    status = napi_typeof(env_, value, &valueType);
    std::shared_ptr<UIServiceExtensionContext> uiServiceExtensionContext =
        std::make_shared<UIServiceExtensionContext>();
    JSUIServiceExtensionContext jsUIServiceExtensionContext(uiServiceExtensionContext);
    sptr<JSUIServiceExtensionConnection> connection =  new JSUIServiceExtensionConnection(env_);
    Want want;
    int32_t accountId = 10;
    auto result = jsUIServiceExtensionContext.CheckConnectionParam(env_, value, connection, want, accountId);
    EXPECT_EQ(result, false);
    TAG_LOGI(AAFwkTag::TEST, "CheckConnectionParam_0200 end");
}

/**
 * @tc.name: GetConnectAbilityExecFunc_0100
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(JsUiServiceExtensionContextSecondTest, GetConnectAbilityExecFunc_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetConnectAbilityExecFunc_0100 start");
    std::shared_ptr<UIServiceExtensionContext> uiServiceExtensionContext =
        std::make_shared<UIServiceExtensionContext>();
    JSUIServiceExtensionContext jsUIServiceExtensionContext(uiServiceExtensionContext);
    sptr<JSUIServiceExtensionConnection> connection =  new JSUIServiceExtensionConnection(env_);
    Want want;
    int64_t connectId = 10;
    std::shared_ptr<int> innerErrorCode = std::make_shared<int>(10);
    jsUIServiceExtensionContext.GetConnectAbilityExecFunc(want, connection, connectId, innerErrorCode);
    EXPECT_NE(innerErrorCode, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetConnectAbilityExecFunc_0100 end");
}

/**
 * @tc.name: FindConnection_0100
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(JsUiServiceExtensionContextSecondTest, FindConnection_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "FindConnection_0100 start");
    std::shared_ptr<UIServiceExtensionContext> uiServiceExtensionContext =
        std::make_shared<UIServiceExtensionContext>();
    JSUIServiceExtensionContext jsUIServiceExtensionContext(uiServiceExtensionContext);
    sptr<JSUIServiceExtensionConnection> connection =  new JSUIServiceExtensionConnection(env_);
    Want want;
    int64_t connectId = 10;
    int32_t accountId = 10;
    jsUIServiceExtensionContext.FindConnection(want, connection, connectId, accountId);
    EXPECT_NE(connection, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "FindConnection_0100 end");
}

/**
 * @tc.name: OnConnectServiceExtensionAbility_0100
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(JsUiServiceExtensionContextSecondTest, OnConnectServiceExtensionAbility_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnConnectServiceExtensionAbility_0100 start");
    NapiCallbackInfo info;
    std::shared_ptr<UIServiceExtensionContext> uiServiceExtensionContext =
        std::make_shared<UIServiceExtensionContext>();
    JSUIServiceExtensionContext jsUIServiceExtensionContext(uiServiceExtensionContext);
    auto result = jsUIServiceExtensionContext.OnConnectServiceExtensionAbility(env_, info);
    EXPECT_NE(info.argc, 0);
    TAG_LOGI(AAFwkTag::TEST, "OnConnectServiceExtensionAbility_0100 end");
}

/**
 * @tc.name: OnConnectServiceExtensionAbility_0200
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(JsUiServiceExtensionContextSecondTest, OnConnectServiceExtensionAbility_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnConnectServiceExtensionAbility_0200 start");
    NapiCallbackInfo info;
    napi_value value;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_create_string_utf8(env_, "Hello, Service Extension!",
        NAPI_AUTO_LENGTH, &value);
    EXPECT_EQ(status, napi_ok);
    status = napi_typeof(env_, value, &valueType);
    std::shared_ptr<UIServiceExtensionContext> uiServiceExtensionContext =
        std::make_shared<UIServiceExtensionContext>();
    JSUIServiceExtensionContext jsUIServiceExtensionContext(uiServiceExtensionContext);
    auto result = jsUIServiceExtensionContext.OnConnectServiceExtensionAbility(env_, info);
    EXPECT_NE(result, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "OnConnectServiceExtensionAbility_0200 end");
}

/**
 * @tc.name: OnDisConnectServiceExtensionAbility_0100
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(JsUiServiceExtensionContextSecondTest, OnDisConnectServiceExtensionAbility_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnDisConnectServiceExtensionAbility_0100 start");
    NapiCallbackInfo info;
    napi_value value;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_create_string_utf8(env_, "Hello, Service Extension!",
        NAPI_AUTO_LENGTH, &value);
    EXPECT_EQ(status, napi_ok);
    status = napi_typeof(env_, value, &valueType);
    std::shared_ptr<UIServiceExtensionContext> uiServiceExtensionContext =
        std::make_shared<UIServiceExtensionContext>();
    JSUIServiceExtensionContext jsUIServiceExtensionContext(uiServiceExtensionContext);
    auto result = jsUIServiceExtensionContext.OnDisConnectServiceExtensionAbility(env_, info);
    EXPECT_NE(result, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "OnDisConnectServiceExtensionAbility_0100 end");
}

/**
 * @tc.name: OnDisConnectServiceExtensionAbility_0200
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(JsUiServiceExtensionContextSecondTest, OnDisConnectServiceExtensionAbility_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnDisConnectServiceExtensionAbility_0200 start");
    NapiCallbackInfo info;
    std::shared_ptr<UIServiceExtensionContext> uiServiceExtensionContext =
        std::make_shared<UIServiceExtensionContext>();
    JSUIServiceExtensionContext jsUIServiceExtensionContext(uiServiceExtensionContext);
    auto result = jsUIServiceExtensionContext.OnDisConnectServiceExtensionAbility(env_, info);
    EXPECT_NE(result, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "OnDisConnectServiceExtensionAbility_0200 end");
}
}  // namespace AbilityRuntime
}  // namespace OHOS