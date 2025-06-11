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
#include <gmock/gmock.h>

#define private public
#define protected public
#include "js_startup_config.h"
#include "js_environment.h"
#include "startup_task_result.h"
#undef private
#undef protected
#include "want_params.h"
#include "string_wrapper.h"
#include "napi_common_execute_result.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "native_reference.h"
#include "js_runtime.h"
#include "mock_my_flag.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
napi_value NapiTestFunc(napi_env env, napi_callback_info info)
{
    return nullptr;
}
namespace {
constexpr int32_t ERR_OK = 0;
constexpr int32_t DEFAULT_AWAIT_TIMEOUT_MS = 10000;
const std::string DEFAULT_CUSTOMIZATION = "default";
const std::string INTERNAL_ERROR = "internal error.";
const std::string RESULT_MESSAGE = "result message.";
const int32_t TEST_VALUE = 123;
}
class JsStartupConfigTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

static std::shared_ptr<JsRuntime> jsRuntime_ = nullptr;
class NativeReferenceMock : public NativeReference {
public:
    static std::string propertyName_;
    NativeReferenceMock() = default;
    virtual ~NativeReferenceMock() = default;
    MOCK_METHOD0(Ref, uint32_t());
    MOCK_METHOD0(Unref, uint32_t());
    MOCK_METHOD0(Get, napi_value());
    MOCK_METHOD0(GetData, void*());
    virtual operator napi_value() override
    {
        return reinterpret_cast<napi_value>(this);
    }
    MOCK_METHOD0(SetDeleteSelf, void());
    MOCK_METHOD0(GetRefCount, uint32_t());
    MOCK_METHOD0(GetFinalRun, bool());
    napi_value GetNapiValue() override
    {
        if (MyFlag::isGetNapiValueNullptr_) {
            return nullptr;
        }
        MyFlag::isGetNapiEnvNullptr_ = false;
        napi_env env = jsRuntime_->GetNapiEnv();
        napi_value object = AppExecFwk::CreateJSObject(env);

        napi_value value;
        napi_create_int32(env, TEST_VALUE, &value);
        napi_set_named_property(env, object, propertyName_.c_str(), value);
        return object;
        return nullptr;
    }
};
std::string NativeReferenceMock::propertyName_ = "";

void JsStartupConfigTest::SetUpTestCase(void)
{
    jsRuntime_ = std::make_shared<JsRuntime>();
}

void JsStartupConfigTest::TearDownTestCase(void)
{}

void JsStartupConfigTest::SetUp()
{}

void JsStartupConfigTest::TearDown()
{}

/*
* Feature: JsInsightIntentEntry
* Function: Init
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryInit_001, TestSize.Level1)
{
    auto jsStartupConfig = std::make_shared<JsStartupConfig>(nullptr);
    MyFlag::isGetNapiValueNullptr_ = true;
    auto want = std::make_shared<Want>();
    std::unique_ptr<NativeReference> ptr = nullptr;
    auto res = jsStartupConfig->Init(ptr, want);
    EXPECT_EQ(res, ERR_STARTUP_INTERNAL_ERROR);
}

/*
* Feature: JsInsightIntentEntry
* Function: Init
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryInit_002, TestSize.Level1)
{
    auto jsRuntime = std::make_shared<JsRuntime>();
    MyFlag::isGetNapiValueNullptr_ = true;
    auto jsStartupConfig = std::make_shared<JsStartupConfig>(nullptr);
    auto want = std::make_shared<Want>();
    std::unique_ptr<NativeReference> ptr = std::make_unique<NativeReferenceMock>();
    auto res = jsStartupConfig->Init(ptr, want);
    EXPECT_EQ(res, ERR_STARTUP_INTERNAL_ERROR);
}

/*
* Feature: JsInsightIntentEntry
* Function: Init
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryInit_003, TestSize.Level1)
{
    MyFlag::isGetNapiEnvNullptr_ = false;
    MyFlag::isGetNapiValueNullptr_ = false;
    panda::RuntimeOption pandaOption;
    jsRuntime_->jsEnv_->Initialize(pandaOption, static_cast<void*>(this));
    auto jsStartupConfig = std::make_shared<JsStartupConfig>(jsRuntime_->GetNapiEnv());
    auto want = std::make_shared<Want>();
    std::unique_ptr<NativeReference> ptr = std::make_unique<NativeReferenceMock>();
    NativeReferenceMock::propertyName_ = "onConfig";
    auto res = jsStartupConfig->Init(ptr, want);
    EXPECT_EQ(res, ERR_STARTUP_INTERNAL_ERROR);
}

/*
* Feature: JsInsightIntentEntry
* Function: Init
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryInit_004, TestSize.Level1)
{
    auto jsRuntime = std::make_shared<JsRuntime>();
    MyFlag::isGetNapiValueNullptr_ = true;
    MyFlag::isGetNapiEnvNullptr_ = false;
    panda::RuntimeOption pandaOption;
    jsRuntime = std::make_shared<JsRuntime>();
    jsRuntime->jsEnv_->Initialize(pandaOption, static_cast<void*>(this));
    auto jsStartupConfig = std::make_shared<JsStartupConfig>(jsRuntime->GetNapiEnv());
    napi_value object = AppExecFwk::CreateJSObject(jsRuntime->GetNapiEnv());
    auto res = jsStartupConfig->Init(object);
    EXPECT_EQ(res, ERR_OK);
}

/*
* Feature: JsInsightIntentEntry
* Function: InitAwaitTimeout
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryInitAwaitTimeout_001, TestSize.Level1)
{
    auto jsRuntime = std::make_shared<JsRuntime>();
    MyFlag::isGetNapiEnvNullptr_ = false;
    panda::RuntimeOption pandaOption;
    jsRuntime = std::make_shared<JsRuntime>();
    jsRuntime->jsEnv_->Initialize(pandaOption, static_cast<void*>(this));

    auto jsStartupConfig = std::make_shared<JsStartupConfig>(nullptr);
    jsStartupConfig->awaitTimeoutMs_ = DEFAULT_AWAIT_TIMEOUT_MS - 1;
    napi_value object = AppExecFwk::CreateJSObject(jsRuntime->GetNapiEnv());
    jsStartupConfig->InitAwaitTimeout(jsRuntime->GetNapiEnv(), object);
    EXPECT_EQ(jsStartupConfig->awaitTimeoutMs_, DEFAULT_AWAIT_TIMEOUT_MS - 1);
}

/*
* Feature: JsInsightIntentEntry
* Function: InitAwaitTimeout
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryInitAwaitTimeout_002, TestSize.Level1)
{
    auto jsRuntime = std::make_shared<JsRuntime>();
    MyFlag::isGetNapiEnvNullptr_ = false;
    panda::RuntimeOption pandaOption;
    jsRuntime = std::make_shared<JsRuntime>();
    jsRuntime->jsEnv_->Initialize(pandaOption, static_cast<void*>(this));

    auto jsStartupConfig = std::make_shared<JsStartupConfig>(nullptr);
    jsStartupConfig->awaitTimeoutMs_ = 0;
    napi_value object = AppExecFwk::CreateJSObject(jsRuntime->GetNapiEnv());
    napi_value value;
    napi_create_int32(jsRuntime->GetNapiEnv(), -1, &value);
    napi_set_named_property(jsRuntime->GetNapiEnv(), object, "timeoutMs", value);

    jsStartupConfig->InitAwaitTimeout(jsRuntime->GetNapiEnv(), object);
    EXPECT_EQ(jsStartupConfig->awaitTimeoutMs_, DEFAULT_AWAIT_TIMEOUT_MS);
}

/*
* Feature: JsInsightIntentEntry
* Function: InitListener
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryInitListener_001, TestSize.Level1)
{
    auto jsRuntime = std::make_shared<JsRuntime>();
    MyFlag::isGetNapiEnvNullptr_ = false;
    panda::RuntimeOption pandaOption;
    jsRuntime = std::make_shared<JsRuntime>();
    jsRuntime->jsEnv_->Initialize(pandaOption, static_cast<void*>(this));

    auto jsStartupConfig = std::make_shared<JsStartupConfig>(nullptr);
    jsStartupConfig->listener_ = nullptr;

    jsStartupConfig->InitListener(jsRuntime->GetNapiEnv(), nullptr);
    EXPECT_EQ(jsStartupConfig->listener_, nullptr);
}

/*
* Feature: JsInsightIntentEntry
* Function: InitListener
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryInitListener_002, TestSize.Level1)
{
    auto jsRuntime = std::make_shared<JsRuntime>();
    MyFlag::isGetNapiEnvNullptr_ = false;
    panda::RuntimeOption pandaOption;
    jsRuntime = std::make_shared<JsRuntime>();
    jsRuntime->jsEnv_->Initialize(pandaOption, static_cast<void*>(this));

    auto jsStartupConfig = std::make_shared<JsStartupConfig>(nullptr);
    jsStartupConfig->listener_ = nullptr;
    napi_value object = AppExecFwk::CreateJSObject(jsRuntime->GetNapiEnv());
    napi_value value;
    napi_create_int32(jsRuntime->GetNapiEnv(), 0, &value);
    napi_set_named_property(jsRuntime->GetNapiEnv(), object, "startupListener", value);

    jsStartupConfig->InitListener(jsRuntime->GetNapiEnv(), object);
    EXPECT_EQ(jsStartupConfig->listener_, nullptr);
}

/*
* Feature: JsInsightIntentEntry
* Function: InitListener
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryInitListener_003, TestSize.Level1)
{
    auto jsRuntime = std::make_shared<JsRuntime>();
    MyFlag::isGetNapiEnvNullptr_ = false;
    panda::RuntimeOption pandaOption;
    jsRuntime = std::make_shared<JsRuntime>();
    jsRuntime->jsEnv_->Initialize(pandaOption, static_cast<void*>(this));

    auto jsStartupConfig = std::make_shared<JsStartupConfig>(nullptr);
    jsStartupConfig->listener_ = nullptr;
    napi_value object = AppExecFwk::CreateJSObject(jsRuntime->GetNapiEnv());
    napi_value listener = AppExecFwk::CreateJSObject(jsRuntime->GetNapiEnv());
    napi_value value;
    napi_create_int32(jsRuntime->GetNapiEnv(), 0, &value);
    napi_set_named_property(jsRuntime->GetNapiEnv(), listener, "onCompleted", value);
    napi_set_named_property(jsRuntime->GetNapiEnv(), object, "startupListener", listener);

    jsStartupConfig->InitListener(jsRuntime->GetNapiEnv(), object);
    EXPECT_NE(jsStartupConfig->listener_, nullptr);
}

/*
* Feature: JsInsightIntentEntry
* Function: InitCustomization
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryInitCustomization_001, TestSize.Level1)
{
    auto jsRuntime = std::make_shared<JsRuntime>();
    MyFlag::isGetNapiEnvNullptr_ = false;
    panda::RuntimeOption pandaOption;
    jsRuntime = std::make_shared<JsRuntime>();
    jsRuntime->jsEnv_->Initialize(pandaOption, static_cast<void*>(this));

    auto jsStartupConfig = std::make_shared<JsStartupConfig>(nullptr);
    jsStartupConfig->customization_ = DEFAULT_CUSTOMIZATION;
    
    jsStartupConfig->InitCustomization(jsRuntime->GetNapiEnv(), nullptr, nullptr);
    EXPECT_EQ(jsStartupConfig->customization_, DEFAULT_CUSTOMIZATION);
}

/*
* Feature: JsInsightIntentEntry
* Function: InitCustomization
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryInitCustomization_002, TestSize.Level1)
{
    auto jsRuntime = std::make_shared<JsRuntime>();
    MyFlag::isGetNapiEnvNullptr_ = false;
    panda::RuntimeOption pandaOption;
    jsRuntime = std::make_shared<JsRuntime>();
    jsRuntime->jsEnv_->Initialize(pandaOption, static_cast<void*>(this));

    auto jsStartupConfig = std::make_shared<JsStartupConfig>(nullptr);
    jsStartupConfig->customization_ = DEFAULT_CUSTOMIZATION;
    napi_value configEntry = AppExecFwk::CreateJSObject(jsRuntime->GetNapiEnv());
    auto want = std::make_shared<Want>();
    
    jsStartupConfig->InitCustomization(jsRuntime->GetNapiEnv(), configEntry, want);
    EXPECT_EQ(jsStartupConfig->customization_, DEFAULT_CUSTOMIZATION);
}

/*
* Feature: JsInsightIntentEntry
* Function: InitCustomization
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryInitCustomization_003, TestSize.Level1)
{
    auto jsRuntime = std::make_shared<JsRuntime>();
    MyFlag::isGetNapiEnvNullptr_ = false;
    panda::RuntimeOption pandaOption;
    jsRuntime = std::make_shared<JsRuntime>();
    jsRuntime->jsEnv_->Initialize(pandaOption, static_cast<void*>(this));

    auto jsStartupConfig = std::make_shared<JsStartupConfig>(nullptr);
    jsStartupConfig->customization_ = DEFAULT_CUSTOMIZATION;
    
    napi_value configEntry = AppExecFwk::CreateJSObject(jsRuntime->GetNapiEnv());
    napi_value value;
    napi_create_int32(jsRuntime->GetNapiEnv(), 0, &value);
    napi_set_named_property(jsRuntime->GetNapiEnv(), configEntry, "onRequestCustomMatchRule", value);

    auto want = std::make_shared<Want>();
    
    jsStartupConfig->InitCustomization(jsRuntime->GetNapiEnv(), configEntry, want);
    EXPECT_EQ(jsStartupConfig->customization_, DEFAULT_CUSTOMIZATION);
}

/*
* Feature: JsInsightIntentEntry
* Function: InitCustomization
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryInitCustomization_004, TestSize.Level1)
{
    auto jsRuntime = std::make_shared<JsRuntime>();
    MyFlag::isGetNapiEnvNullptr_ = false;
    panda::RuntimeOption pandaOption;
    jsRuntime = std::make_shared<JsRuntime>();
    jsRuntime->jsEnv_->Initialize(pandaOption, static_cast<void*>(this));

    auto jsStartupConfig = std::make_shared<JsStartupConfig>(nullptr);
    jsStartupConfig->customization_ = DEFAULT_CUSTOMIZATION;
    
    napi_value configEntry = AppExecFwk::CreateJSObject(jsRuntime->GetNapiEnv());
    napi_value fn;
    napi_create_function(jsRuntime->GetNapiEnv(), "test", 0, NapiTestFunc, NULL, &fn);
    napi_set_named_property(jsRuntime->GetNapiEnv(), configEntry, "onRequestCustomMatchRule", fn);
    auto want = std::make_shared<Want>();
    
    jsStartupConfig->InitCustomization(jsRuntime->GetNapiEnv(), configEntry, want);
    EXPECT_NE(jsStartupConfig->customization_, DEFAULT_CUSTOMIZATION);
}

/*
* Feature: JsInsightIntentEntry
* Function: BuildResult
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryBuildResult_001, TestSize.Level1)
{
    auto jsRuntime = std::make_shared<JsRuntime>();
    MyFlag::isGetNapiEnvNullptr_ = false;
    panda::RuntimeOption pandaOption;
    jsRuntime = std::make_shared<JsRuntime>();
    jsRuntime->jsEnv_->Initialize(pandaOption, static_cast<void*>(this));

    auto jsStartupConfig = std::make_shared<JsStartupConfig>(nullptr);
    auto res = jsStartupConfig->BuildResult(jsRuntime->GetNapiEnv(), nullptr);

    napi_value messageProp;
    napi_get_named_property(jsRuntime->GetNapiEnv(), res, "message", &messageProp);
    char errorMessage[1024];
    memset_s(errorMessage, sizeof(errorMessage), 0, sizeof(errorMessage));
    size_t copied;
    auto status = napi_get_value_string_utf8(jsRuntime->GetNapiEnv(), messageProp, errorMessage,
        sizeof(errorMessage), &copied);
    EXPECT_EQ(status, napi_ok);
    std::string errStr(errorMessage);
    EXPECT_EQ(copied, INTERNAL_ERROR.size());
    EXPECT_EQ(errStr, INTERNAL_ERROR);
}

/*
* Feature: JsInsightIntentEntry
* Function: BuildResult
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryBuildResult_002, TestSize.Level1)
{
    auto jsRuntime = std::make_shared<JsRuntime>();
    MyFlag::isGetNapiEnvNullptr_ = false;
    panda::RuntimeOption pandaOption;
    jsRuntime = std::make_shared<JsRuntime>();
    jsRuntime->jsEnv_->Initialize(pandaOption, static_cast<void*>(this));

    auto jsStartupConfig = std::make_shared<JsStartupConfig>(nullptr);
    auto startupTaskResult = std::make_shared<StartupTaskResult>();
    startupTaskResult->resultCode_ = -1;
    startupTaskResult->resultMessage_ = RESULT_MESSAGE;
    auto res = jsStartupConfig->BuildResult(jsRuntime->GetNapiEnv(), startupTaskResult);

    napi_value messageProp;
    napi_get_named_property(jsRuntime->GetNapiEnv(), res, "message", &messageProp);
    char errorMessage[1024];
    memset_s(errorMessage, sizeof(errorMessage), 0, sizeof(errorMessage));
    size_t copied;
    auto status = napi_get_value_string_utf8(jsRuntime->GetNapiEnv(), messageProp, errorMessage,
        sizeof(errorMessage), &copied);
    EXPECT_EQ(status, napi_ok);
    std::string errStr(errorMessage);
    EXPECT_EQ(copied, RESULT_MESSAGE.size());
    EXPECT_EQ(errStr, RESULT_MESSAGE);
}

/*
* Feature: JsInsightIntentEntry
* Function: BuildResult
* SubFunction: NA
*/
HWTEST_F(JsStartupConfigTest, JsInsightIntentEntryBuildResult_003, TestSize.Level1)
{
    auto jsRuntime = std::make_shared<JsRuntime>();
    MyFlag::isGetNapiEnvNullptr_ = false;
    panda::RuntimeOption pandaOption;
    jsRuntime = std::make_shared<JsRuntime>();
    jsRuntime->jsEnv_->Initialize(pandaOption, static_cast<void*>(this));

    auto jsStartupConfig = std::make_shared<JsStartupConfig>(nullptr);
    auto startupTaskResult = std::make_shared<StartupTaskResult>();
    startupTaskResult->resultCode_ = ERR_OK;
    auto res = jsStartupConfig->BuildResult(jsRuntime->GetNapiEnv(), startupTaskResult);
    napi_value messageProp;
    EXPECT_NE(napi_get_named_property(jsRuntime->GetNapiEnv(), res, "message", &messageProp), napi_ok);
}
} // namespace AbilityRuntime
} // namespace OHOS
