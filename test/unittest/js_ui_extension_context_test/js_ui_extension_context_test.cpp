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
#include <singleton.h>
#include <uv.h>
#include "ability_context.h"
#include "ability_context_impl.h"
#include "ability_business_error.h"
#include "errors.h"
#include "hilog_wrapper.h"
#define private public
#define protected public
#include "js_ui_extension_context.h"
#undef private
#undef protected
#include "js_runtime_utils.h"
#include "native_engine/impl/ark/ark_native_engine.h"
#include "native_engine/impl/ark/ark_native_deferred.h"
#include "native_engine/native_engine.h"
#include "js_runtime_lite.h"
#include "napi_common_want.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AbilityRuntime {

constexpr size_t ARGC_ZERO = 0;
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;

const int USLEEPTIME = 100000;

napi_env env_ = nullptr;
panda::ecmascript::EcmaVM* vm_ = nullptr;

class MockDeferred : public NativeDeferred {
public:
    void Resolve(napi_value data) override
    {
        resolved_ = true;
        if (nref_ != nullptr) {
            napi_delete_reference(env_, nref_);
            nref_ = nullptr;
        }
        if (data != nullptr) {
            napi_create_reference(env_, data, 1, &nref_);
        }
    }

    void Reject(napi_value reason) override
    {
        resolved_ = false;
    }

public:
    static bool GetLastResolveStatus() { return resolved_; }
    static napi_ref GetLastResolveValue() { return nref_; }
    static void Clear()
    {
        if (nref_) {
            delete (reinterpret_cast<NativeReference*>(nref_));
            nref_ = nullptr;
        }
    }
    static bool resolved_;
    static napi_ref nref_;
};
bool MockDeferred::resolved_ = false;
napi_ref MockDeferred::nref_ = nullptr;

class MockArkNativeEngine : public ArkNativeEngine {
public:
    MockArkNativeEngine(EcmaVM* vm, void* jsEngine, bool isLimitedWorker = false)
        :ArkNativeEngine(vm, jsEngine, isLimitedWorker)
    {}

    napi_value CreatePromise(NativeDeferred** deferred) override
    {
        napi_value ret = ArkNativeEngine::CreatePromise(deferred);
        *deferred = new (std::nothrow) MockDeferred;
        return ret;
    }
};

class MockAbilityContextImpl : public UIExtensionContext {
public:
    virtual ErrCode ConnectUIServiceExtensionAbility(const AAFwk::Want &want,
        const sptr<AbilityConnectCallback> &connectCallback) const override
    {
        callback_ = connectCallback;
        return connectRet_;
    }
    virtual ErrCode DisconnectAbility(const AAFwk::Want &want,
        const sptr<AbilityConnectCallback> &connectCallback) const override
    {
        return ERR_OK;
    }
public:
    static void DoneConnect(int status)
    {
        GTEST_LOG_(INFO) << "DoneConnect " << status;
        AppExecFwk::ElementName element;
        sptr<IRemoteObject> remoteObject;
        callback_->OnAbilityConnectDone(element, remoteObject, 0);
    }
    static void DoneDisconnect(int status)
    {
        GTEST_LOG_(INFO) << "DoneDisconnect " << status;
        AppExecFwk::ElementName element;
        callback_->OnAbilityDisconnectDone(element, 0);
    }
    void SetConnectResult(ErrCode code) { connectRet_ = code; }
protected:
    static sptr<AbilityConnectCallback> callback_;
    ErrCode connectRet_ = ERR_OK;
};

sptr<AbilityConnectCallback> MockAbilityContextImpl::callback_;

class UIExtensionContextTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    void RunNowait(uv_loop_t* loop)
    {
        usleep(USLEEPTIME);
        uv_run(loop, UV_RUN_NOWAIT);
    }
    void Connect(napi_value* argv, int32_t argc);
    void Disconnect(napi_value* argv, int32_t argc);
public:
    std::shared_ptr<JsUIExtensionContext> jsUIExtensionContext_;
    std::shared_ptr<MockAbilityContextImpl> abilityContextImpl_;
};

void UIExtensionContextTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "SetUpTestCase";
    panda::RuntimeOption option;
    option.SetGcType(panda::RuntimeOption::GC_TYPE::GEN_GC);
    const int64_t poolSize = 0x1000000;
    option.SetGcPoolSize(poolSize);
    option.SetLogLevel(panda::RuntimeOption::LOG_LEVEL::ERROR);
    option.SetDebuggerLibraryPath("");
    vm_ = panda::JSNApi::CreateJSVM(option);
    if (vm_ == nullptr) {
        GTEST_LOG_(INFO) << "Create vm failed.";
        return;
    }
    env_ = reinterpret_cast<napi_env>(new (std::nothrow) MockArkNativeEngine(vm_, nullptr));
}

void UIExtensionContextTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "TearDownTestCase";
    MockArkNativeEngine* engine = reinterpret_cast<MockArkNativeEngine*>(env_);
    delete engine;
    engine = nullptr;
    if (vm_ != nullptr) {
        JSNApi::DestroyJSVM(vm_);
        vm_ = nullptr;
    }
}

void UIExtensionContextTest::SetUp()
{
    GTEST_LOG_(INFO) << "AbilityContextTest::SetUp";
    abilityContextImpl_ = std::make_shared<MockAbilityContextImpl>();
    if (abilityContextImpl_ == nullptr) {
        GTEST_LOG_(INFO) << "abilityContextImpl is nullptr.";
        return;
    }
    jsUIExtensionContext_ = std::make_shared<JsUIExtensionContext>(abilityContextImpl_);
}

void UIExtensionContextTest::TearDown()
{
    GTEST_LOG_(INFO) << "AbilityContextTest::TearDown " << (void*)this;
    MockDeferred::Clear();
    abilityContextImpl_.reset();
    jsUIExtensionContext_.reset();
}

void UIExtensionContextTest::Connect(napi_value* argv, int32_t argc)
{
    GTEST_LOG_(INFO) << "AbilityRuntime_AbilityContext_0100 start";
    auto func = [](napi_env env, napi_callback_info info) -> napi_value {
        JsUIExtensionContext::ConnectUIServiceExtension(env, info);
        napi_value result = nullptr;
        napi_get_undefined(env, &result);
        return result;
    };

    HandleScope handleScope(env_);
    napi_value recv = nullptr;
    napi_create_object(env_, &recv);
    napi_status wrapret = napi_wrap(env_, recv, jsUIExtensionContext_.get(),
        [](napi_env env, void* data, void* hint) {}, nullptr, nullptr);
    EXPECT_EQ(wrapret, napi_ok);

    napi_value funcValue = nullptr;
    napi_create_function(env_, "testFunc", NAPI_AUTO_LENGTH, func, nullptr, &funcValue);

    napi_value funcResultValue = nullptr;
    napi_call_function(env_, recv, funcValue, argc, argv, &funcResultValue);
}

void UIExtensionContextTest::Disconnect(napi_value* argv, int32_t argc)
{
    auto func = [](napi_env env, napi_callback_info info) -> napi_value {
        JsUIExtensionContext::DisconnectUIServiceExtension(env, info);
        napi_value result = nullptr;
        napi_get_undefined(env, &result);
        return result;
    };
    HandleScope handleScope(env_);
    napi_value recv = nullptr;
    napi_create_object(env_, &recv);
    napi_status wrapret = napi_wrap(env_, recv, jsUIExtensionContext_.get(),
        [](napi_env env, void* data, void* hint) {}, nullptr, nullptr);
    EXPECT_EQ(wrapret, napi_ok);

    napi_value funcResultValue = nullptr;
    napi_value funcValue = nullptr;
    napi_create_function(env_, "disconnectFunc", NAPI_AUTO_LENGTH, func, nullptr, &funcValue);
    napi_call_function(env_, recv, funcValue, argc, argv, &funcResultValue);
}

HWTEST_F(UIExtensionContextTest, AbilityRuntime_UIExtensionContext_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityRuntime_UIExtensionContext_0100 start";
    HandleScope handleScope(env_);
    TryCatch tryCatch(env_);
    napi_value argv[] = { };
    Connect(argv, ARGC_ZERO);

    EXPECT_TRUE(tryCatch.HasCaught());
    tryCatch.ClearException();
    ArkNativeEngine* engine = (ArkNativeEngine*)env_;
    if (!engine->lastException_.IsEmpty()) {
        engine->lastException_.Empty();
    }
    GTEST_LOG_(INFO) << "AbilityRuntime_UIExtensionContext_0100 end";
}

HWTEST_F(UIExtensionContextTest, AbilityRuntime_UIExtensionContext_0101, TestSize.Level1)
{
    HandleScope handleScope(env_);
    TryCatch tryCatch(env_);
    napi_value undef = nullptr;
    napi_get_undefined(env_, &undef);
    napi_value argv[] = { undef };
    Connect(argv, ARGC_ZERO);

    EXPECT_TRUE(tryCatch.HasCaught());
    tryCatch.ClearException();
    ArkNativeEngine* engine = (ArkNativeEngine*)env_;
    if (!engine->lastException_.IsEmpty()) {
        engine->lastException_.Empty();
    }
    GTEST_LOG_(INFO) << "AbilityRuntime_UIExtensionContext_0101 end";
}

HWTEST_F(UIExtensionContextTest, AbilityRuntime_UIExtensionContext_0102, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityRuntime_UIExtensionContext_0102 start";
    TryCatch tryCatch(env_);
    AAFwk::Want want;
    napi_value jswant = AppExecFwk::CreateJsWant(env_, want);
    napi_value argv[] = { jswant };
    Connect(argv, ARGC_ZERO);
    EXPECT_TRUE(tryCatch.HasCaught());

    ArkNativeEngine* engine = (ArkNativeEngine*)env_;
    uv_loop_t* loop = engine->GetUVLoop();
    RunNowait(loop);
    EXPECT_FALSE(MockDeferred::GetLastResolveStatus());

    tryCatch.ClearException();
    if (!engine->lastException_.IsEmpty()) {
        engine->lastException_.Empty();
    }

    abilityContextImpl_->SetConnectResult(ERR_OK);
    GTEST_LOG_(INFO) << "AbilityRuntime_UIExtensionContext_0102 end";
}

HWTEST_F(UIExtensionContextTest, AbilityRuntime_UIExtensionContext_0103, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityRuntime_UIExtensionContext_0103 start";
    abilityContextImpl_->SetConnectResult(ERR_OK);

    TryCatch tryCatch(env_);
    AAFwk::Want want;
    napi_value jswant = AppExecFwk::CreateJsWant(env_, want);
    napi_value callbackObject = nullptr;
    napi_create_object(env_, &callbackObject);
    napi_value argv[] = { jswant, callbackObject };
    Connect(argv, ARGC_TWO);
    EXPECT_FALSE(tryCatch.HasCaught());

    ArkNativeEngine* engine = (ArkNativeEngine*)env_;
    uv_loop_t* loop = engine->GetUVLoop();
    RunNowait(loop);

    MockAbilityContextImpl::DoneConnect(ERR_OK);
    RunNowait(loop);

    EXPECT_TRUE(MockDeferred::GetLastResolveStatus());
    napi_ref nref = MockDeferred::GetLastResolveValue();
    EXPECT_NE(nref, nullptr);
    napi_value proxy = (reinterpret_cast<NativeReference*>(nref))->GetNapiValue();
    napi_value argv2[] = { proxy };
    Disconnect(argv2, ARGC_ONE);
    RunNowait(loop);

    MockAbilityContextImpl::DoneDisconnect(0);
    RunNowait(loop);
    abilityContextImpl_->SetConnectResult(ERR_OK);
    GTEST_LOG_(INFO) << "AbilityRuntime_UIExtensionContext_0103 end";
}

HWTEST_F(UIExtensionContextTest, AbilityRuntime_UIExtensionContext_0104, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityRuntime_UIExtensionContext_0202 start";
    TryCatch tryCatch(env_);
    napi_value argv[] = {};
    Disconnect(argv, ARGC_ZERO);
    EXPECT_TRUE(tryCatch.HasCaught());
    tryCatch.ClearException();
    ArkNativeEngine* engine = (ArkNativeEngine*)env_;
    if (!engine->lastException_.IsEmpty()) {
        engine->lastException_.Empty();
    }
    GTEST_LOG_(INFO) << "AbilityRuntime_UIExtensionContext_0202 end";
}

HWTEST_F(UIExtensionContextTest, AbilityRuntime_UIExtensionContext_0105, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityRuntime_UIExtensionContext_0105 start";
    HandleScope handleScope(env_);
    TryCatch tryCatch(env_);
    napi_value proxy = nullptr;
    napi_create_object(env_, &proxy);
    napi_value argv[] = {proxy};
    Disconnect(argv, ARGC_ONE);
    EXPECT_TRUE(tryCatch.HasCaught());
    tryCatch.ClearException();
    ArkNativeEngine* engine = (ArkNativeEngine*)env_;
    if (!engine->lastException_.IsEmpty()) {
        engine->lastException_.Empty();
    }
    GTEST_LOG_(INFO) << "AbilityRuntime_UIExtensionContext_0105 end";
}

HWTEST_F(UIExtensionContextTest, AbilityRuntime_UIExtensionContext_0106, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityRuntime_UIExtensionContext_0106 start";

    OHOS::AbilityRuntime::Runtime::Options options;
    std::shared_ptr<OHOS::JsEnv::JsEnvironment> jsEnv = nullptr;
    auto err = JsRuntimeLite::GetInstance().CreateJsEnv(options, jsEnv);
    EXPECT_EQ(err, napi_status::napi_ok);
    napi_env env = reinterpret_cast<napi_env>(jsEnv->GetNativeEngine());

    NapiCallbackInfo info{1};
    jsUIExtensionContext_->OnStartUIServiceExtension(env, info);

    JsRuntimeLite::GetInstance().RemoveJsEnv(reinterpret_cast<napi_env>(jsEnv->GetNativeEngine()));

    GTEST_LOG_(INFO) << "AbilityRuntime_UIExtensionContext_0106 end";
}

HWTEST_F(UIExtensionContextTest, AbilityRuntime_UIExtensionContext_0107, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetParam(AAFwk::Want::PARAM_RESV_DISPLAY_ID, 0);
    jsUIExtensionContext_->InitDisplayId(want);
    auto displayId = want.GetIntParam(AAFwk::Want::PARAM_RESV_DISPLAY_ID, 0);
    EXPECT_EQ(displayId, 0);
}
}  // namespace AAFwk
}  // namespace OHOS