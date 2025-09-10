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

#include "ability_manager_errors.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "js_environment.h"
#define private public
#include "js_panel_start_callback.h"
#undef private
#include "js_runtime.h"
#include "js_runtime_lite.h"
#include "js_runtime_utils.h"
#include "mock_vertical_panel_manager.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AppExecFwk {

class PanelStartCallbackTest : public testing::Test {
public:
    PanelStartCallbackTest()
    {
        OHOS::AbilityRuntime::Runtime::Options options;
        std::shared_ptr<OHOS::JsEnv::JsEnvironment> jsEnv = nullptr;
        JsRuntimeLite::GetInstance().CreateJsEnv(options, jsEnv);
        env = reinterpret_cast<napi_env>(jsEnv->GetNativeEngine());
    }
    static void SetUpTestCase(void)
    {}

    static void TearDownTestCase(void)
    {}

    void SetUp() override
    {
        jsPanelStartCallback = std::make_shared<JsPanelStartCallback>(env);
        jsPanelStartCallback->SetSessionId(mockSessionId);
        jsPanelStartCallback->SetUIContent(&mockUIContent);
    }

    void TearDown()
    {}

    std::shared_ptr<JsPanelStartCallback> jsPanelStartCallback;
    int32_t mockSessionId = 12345;
    Ace::MockUIContent mockUIContent;
    napi_env env;
};

/*
 * Feature: PanelStartCallback
 * Function: SetSessionId
 * SubFunction: NA
 * FunctionPoints: SetSessionId Basic Functionality
 */
HWTEST_F(PanelStartCallbackTest, SetSessionId_001, TestSize.Level1)
{
    int32_t tmpSessionId = 123;
    jsPanelStartCallback->SetSessionId(tmpSessionId);
    EXPECT_EQ(jsPanelStartCallback->sessionId_, tmpSessionId);
}

/*
 * Feature: PanelStartCallback
 * Function: SetUIContent
 * SubFunction: NA
 * FunctionPoints: SetUIContent Basic Functionality
 */
HWTEST_F(PanelStartCallbackTest, SetUIContent_001, TestSize.Level1)
{
    Ace::MockUIContent tmpUIContent;
    jsPanelStartCallback->SetUIContent(&tmpUIContent);
    EXPECT_EQ(jsPanelStartCallback->uiContent_, &tmpUIContent);
}

/*
 * Feature: PanelStartCallback
 * Function: SetUIContent
 * SubFunction: NA
 * FunctionPoints: SetUIContent Null Parameter
 */
HWTEST_F(PanelStartCallbackTest, SetUIContent_002, TestSize.Level1)
{
    // 测试传入nullptr
    jsPanelStartCallback->SetUIContent(nullptr);
    EXPECT_EQ(jsPanelStartCallback->uiContent_, nullptr);
}

/*
 * Feature: PanelStartCallback
 * Function: OnRelease
 * SubFunction: NA
 * FunctionPoints: OnRelease Basic Functionality
 */
HWTEST_F(PanelStartCallbackTest, OnRelease_001, TestSize.Level1)
{
    int32_t releaseCode = 0;
    // 期望调用CloseModalUIExtension
    EXPECT_CALL(mockUIContent, CloseModalUIExtension(mockSessionId)).Times(1);
    jsPanelStartCallback->OnRelease(releaseCode);
}

/*
 * Feature: PanelStartCallback
 * Function: OnRelease
 * SubFunction: NA
 * FunctionPoints: OnRelease Null UIContent Handling
 */
HWTEST_F(PanelStartCallbackTest, OnRelease_002, TestSize.Level1)
{
    int32_t releaseCode = 0;
    // 不设置UIContent，保持为nullptr
    jsPanelStartCallback->SetUIContent(nullptr);
    EXPECT_CALL(mockUIContent, CloseModalUIExtension(_)).Times(0);
    jsPanelStartCallback->OnRelease(releaseCode);
}

/*
 * Feature: JsPanelStartCallback
 * Function: SetJsCallbackObject
 * SubFunction: NA
 * FunctionPoints: SetJsCallbackObject Null Parameter
 */
HWTEST_F(PanelStartCallbackTest, SetJsCallbackObject_002, TestSize.Level1)
{
    // 测试传入空对象
    jsPanelStartCallback->SetJsCallbackObject(nullptr);

    // 验证回调对象为空
    EXPECT_EQ(jsPanelStartCallback->jsCallbackObject_, nullptr);
}

/*
 * Feature: JsPanelStartCallback
 * Function: OnError
 * SubFunction: NA
 * FunctionPoints: OnError Null Environment Handling
 */
HWTEST_F(PanelStartCallbackTest, OnError_001, TestSize.Level1)
{
    int32_t errorCode = 1001;
    // 测试空环境处理
    jsPanelStartCallback->env_ = nullptr;
    EXPECT_CALL(mockUIContent, CloseModalUIExtension(_)).Times(0);
    jsPanelStartCallback->OnError(errorCode);
}

/*
 * Feature: JsPanelStartCallback
 * Function: OnError
 * SubFunction: NA
 * FunctionPoints: OnError Null Environment Handling
 */
HWTEST_F(PanelStartCallbackTest, OnError_002, TestSize.Level1)
{
    int32_t errorCode = 1001;
    EXPECT_CALL(mockUIContent, CloseModalUIExtension(mockSessionId)).Times(1);
    jsPanelStartCallback->OnError(errorCode);
}

/*
 * Feature: JsPanelStartCallback
 * Function: OnResult
 * SubFunction: NA
 * FunctionPoints: OnResult Null Environment Handling
 */
HWTEST_F(PanelStartCallbackTest, OnResult_001, TestSize.Level1)
{
    int32_t resultCode = 0;
    AAFwk::Want want;
    // 测试空环境处理
    jsPanelStartCallback->env_ = nullptr;

    EXPECT_CALL(mockUIContent, CloseModalUIExtension(mockSessionId)).Times(0);
    jsPanelStartCallback->OnResult(resultCode, want);
}

/*
 * Feature: JsPanelStartCallback
 * Function: OnResult
 * SubFunction: NA
 * FunctionPoints: OnResult Null Environment Handling
 */
HWTEST_F(PanelStartCallbackTest, OnResult_002, TestSize.Level1)
{
    int32_t resultCode = 0;
    AAFwk::Want want;

    EXPECT_CALL(mockUIContent, CloseModalUIExtension(mockSessionId)).Times(1);
    jsPanelStartCallback->OnResult(resultCode, want);
}

/*
 * Feature: JsPanelStartCallback
 * Function: CallJsResult
 * SubFunction: NA
 * FunctionPoints: CallJsResult Null Environment Handling
 */
HWTEST_F(PanelStartCallbackTest, CallJsResult_001, TestSize.Level1)
{
    int32_t resultCode = 0;
    AAFwk::Want want;

    // 测试空环境
    jsPanelStartCallback->env_ = nullptr;
    EXPECT_CALL(mockUIContent, CloseModalUIExtension(mockSessionId)).Times(0);
    jsPanelStartCallback->CallJsResult(resultCode, want);
}

/*
 * Feature: JsPanelStartCallback
 * Function: CallJsError
 * SubFunction: NA
 * FunctionPoints: CallJsError Null Environment Handling
 */
HWTEST_F(PanelStartCallbackTest, CallJsError_001, TestSize.Level1)
{
    // 测试空环境
    jsPanelStartCallback->env_ = nullptr;
    EXPECT_CALL(mockUIContent, CloseModalUIExtension(mockSessionId)).Times(0);
    jsPanelStartCallback->CallJsError(0);
}

}  // namespace AppExecFwk
}  // namespace OHOS