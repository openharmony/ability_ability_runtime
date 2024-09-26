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
#include "ui_extension_servicehost_stub_impl.h"
#define private public
#include "js_uiservice_uiext_connection.h"
#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AbilityRuntime {
class JsUiserviceUiextConnectionTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void JsUiserviceUiextConnectionTest::SetUpTestCase(void)
{}
void JsUiserviceUiextConnectionTest::TearDownTestCase(void)
{}
void JsUiserviceUiextConnectionTest::SetUp()
{}
void JsUiserviceUiextConnectionTest::TearDown()
{}

/**
 * @tc.number: HandleOnAbilityConnectDone_0100
 * @tc.desc: HandleOnAbilityConnectDone
 * @tc.type: FUNC
 */
HWTEST_F(JsUiserviceUiextConnectionTest, HandleOnAbilityConnectDone_0100, TestSize.Level1)
{
    napi_env env;
    sptr<JSUIServiceUIExtConnection> connection = sptr<JSUIServiceUIExtConnection>::MakeSptr(env);
    EXPECT_NE(connection, nullptr);

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject;
    int resultCode = 0;
    connection->HandleOnAbilityConnectDone(element, remoteObject, resultCode);
    EXPECT_EQ(connection->napiAsyncTask_, nullptr);
}

/**
 * @tc.number: HandleOnAbilityDisconnectDone_0100
 * @tc.desc: HandleOnAbilityDisconnectDone
 * @tc.type: FUNC
 */
HWTEST_F(JsUiserviceUiextConnectionTest, HandleOnAbilityDisconnectDone_0100, TestSize.Level1)
{
    napi_env env;
    sptr<JSUIServiceUIExtConnection> connection = sptr<JSUIServiceUIExtConnection>::MakeSptr(env);
    EXPECT_NE(connection, nullptr);

    AppExecFwk::ElementName element;
    int resultCode = 0;
    connection->HandleOnAbilityDisconnectDone(element, resultCode);
    EXPECT_EQ(connection->serviceProxyObject_, nullptr);
}

/**
 * @tc.number: ResolveDuplicatedPendingTask_0100
 * @tc.desc: ResolveDuplicatedPendingTask
 * @tc.type: FUNC
 */
HWTEST_F(JsUiserviceUiextConnectionTest, ResolveDuplicatedPendingTask_0100, TestSize.Level1)
{
    napi_env env;
    sptr<JSUIServiceUIExtConnection> connection = sptr<JSUIServiceUIExtConnection>::MakeSptr(env);
    EXPECT_NE(connection, nullptr);

    napi_value proxy = nullptr;
    connection->ResolveDuplicatedPendingTask(env, proxy);
    EXPECT_EQ(connection->duplicatedPendingTaskList_.size(), 0);
}

/**
 * @tc.number: RejectDuplicatedPendingTask_0100
 * @tc.desc: RejectDuplicatedPendingTask
 * @tc.type: FUNC
 */
HWTEST_F(JsUiserviceUiextConnectionTest, RejectDuplicatedPendingTask_0100, TestSize.Level1)
{
    napi_env env;
    sptr<JSUIServiceUIExtConnection> connection = sptr<JSUIServiceUIExtConnection>::MakeSptr(env);
    EXPECT_NE(connection, nullptr);

    napi_value error = nullptr;
    connection->RejectDuplicatedPendingTask(env, error);
    EXPECT_EQ(connection->duplicatedPendingTaskList_.size(), 0);
}

/**
 * @tc.number: SetProxyObject_0100
 * @tc.desc: SetProxyObject
 * @tc.type: FUNC
 */
HWTEST_F(JsUiserviceUiextConnectionTest, SetProxyObject_0100, TestSize.Level1)
{
    napi_env env;
    sptr<JSUIServiceUIExtConnection> connection = sptr<JSUIServiceUIExtConnection>::MakeSptr(env);
    EXPECT_NE(connection, nullptr);

    napi_value proxy = nullptr;
    connection->SetProxyObject(proxy);
    EXPECT_EQ(connection->serviceProxyObject_, nullptr);
}

/**
 * @tc.number: GetProxyObject_0100
 * @tc.desc: GetProxyObject
 * @tc.type: FUNC
 */
HWTEST_F(JsUiserviceUiextConnectionTest, GetProxyObject_0100, TestSize.Level1)
{
    napi_env env;
    sptr<JSUIServiceUIExtConnection> connection = sptr<JSUIServiceUIExtConnection>::MakeSptr(env);
    EXPECT_NE(connection, nullptr);

    EXPECT_EQ(connection->GetProxyObject(), nullptr);
}

/**
 * @tc.number: OnSendData_0100
 * @tc.desc: OnSendData
 * @tc.type: FUNC
 */
HWTEST_F(JsUiserviceUiextConnectionTest, OnSendData_0100, TestSize.Level1)
{
    napi_env env;
    sptr<JSUIServiceUIExtConnection> connection = sptr<JSUIServiceUIExtConnection>::MakeSptr(env);
    EXPECT_NE(connection, nullptr);

    OHOS::AAFwk::WantParams data;
    EXPECT_EQ(connection->OnSendData(data), ERR_OK);
}

/**
 * @tc.number: IsJsCallbackObjectEquals_0100
 * @tc.desc: IsJsCallbackObjectEquals
 * @tc.type: FUNC
 */
HWTEST_F(JsUiserviceUiextConnectionTest, IsJsCallbackObjectEquals_0100, TestSize.Level1)
{
    napi_env env;
    sptr<JSUIServiceUIExtConnection> connection = sptr<JSUIServiceUIExtConnection>::MakeSptr(env);
    EXPECT_NE(connection, nullptr);

    std::unique_ptr<NativeReference> callback;
    napi_value value = nullptr;
    EXPECT_TRUE(connection->IsJsCallbackObjectEquals(env, callback, value));
}
}  // namespace AAFwk
}  // namespace OHOS
