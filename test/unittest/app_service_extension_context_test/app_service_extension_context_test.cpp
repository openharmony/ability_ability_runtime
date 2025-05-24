/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "ability_manager_client.h"
#include "app_service_extension_context.h"
#undef private

#include "ability_connection.h"
#include "ability_manager_stub_mock.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr int32_t ERR_INVALID_VALUE = 22;
} // namespace
class AppServiceExtensionContextTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AppServiceExtensionContextTest::SetUpTestCase(void)
{}
void AppServiceExtensionContextTest::TearDownTestCase(void)
{}
void AppServiceExtensionContextTest::SetUp(void)
{}
void AppServiceExtensionContextTest::TearDown(void)
{}

/*
 * Feature: AppServiceExtensionContext
 * Function: ConnectAbility
 * SubFunction: NA
 * FunctionPoints: AppServiceExtensionContextTest ConnectAbility
 * EnvConditions: NA
 * CaseDescription: Verify ConnectAbility
 */
HWTEST_F(AppServiceExtensionContextTest, service_extension_context_ConnectAbility_001, TestSize.Level1)
{
    AppServiceExtensionContext appServiceExtensionContextTest;
    Want want;
    sptr<AbilityConnectCallback> connectCallback;
    ErrCode result = appServiceExtensionContextTest.ConnectAbility(want, connectCallback);
    EXPECT_EQ(AAFwk::ERR_INVALID_CALLER, result);
}

/*
 * Feature: AppServiceExtensionContext
 * Function: DisconnectAbility
 * SubFunction: NA
 * FunctionPoints: AppServiceExtensionContextTest DisconnectAbility
 * EnvConditions: NA
 * CaseDescription: Verify DisconnectAbility
 */
HWTEST_F(AppServiceExtensionContextTest, service_extension_context_DisconnectAbility_001, TestSize.Level1)
{
    AppServiceExtensionContext appServiceExtensionContextTest;
    Want want;
    int32_t accountId = 1;
    sptr<AbilityConnectCallback> connectCallback;
    ErrCode result = appServiceExtensionContextTest.DisconnectAbility(want, connectCallback, accountId);
    GTEST_LOG_(INFO) <<result;
    EXPECT_EQ(AAFwk::ERR_INVALID_CALLER, result);
}

/*
 * Feature: AppServiceExtensionContext
 * Function: TerminateSelf
 * SubFunction: NA
 * FunctionPoints: AppServiceExtensionContextTest TerminateSelf
 * EnvConditions: NA
 * CaseDescription: Verify TerminateSelf
 */
HWTEST_F(AppServiceExtensionContextTest, service_extension_context_TerminateSelf_001, TestSize.Level1)
{
    AppServiceExtensionContext appServiceExtensionContextTest;
    ErrCode result = appServiceExtensionContextTest.TerminateSelf();
    GTEST_LOG_(INFO) <<result;
    EXPECT_EQ(ERR_INVALID_VALUE, result);
}
}
}
