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
#include "ability_handler.h"
#include "ability_info.h"
#include "ability_local_record.h"
#include "ability_thread.h"
#include "extension.h"
#undef private
#undef protected
#include "event_runner.h"
#include "mock_ability_token.h"

namespace OHOS {
namespace AppExecFwk {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

class ExtensionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<AbilityRuntime::Extension> extension_;
};

void ExtensionTest::SetUpTestCase(void)
{
}

void ExtensionTest::TearDownTestCase(void)
{
}

void ExtensionTest::SetUp(void)
{
    std::shared_ptr<AbilityInfo> info = std::make_shared<AbilityInfo>();
    sptr<IRemoteObject> token = new AppExecFwk::MockAbilityToken();
    auto record = std::make_shared<AbilityLocalRecord>(info, token);
    auto application = std::make_shared<AppExecFwk::OHOSApplication>();
    std::shared_ptr<EventRunner> runner;
    auto handler = std::make_shared<AppExecFwk::AbilityHandler>(runner);
    extension_ = std::make_shared<AbilityRuntime::Extension>();
    extension_->Init(record, application, handler, token);
}

void ExtensionTest::TearDown(void)
{
}

/**
 * @tc.number: AaFwk_Extension_0100
 * @tc.name: GetLaunchParam
 * @tc.desc: The result of GetLaunchParam is correct
 */
HWTEST_F(ExtensionTest, AaFwk_Extension_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "AaFwk_Extension_0100 start";
    auto extension = std::make_shared<AbilityRuntime::Extension>();
    AAFwk::LaunchParam launchParam;
    launchParam.lastExitMessage = "test";
    extension->SetLaunchParam(launchParam);
    AAFwk::LaunchParam launchParam2 = extension->GetLaunchParam();
    EXPECT_EQ(launchParam2.launchReason, launchParam.launchReason);
    EXPECT_EQ(launchParam2.lastExitReason, launchParam.lastExitReason);
    EXPECT_EQ(launchParam2.lastExitMessage, launchParam.lastExitMessage);
    GTEST_LOG_(INFO) << "AaFwk_Extension_0100 end";
}
} // namespace AppExecFwk
} // namespace OHOS
