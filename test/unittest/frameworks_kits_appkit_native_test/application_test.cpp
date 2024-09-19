/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "ohos_application.h"
#include "ui_ability.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
class ApplicationTest : public testing::Test {
public:
    ApplicationTest()
    {}
    ~ApplicationTest()
    {}
    std::shared_ptr<OHOSApplication> ApplicationTest_ = nullptr;
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ApplicationTest::SetUpTestCase(void)
{}

void ApplicationTest::TearDownTestCase(void)
{}

void ApplicationTest::SetUp(void)
{
    ApplicationTest_ = std::make_shared<OHOSApplication>();
}

void ApplicationTest::TearDown(void)
{}

/**
 * @tc.number: AppExecFwk_Application_OnStart_0100
 * @tc.name: OnStart
 * @tc.desc: Test whether OnStart is called normally.
 */
HWTEST_F(ApplicationTest, AppExecFwk_Application_OnStart_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_Application_OnStart_0100 start";

    EXPECT_NE(ApplicationTest_, nullptr);
    if (ApplicationTest_ != nullptr) {
        ApplicationTest_->OnStart();
    }

    GTEST_LOG_(INFO) << "AppExecFwk_Application_OnStart_0100 end";
}

/**
 * @tc.number: AppExecFwk_Application_OnTerminate_0100
 * @tc.name: OnTerminate
 * @tc.desc: Test whether OnTerminate is called normally.
 */
HWTEST_F(ApplicationTest, AppExecFwk_Application_OnTerminate_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "AppExecFwk_Application_OnTerminate_0100 start";

    EXPECT_NE(ApplicationTest_, nullptr);
    if (ApplicationTest_ != nullptr) {
        ApplicationTest_->OnTerminate();
    }

    GTEST_LOG_(INFO) << "AppExecFwk_Application_OnTerminate_0100 end";
}
}  // namespace AppExecFwk
}  // namespace OHOS
