/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "auto_fill_manager.h"
#include "auto_fill_error.h"
#include "auto_fill_extension_callback.h"
#include "extension_ability_info.h"
#include "hilog_wrapper.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class AutoFillManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    virtual Ace::UIContent* GetUIContent()
    {
        return nullptr;
    }

    std::shared_ptr<AutoFillManager> autoFillManager_ = std::make_shared<AutoFillManager>();
};

void AutoFillManagerTest::SetUpTestCase(void)
{}

void AutoFillManagerTest::TearDownTestCase(void)
{}

void AutoFillManagerTest::SetUp()
{}

void AutoFillManagerTest::TearDown()
{}

/**
 * @tc.name: ReloadInModal_0100
 * @tc.desc: Js auto fill extension ReloadInModal.
 * @tc.type: FUNC
 */
HWTEST_F(AutoFillManagerTest, ReloadInModal_0100, TestSize.Level1)
{
    AutoFill::ReloadInModalRequest request;
    ASSERT_NE(autoFillManager_, nullptr);
    auto ret = autoFillManager_->ReloadInModal(request);
    EXPECT_EQ(ret, AutoFill::AUTO_FILL_OBJECT_IS_NULL);
}
} // namespace AppExecFwk
} // namespace OHOS