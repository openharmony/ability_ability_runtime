/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#define protected public
#include "ets_ui_ability_instance.h"
#undef private
#undef protected
#include "ets_runtime.h"
#include "hilog_tag_wrapper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class EtsUIAbilityInstanceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void EtsUIAbilityInstanceTest::SetUpTestCase() {}

void EtsUIAbilityInstanceTest::TearDownTestCase() {}

void EtsUIAbilityInstanceTest::SetUp() {}

void EtsUIAbilityInstanceTest::TearDown() {}

/**
 * @tc.name: CreateETSUIAbility_100
 * @tc.desc: CreateETSUIAbility test.
 * @tc.type: FUNC
 */
HWTEST_F(EtsUIAbilityInstanceTest, CreateETSUIAbility_100, TestSize.Level1)
{
    AbilityRuntime::Runtime::Options options;
    options.lang = AbilityRuntime::Runtime::Language::ETS;
    auto runtime = AbilityRuntime::Runtime::Create(options);
    auto ability = CreateETSUIAbility(runtime);
    EXPECT_NE(ability, nullptr);
}
} // namespace AbilityRuntime
} // namespace OHOS
