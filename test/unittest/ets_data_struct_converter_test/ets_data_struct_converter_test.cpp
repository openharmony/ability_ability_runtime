/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "hilog_wrapper.h"
#define private public
#define protected public
#include "ets_data_struct_converter.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AbilityRuntime {

class EtsDataStructConverterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void EtsDataStructConverterTest::SetUpTestCase() {}

void EtsDataStructConverterTest::TearDownTestCase() {}

void EtsDataStructConverterTest::SetUp() {}

void EtsDataStructConverterTest::TearDown() {}

/**
 * @tc.name: EtsDataStructConverter_WrapLaunchParam_0100
 * @tc.desc: WrapLaunchParam test
 * @tc.desc: Verify function WrapLaunchParam.
 */
HWTEST_F(EtsDataStructConverterTest, EtsDataStructConverter_WrapLaunchParam_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EtsDataStructConverter_WrapLaunchParam_0100 start";
    AAFwk::LaunchParam launchParam {};
    ani_object object = nullptr;
    ani_env *env = nullptr;
    ASSERT_FALSE(WrapLaunchParam(env, launchParam, object));
    GTEST_LOG_(INFO) << "EtsDataStructConverter_WrapLaunchParam_0100 end";
}
} // namespace AbilityRuntime
} // namespace OHOS