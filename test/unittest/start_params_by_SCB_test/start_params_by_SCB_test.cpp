/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "parcel.h"
#define private public
#include "start_params_by_SCB.h"
#undef private

using namespace testing::ext;
namespace OHOS {
namespace AbilityRuntime {
class StartParamsBySCBTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void StartParamsBySCBTest::SetUpTestCase()
{}

void StartParamsBySCBTest::TearDownTestCase()
{}

void StartParamsBySCBTest::SetUp()
{}

void StartParamsBySCBTest::TearDown()
{}

/**
 * @tc.name: start_params_by_SCB_test_001
 * @tc.desc: test class StartParamsBySCB marshalling function
 * @tc.type: FUNC
 */
HWTEST_F(StartParamsBySCBTest, start_params_by_SCB_test_001, TestSize.Level1)
{
    StartParamsBySCB params;
    Parcel parcel;
    bool marshallResult = params.Marshalling(parcel);
    EXPECT_EQ(marshallResult, true);
}

/**
 * @tc.name: start_params_by_SCB_test_002
 * @tc.desc: test class StartOptions Unmarshalling function
 * @tc.type: FUNC
 */
HWTEST_F(StartParamsBySCBTest, start_params_by_SCB_test_002, TestSize.Level1)
{
    StartParamsBySCB params;
    Parcel parcel;
    auto unmarshallResult = params.Unmarshalling(parcel);
    EXPECT_NE(unmarshallResult, nullptr);
    ASSERT_FALSE(unmarshallResult->isRestart);
}

/**
 * @tc.name: start_params_by_SCB_test_003
 * @tc.desc: test class StartOptions Unmarshalling function
 * @tc.type: FUNC
 */
HWTEST_F(StartParamsBySCBTest, start_params_by_SCB_test_003, TestSize.Level1)
{
    StartParamsBySCB params;
    Parcel parcel;
    bool result = params.ReadFromParcel(parcel);
    ASSERT_TRUE(result);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
