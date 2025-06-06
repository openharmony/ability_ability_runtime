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

#include <gtest/gtest.h>

#include "parcel.h"
#define private public
#include "rule.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
const RuleType type = RuleType::ALLOW;
class RuleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RuleTest::SetUpTestCase(void)
{}

void RuleTest::TearDownTestCase(void)
{}

void RuleTest::SetUp()
{}

void RuleTest::TearDown()
{}

/*
 * @tc.number: ReadFromParcel_0100
 * @tc.name: ReadFromParcel
 * @tc.desc: Verify ReadFromParcel functionality
 */
HWTEST_F(RuleTest, ReadFromParcel_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "RuleTest, Rule_0100, TestSize.Level1";
    Rule rule;
    Parcel parcel;

    parcel.WriteInt32(static_cast<int32_t>(type));
    EXPECT_TRUE(rule.ReadFromParcel(parcel));
}

/*
 * @tc.number: Marshalling_0100
 * @tc.name: Marshalling
 * @tc.desc: Verify Marshalling functionality
 */
HWTEST_F(RuleTest, Marshalling_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "RuleTest, Marshalling_0100, TestSize.Level1";
    Rule rule;
    Parcel parcel;
    EXPECT_TRUE(rule.Marshalling(parcel));
}

/*
 * @tc.number: Unmarshalling_0100
 * @tc.name: Unmarshalling
 * @tc.desc: Verify Unmarshalling functionality
 */
HWTEST_F(RuleTest, Unmarshalling_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "RuleTest, Unmarshalling_0100, TestSize.Level1";
    Rule rule;
    Parcel parcel;

    parcel.WriteInt32(static_cast<int32_t>(type));
    EXPECT_NE(rule.Unmarshalling(parcel), nullptr);
}
} // namespace AbilityRuntime
} // namespace OHOS