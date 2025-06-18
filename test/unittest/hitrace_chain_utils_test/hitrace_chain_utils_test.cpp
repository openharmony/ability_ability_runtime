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

#include "hitrace_chain_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class AbilityHitraceChainTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AbilityHitraceChainTest::SetUpTestCase(void) {}

void AbilityHitraceChainTest::TearDownTestCase(void) {}

void AbilityHitraceChainTest::SetUp() {}

void AbilityHitraceChainTest::TearDown() {}

HWTEST_F(AbilityHitraceChainTest, AbilityHitraceChain_001, TestSize.Level1)
{
    auto isValid = HiviewDFX::HiTraceChain::GetId().IsValid();
    EXPECT_FALSE(isValid);
    AAFwk::AbilityHitraceChain abilityHitraceChain("StartAbility", HITRACE_FLAG_INCLUDE_ASYNC);
    isValid = HiviewDFX::HiTraceChain::GetId().IsValid();
    EXPECT_TRUE(isValid);
}

HWTEST_F(AbilityHitraceChainTest, AbilityHitraceChain_002, TestSize.Level1)
{
    auto traceId = HiviewDFX::HiTraceChain::Begin("StartAbility", HITRACE_FLAG_INCLUDE_ASYNC);
    AAFwk::AbilityHitraceChain abilityHitraceChain("StartAbility", HITRACE_FLAG_DEFAULT);
    auto chainId = HiviewDFX::HiTraceChain::GetId().GetChainId();
    EXPECT_EQ(chainId, traceId.GetChainId());
    auto isFlagEnabled = HiviewDFX::HiTraceChain::GetId().IsFlagEnabled(HITRACE_FLAG_INCLUDE_ASYNC);
    EXPECT_TRUE(isFlagEnabled);
    HiviewDFX::HiTraceChain::End(traceId);
}
} // namespace AbilityRuntime
} // namespace OHOS