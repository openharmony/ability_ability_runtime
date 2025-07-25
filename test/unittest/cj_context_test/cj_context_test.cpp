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

#include "gtest/gtest.h"
#include "cj_context.h"
#include "context.h"
#include "context_impl.h"
#include "cj_utils_ffi.h"
#include "cj_macro.h"
#include "cj_application_context.h"

using namespace OHOS::FFI;
using namespace OHOS::AbilityRuntime;

using namespace testing;
using namespace testing::ext;
using namespace OHOS::FfiContext;

extern "C" {
    void FfiContextSwitchArea(int64_t id, int32_t mode);
    int32_t FfiContextGetArea(int64_t id, int32_t type);
}

class FfiContextSwitchAreaTest : public ::testing::Test {};

/**
 * @tc.name  : FfiContextSwitchArea_ShouldLogError_WhenContextIsNull
 * @tc.number: FfiContextSwitchAreaTest_001
 */
HWTEST_F(FfiContextSwitchAreaTest, ATC_FfiContextSwitchArea_ShouldLogError_WhenContextIsNull, TestSize.Level0) {
    int64_t id = 123;
    int32_t mode = 4;
    FfiContextSwitchArea(id, mode);
}

/**
 * @tc.name  : FfiContextSwitchArea_ShouldCallSwitchArea_WhenContextIsNotNull
 * @tc.number: FfiContextSwitchAreaTest_002
 */
HWTEST_F(FfiContextSwitchAreaTest, ATC_FfiContextSwitchArea_ShouldCallSwitchArea_WhenContextIsNotNull,
    TestSize.Level0) {
    int32_t mode = 4;
    std::shared_ptr<ContextImpl> mockContext = std::make_shared<ContextImpl>();
    EXPECT_NE(mockContext, nullptr);
    auto cjContext = FFIData::Create<CJContext>(mockContext);
    EXPECT_NE(cjContext, nullptr);
    FfiContextSwitchArea(cjContext->GetID(), mode);
    auto modeGet = FfiContextGetArea(cjContext->GetID(), 0);
    EXPECT_EQ(modeGet, mode);
}