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
#include "ag_convert_callback_impl.h"
#include "hilog_tag_wrapper.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
namespace OHOS {
namespace AAFwk {
class AgConvertCallbackImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void AgConvertCallbackImplTest::SetUpTestCase(void) {}
void AgConvertCallbackImplTest::TearDownTestCase(void) {}
void AgConvertCallbackImplTest::TearDown() {}
void AgConvertCallbackImplTest::SetUp() {}

/**
 * @tc.name: AgConvertCallbackImplTest_OnConvert_0001
 * @tc.desc: Test the state of OnConvert
 * @tc.type: FUNC
 */
HWTEST_F(AgConvertCallbackImplTest, OnConvert_0001, TestSize.Level1)
{
    ConvertCallbackTask task = [](int x, AAFwk::Want &y) {};
    auto callbackImpl = std::make_shared<ConvertCallbackImpl>(std::move(task));
    int resultCode = 1;
    AAFwk::Want want;
    callbackImpl->task_ = nullptr;
    callbackImpl->OnConvert(resultCode, want);
    EXPECT_EQ(callbackImpl->task_, nullptr);
}
} // namespace AAFwk
} // namespace OHOS
