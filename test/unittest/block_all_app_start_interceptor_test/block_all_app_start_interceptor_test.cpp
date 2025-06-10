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
#define private public
#define protected public
#include "interceptor/block_all_app_start_interceptor.h"
#undef private
#undef protected

#include "hilog_tag_wrapper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
class BlockAllAppStartInterceptorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

public:
};

void BlockAllAppStartInterceptorTest::SetUpTestCase()
{}

void BlockAllAppStartInterceptorTest::TearDownTestCase()
{}

void BlockAllAppStartInterceptorTest::SetUp()
{}

void BlockAllAppStartInterceptorTest::TearDown()
{}

/**
 * @tc.name: BlockAllAppStartInterceptorTest_DoProcess_001
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BlockAllAppStartInterceptorTest, DoProcess_001, TestSize.Level1)
{
    BlockAllAppStartInterceptor blockAllAppStartInterceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken = nullptr;
    std::function<bool(void)> shouldBlockAllAppStartFunc = nullptr;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldBlockAllAppStartFunc);
    auto ret = blockAllAppStartInterceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: BlockAllAppStartInterceptorTest_DoProcess_002
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BlockAllAppStartInterceptorTest, DoProcess_002, TestSize.Level1)
{
    BlockAllAppStartInterceptor blockAllAppStartInterceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken = nullptr;
    std::function<bool(void)> shouldBlockAllAppStartFunc = []() -> bool {
        return true;
    };
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldBlockAllAppStartFunc);
    auto ret = blockAllAppStartInterceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_ALL_APP_START_BLOCKED);
}

/**
 * @tc.name: BlockAllAppStartInterceptorTest_DoProcess_003
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BlockAllAppStartInterceptorTest, DoProcess_003, TestSize.Level1)
{
    BlockAllAppStartInterceptor blockAllAppStartInterceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken = nullptr;
    std::function<bool(void)> shouldBlockAllAppStartFunc = []() -> bool {
        return false;
    };
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldBlockAllAppStartFunc);
    auto ret = blockAllAppStartInterceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
}
} // namespace AAFwk
} // namespace OHOS
