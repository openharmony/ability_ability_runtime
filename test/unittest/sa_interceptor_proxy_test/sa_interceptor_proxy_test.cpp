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
#include "sa_interceptor_proxy.h"
#undef private
#include "ipc_types.h"
#include "message_parcel.h"
#include "mock_sa_interceptor_stub.h"
#include "rule.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace AbilityRuntime {
class SAInterceptorProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SAInterceptorProxyTest::SetUpTestCase(void)
{}
void SAInterceptorProxyTest::TearDownTestCase(void)
{}
void SAInterceptorProxyTest::TearDown(void)
{}
void SAInterceptorProxyTest::SetUp()
{}

/*
 * @tc.number: OnCheckStarting_001
 * @tc.name: OnCheckStarting
 * @tc.desc: Verify OnCheckStarting functionality
 */
HWTEST_F(SAInterceptorProxyTest, OnCheckStarting_001, TestSize.Level1)
{
    sptr<SAInterceptorStub> sAInterceptorStub(new MockSAInterceptorStub(0));
    sptr<SAInterceptorProxy> proxy(new SAInterceptorProxy(sAInterceptorStub));
    Rule rule;
    std::string params = "";
    auto result = proxy->OnCheckStarting(params, rule);
    EXPECT_EQ(result, NO_ERROR);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
