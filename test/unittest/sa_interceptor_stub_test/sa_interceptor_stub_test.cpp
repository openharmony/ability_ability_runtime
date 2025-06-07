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
#include "sa_interceptor_stub.h"
#undef private
#include "ability_manager_errors.h"
#include "mock_sa_interceptor_stub.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace AbilityRuntime {
const int32_t INVALIED_ID = 10000;
class SAInterceptorStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void WriteInterfaceToken(MessageParcel& data);
    sptr<MockSAInterceptorStub> stub_{ nullptr };
};

void SAInterceptorStubTest::SetUpTestCase(void)
{}
void SAInterceptorStubTest::TearDownTestCase(void)
{}
void SAInterceptorStubTest::SetUp()
{
    stub_ = new MockSAInterceptorStub(0);
}
void SAInterceptorStubTest::TearDown()
{}

void SAInterceptorStubTest::WriteInterfaceToken(MessageParcel& data)
{
    data.WriteInterfaceToken(MockSAInterceptorStub::GetDescriptor());
}

/*
 * @tc.number: OnRemoteRequest_001
 * @tc.name: OnRemoteRequest
 * @tc.desc: Verify OnRemoteRequest functionality
 */
HWTEST_F(SAInterceptorStubTest, OnRemoteRequest_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    WriteInterfaceToken(data);
    int res = stub_->OnRemoteRequest(INVALIED_ID, data, reply, option);
    EXPECT_EQ(res, IPC_STUB_UNKNOW_TRANS_ERR);
}

/*
 * @tc.number: OnRemoteRequest_002
 * @tc.name: OnRemoteRequest
 * @tc.desc: Verify OnRemoteRequest functionality
 */
HWTEST_F(SAInterceptorStubTest, OnRemoteRequest_002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int res = stub_->OnRemoteRequest(static_cast<int32_t>(ISAInterceptor::SAInterceptorCmd::ON_DO_CHECK_STARTING),
        data, reply, option);
    EXPECT_EQ(res, AAFwk::ERR_SA_INTERCEPTOR_DESCRIPTOR_MISMATCH);
}

/*
 * @tc.number: OnRemoteRequest_003
 * @tc.name: OnRemoteRequest
 * @tc.desc: Verify OnRemoteRequest functionality
 */
HWTEST_F(SAInterceptorStubTest, OnRemoteRequest_003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    WriteInterfaceToken(data);
    int res = stub_->OnRemoteRequest(static_cast<int32_t>(ISAInterceptor::SAInterceptorCmd::ON_DO_CHECK_STARTING),
        data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * @tc.number: HandleOnCheckStarting_001
 * @tc.name: HandleOnCheckStarting
 * @tc.desc: Verify HandleOnCheckStarting functionality
 */
HWTEST_F(SAInterceptorStubTest, HandleOnCheckStarting_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int res = stub_->HandleOnCheckStarting(data, reply);
    EXPECT_EQ(res, NO_ERROR);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
