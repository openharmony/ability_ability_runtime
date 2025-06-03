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
#include "ability_start_with_wait_observer_proxy.h"
#include "ability_start_with_wait_observer_data.h"
#undef private
#include "mock_ability_start_with_wait_observer_stub.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class AbilityStartWithWaitObserverProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    sptr<AbilityStartWithWaitObserverProxy> observerProxy_ {nullptr};
    sptr<MockAbilityStartWithWaitObserverStub> mock_;
};
void AbilityStartWithWaitObserverProxyTest::SetUpTestCase()
{}

void AbilityStartWithWaitObserverProxyTest::TearDownTestCase()
{}

void AbilityStartWithWaitObserverProxyTest::SetUp()
{
    mock_ = new MockAbilityStartWithWaitObserverStub();
    observerProxy_ = new AbilityStartWithWaitObserverProxy(mock_);
}

void AbilityStartWithWaitObserverProxyTest::TearDown()
{}

/**
 * @tc.number: WriteInterfaceToken_0100
 * @tc.desc: Write token into parcel data.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityStartWithWaitObserverProxyTest, WriteInterfaceToken_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "WriteInterfaceToken_0100 start";
    MessageParcel data;
    auto ret = observerProxy_->WriteInterfaceToken(data);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "WriteInterfaceToken_0100 end";
}

/**
 * @tc.number: NotifyAATerminateWait_0100
 * @tc.desc: Test by determine whether sendRequest has been executed.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityStartWithWaitObserverProxyTest, NotifyAATerminateWait_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyAATerminateWait_0100 start";
    EXPECT_CALL(*mock_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(mock_.GetRefPtr(), &MockAbilityStartWithWaitObserverStub::InvokeSendRequest));
    AbilityStartWithWaitObserverData data;
    Parcel parcel;
    EXPECT_TRUE(data.Marshalling(parcel));
    observerProxy_->NotifyAATerminateWait(data);
    EXPECT_EQ(
        static_cast<uint32_t>(IAbilityStartWithWaitObserver::Message::NOTIFY_AA_TERMINATE_WAIT),
        mock_->GetCode());
    GTEST_LOG_(INFO) << "NotifyAATerminateWait_0100 end";
}
} // namespace AAFwk
} // namespace OHOS
