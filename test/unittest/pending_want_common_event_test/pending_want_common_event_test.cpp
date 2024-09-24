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
#include "pending_want_common_event.h"
#undef private
#include "want.h"
#include "wants_info.h"
#include "hilog_tag_wrapper.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace AAFwk {
class PendingWantCommonEventTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PendingWantCommonEventTest::SetUpTestCase(void)
{}
void PendingWantCommonEventTest::TearDownTestCase(void)
{}
void PendingWantCommonEventTest::SetUp(void)
{}
void PendingWantCommonEventTest::TearDown(void)
{}
class TestWantReceiver : public IWantReceiver {
    virtual void Send(const int32_t resultCode) {}
    virtual void PerformReceive(const Want &want, int resultCode, const std::string &data, const WantParams &extras,
        bool serialized, bool sticky, int sendingUser) {}
    virtual sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    }
};
/*
 * @tc.number: OnReceiveEvent_0100
 * @tc.name: set type
 * @tc.desc: Set RequestWant, use GetRequestWant to verify whether the RequestWant  is set successfully
 */
HWTEST_F(PendingWantCommonEventTest, OnReceiveEvent_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PendingWantCommonEventTest OnReceiveEvent_0100 start");
    PendingWantCommonEvent PendingWant;
    EventFwk::CommonEventData data;
    PendingWant.OnReceiveEvent(data);
    EXPECT_EQ(PendingWant.finishedReceiver_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "PendingWantCommonEventTest OnReceiveEvent_0100 end");
}

/*
 * @tc.number: OnReceiveEvent_0200
 * @tc.name: set type
 * @tc.desc: Set RequestWant, use GetRequestWant to verify whether the RequestWant  is set successfully
 */
HWTEST_F(PendingWantCommonEventTest, OnReceiveEvent_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PendingWantCommonEventTest OnReceiveEvent_0200 start");
    PendingWantCommonEvent PendingWant;
    EventFwk::CommonEventData data;
    PendingWant.finishedReceiver_ = new TestWantReceiver();
    PendingWant.OnReceiveEvent(data);
    EXPECT_NE(PendingWant.finishedReceiver_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "PendingWantCommonEventTest OnReceiveEvent_0200 end");
}
}  // namespace AAFwk
}  // namespace OHOS
