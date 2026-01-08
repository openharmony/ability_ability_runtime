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
#include <gmock/gmock.h>
#include "agent_bundle_event_callback.h"
#include "want.h"

using namespace OHOS;
using namespace testing;
using namespace testing::ext;
using Want = OHOS::AAFwk::Want;

namespace OHOS {
namespace AgentRuntime {
class AgentBundleEventCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void AgentBundleEventCallbackTest::SetUpTestCase(void)
{}

void AgentBundleEventCallbackTest::TearDownTestCase(void)
{}

void AgentBundleEventCallbackTest::SetUp(void)
{}

void AgentBundleEventCallbackTest::TearDown(void)
{}

/**
 * @tc.name: OnReceiveEventTest_001
 * @tc.desc: OnReceiveEventTest_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentBundleEventCallbackTest, OnReceiveEventTest_001, TestSize.Level1)
{
    AgentBundleEventCallback bundleEventCallback;
    EventFwk::CommonEventData eventData;
    Want want;
    want.SetBundle("test");
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    eventData.SetWant(want);
    bundleEventCallback.OnReceiveEvent(eventData);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    bundleEventCallback.OnReceiveEvent(eventData);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    bundleEventCallback.OnReceiveEvent(eventData);

    EventFwk::CommonEventData eventData1;
    bundleEventCallback.OnReceiveEvent(eventData1);

    EventFwk::CommonEventData eventData2;
    Want want1;
    want1.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    eventData2.SetWant(want1);
    bundleEventCallback.OnReceiveEvent(eventData2);
    EXPECT_TRUE(eventData2.GetWant().GetElement().GetBundleName().empty());
}
} // namespace AgentRuntime
} // namespace OHOS