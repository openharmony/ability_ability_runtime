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

#include "insight_intent_sys_event_receiver.h"
#include "insight_intent_event_mgr.h"
#include "common_event_support.h"
#include "hilog_tag_wrapper.h"

using namespace testing::ext;
using namespace testing;
namespace OHOS {
namespace AbilityRuntime {
const int32_t MAIN_USER_ID = 100;
const int32_t OTHER_USER_ID = 101;

class InsightIntentSysEventReceiverTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void InsightIntentSysEventReceiverTest::SetUpTestCase(void) {}
void InsightIntentSysEventReceiverTest::TearDownTestCase(void) {}
void InsightIntentSysEventReceiverTest::TearDown() {}
void InsightIntentSysEventReceiverTest::SetUp() {}

/**
 * @tc.name: InsightIntentSysEventReceiverTest_OnReceiveEvent_0001
 * @tc.desc: Test the state of OnReceiveEvent
 * @tc.type: FUNC
 */
HWTEST_F(InsightIntentSysEventReceiverTest, OnReceiveEvent_0001, TestSize.Level1)
{
    // modulename invalid
    AppExecFwk::ElementName element1("", "com.test.demo", "MainAbility");
    AbilityRuntime::InsightIntentEventMgr::UpdateInsightIntentEvent(element1, -1);
    // userId invalid
    AppExecFwk::ElementName element2("", "com.test.demo", "MainAbility", "module1, module2");
    AbilityRuntime::InsightIntentEventMgr::UpdateInsightIntentEvent(element2, -1);
    // param valid
    AbilityRuntime::InsightIntentEventMgr::UpdateInsightIntentEvent(element2, MAIN_USER_ID);

    // bundleName invalid
    AppExecFwk::ElementName element3("", "", "MainAbility", "module1, module2");
    AbilityRuntime::InsightIntentEventMgr::DeleteInsightIntentEvent(element3, -1, 1);
    // appIndex invalid
    AbilityRuntime::InsightIntentEventMgr::DeleteInsightIntentEvent(element1, -1, 1);
    // userId invalid
    AbilityRuntime::InsightIntentEventMgr::DeleteInsightIntentEvent(element1, -1, 0);
    // param valid
    AbilityRuntime::InsightIntentEventMgr::DeleteInsightIntentEvent(element1, MAIN_USER_ID, 0);
    AbilityRuntime::InsightIntentEventMgr::DeleteInsightIntent("com.test.demo", "module1", MAIN_USER_ID);

    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    auto sysEventReceiver = std::make_shared<AbilityRuntime::InsightIntentSysEventReceiver>(subscribeInfo);

    EventFwk::CommonEventData data;
    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED;
    data.code_ = 101;
    sysEventReceiver->OnReceiveEvent(data);
    EXPECT_NE(sysEventReceiver->lastUserId_, 0);

    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED;
    sysEventReceiver->OnReceiveEvent(data);
    EXPECT_NE(sysEventReceiver->lastUserId_, 0);

    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED;
    data.code_ = MAIN_USER_ID;
    sysEventReceiver->OnReceiveEvent(data);
    EXPECT_NE(sysEventReceiver->lastUserId_, 0);

    data.want_.operation_.action_ = EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED;
    data.code_ = OTHER_USER_ID;
    sysEventReceiver->OnReceiveEvent(data);
    EXPECT_NE(sysEventReceiver->lastUserId_, 0);
}
} // namespace AbilityRuntime
} // namespace OHOS
