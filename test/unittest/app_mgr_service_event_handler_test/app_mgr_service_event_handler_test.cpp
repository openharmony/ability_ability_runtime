/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#define private public
#include "app_mgr_service_event_handler.h"
#undef private

#include "app_mgr_service_inner.h"
#include <gtest/gtest.h>
#include <memory>
#include "mock_app_scheduler.h"
#include "hilog_tag_wrapper.h"
#include "inner_event.h"
#include <gtest/gtest.h>

using namespace testing::ext;
namespace OHOS {
namespace AppExecFwk {
static bool eventHandlerFlag_ = false;
const int EVENT_ID = 10;
class MockAMSEventHandler : public AMSEventHandler {
public:
    MockAMSEventHandler(const std::shared_ptr<AAFwk::TaskHandlerWrap>& runner,
        const std::shared_ptr<AppMgrServiceInner>& appMgrService);
    virtual ~MockAMSEventHandler();

    void ProcessEvent(const AAFwk::EventWrap& event) override
    {
        if (event.GetEventId() == EVENT_ID) {
            eventHandlerFlag_ = true;
        }
    }
};

class AMSEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

public:
    std::shared_ptr<AppMgrServiceInner> testAms;
    std::shared_ptr<MockAMSEventHandler> eventHandler_;
    std::shared_ptr<AAFwk::TaskHandlerWrap> runner_;
};

static void WaitUntilTaskFinished(std::shared_ptr<AAFwk::TaskHandlerWrap> handler)
{
    if (!handler) {
        return;
    }

    const uint32_t maxRetryCount = 1000;
    const uint32_t sleepTime = 1000;
    uint32_t count = 0;
    std::atomic<bool> taskCalled(false);
    auto f = [&taskCalled]() { taskCalled.store(true); };
    if (handler->SubmitTask(f)) {
        while (!taskCalled.load()) {
            ++count;
            // if delay more than 1 second, break
            if (count >= maxRetryCount) {
                break;
            }

            usleep(sleepTime);
        }
    }
}

void AMSEventHandlerTest::SetUpTestCase()
{}

void AMSEventHandlerTest::TearDownTestCase()
{}

void AMSEventHandlerTest::SetUp()
{
    runner_ = AAFwk::TaskHandlerWrap::CreateQueueHandler("AMSEventHandlerTest");
    testAms = std::make_shared<AppMgrServiceInner>();
}

void AMSEventHandlerTest::TearDown()
{}

MockAMSEventHandler::MockAMSEventHandler(
    const std::shared_ptr<AAFwk::TaskHandlerWrap>& runner, const std::shared_ptr<AppMgrServiceInner>& appMgrService)
    : AMSEventHandler(runner, appMgrService)
{}

MockAMSEventHandler::~MockAMSEventHandler()
{}

/*
 * Feature: AMS
 * Function: AMSEventHandler
 * SubFunction: AMSEventHandler
 * FunctionPoints: init.
 * EnvConditions: need to start a runner
 * CaseDescription: Initialize message class
 */

HWTEST_F(AMSEventHandlerTest, app_mgr_service_event_handler_test_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "app_mgr_service_event_handler_test start");

    if (!runner_) {
        TAG_LOGI(AAFwkTag::TEST, "app_mgr_service_event_handler_test : runner_ is null");
    }

    if (!testAms) {
        TAG_LOGI(AAFwkTag::TEST, "app_mgr_service_event_handler_test : testAms is null");
    }
    EXPECT_FALSE(eventHandler_);
    // init
    eventHandler_ = std::make_shared<MockAMSEventHandler>(runner_, testAms);
    EXPECT_TRUE(eventHandler_);
    TAG_LOGI(AAFwkTag::TEST, "app_mgr_service_event_handler_test end");
}

/*
 * Feature: AMS
 * Function: ProcessEvent
 * SubFunction: AMSEventHandler
 * FunctionPoints: postTask.
 * EnvConditions: need to start a runner
 * CaseDescription: Notification message
 */

HWTEST_F(AMSEventHandlerTest, app_mgr_service_event_handler_test_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "app_mgr_service_event_handler_test start");

    if (!eventHandler_) {
        eventHandler_ = std::make_shared<MockAMSEventHandler>(runner_, testAms);
    }

    // Error testing
    eventHandler_->SendEvent(20);

    // waiting callback
    WaitUntilTaskFinished(runner_);
    EXPECT_FALSE(eventHandlerFlag_);

    // test num == 10
    eventHandler_->SendEvent(10);

    // waiting callback
    WaitUntilTaskFinished(runner_);
    EXPECT_TRUE(eventHandlerFlag_);

    TAG_LOGI(AAFwkTag::TEST, "app_mgr_service_event_handler_test end");
}
}  // namespace AppExecFwk
}  // namespace OHOS
