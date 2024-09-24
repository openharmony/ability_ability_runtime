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
#include <singleton.h>
#include <cstdint>
#include <cstring>

#define private public
#define protected public
#include "overlay_event_subscriber.h"
#include "bundle_mgr_proxy.h"
#include "hilog_tag_wrapper.h"
#include "overlay_module_info.h"
#include "want.h"
#undef private
#undef protected

namespace OHOS {
namespace AppExecFwk {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
namespace {
int32_t code1_ = 0;
std::string data1_ = "data1";
}

class OverlayEventSubscriberTest : public testing::Test {
public:
    OverlayEventSubscriberTest()
    {}
    ~OverlayEventSubscriberTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OverlayEventSubscriberTest::SetUpTestCase(void)
{}

void OverlayEventSubscriberTest::TearDownTestCase(void)
{}

void OverlayEventSubscriberTest::SetUp(void)
{}

void OverlayEventSubscriberTest::TearDown(void)
{}

void OverlayEventSubscriberTestCallback(const EventFwk::CommonEventData & testData)
{
    code1_ = testData.code_;
    data1_ = testData.data_;
}

/**
 * @tc.number: OverlayEventSubscriberTest_001
 * @tc.name: DumpFfrt
 * @tc.desc: Test whether GetBundleName is called normally.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(OverlayEventSubscriberTest, OverlayEventSubscriberTest_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "OverlayEventSubscriberTest_001 start";
    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    std::function<void (const EventFwk::CommonEventData &)> func = OverlayEventSubscriberTestCallback;
    OverlayEventSubscriber overlayEventSubscriber(subscribeInfo, func);
    OHOS::AAFwk::Want want;
    int32_t code = 1;
    std::string data = "testData";
    EventFwk::CommonEventData eventData(want, code, data);
    overlayEventSubscriber.OnReceiveEvent(eventData);
    EXPECT_EQ(data1_, "testData");
    EXPECT_EQ(code1_, 1);
    GTEST_LOG_(INFO) << "OverlayEventSubscriberTest_001 end";
}
}
}