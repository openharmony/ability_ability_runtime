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

#include "ability_manager_service.h"
#include "ability_record.h"
#include "wm_common.h"
#define private public
#define protected public
#include "window_focus_changed_listener.h"
#undef private
#undef protected

namespace OHOS {
namespace AppExecFwk {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AAFwk;

class WindowFocusChangedListenerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WindowFocusChangedListenerTest::SetUpTestCase(void)
{}

void WindowFocusChangedListenerTest::TearDownTestCase(void)
{}

void WindowFocusChangedListenerTest::SetUp(void)
{}

void WindowFocusChangedListenerTest::TearDown(void)
{}

/**
 * @tc.number: DumpFfrtHelperTest_001
 * @tc.name: DumpFfrt
 * @tc.desc: Test whether GetBundleName is called normally.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(WindowFocusChangedListenerTest, OnFocused_001, Function | MediumTest | Level1)
{
    std::shared_ptr<AbilityManagerService> owner;
    std::shared_ptr<AAFwk::TaskHandlerWrap> handler;
    auto info = std::make_shared<WindowFocusChangedListener>(owner, handler);
    sptr<Rosen::FocusChangeInfo> focusChangeInfo;
    info->OnFocused(focusChangeInfo);
    EXPECT_EQ(focusChangeInfo, nullptr);
}

/**
 * @tc.number: DumpFfrtHelperTest_001
 * @tc.name: DumpFfrt
 * @tc.desc: Test whether GetBundleName is called normally.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(WindowFocusChangedListenerTest, OnFocused_002, Function | MediumTest | Level1)
{
    std::shared_ptr<AbilityManagerService> owner;
    std::shared_ptr<AAFwk::TaskHandlerWrap> handler;
    auto info = std::make_shared<WindowFocusChangedListener>(owner, handler);
    sptr<Rosen::FocusChangeInfo> focusChangeInfo;
    pid_t pid = 1;
    focusChangeInfo = new Rosen::FocusChangeInfo();
    focusChangeInfo->pid_ = pid;
    info->OnFocused(focusChangeInfo);
    EXPECT_NE(focusChangeInfo, nullptr);
}

/**
 * @tc.number: DumpFfrtHelperTest_001
 * @tc.name: DumpFfrt
 * @tc.desc: Test whether GetBundleName is called normally.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(WindowFocusChangedListenerTest, OnFocused_003, Function | MediumTest | Level1)
{
    std::shared_ptr<AbilityManagerService> owner;
    std::string queueName = "queueName";
    std::shared_ptr<AAFwk::TaskHandlerWrap> handler = AAFwk::TaskHandlerWrap::CreateQueueHandler(queueName);
    EXPECT_NE(handler, nullptr);
    auto info = std::make_shared<WindowFocusChangedListener>(owner, handler);
    sptr<Rosen::FocusChangeInfo> focusChangeInfo;
    pid_t pid = 1;
    focusChangeInfo = new Rosen::FocusChangeInfo();
    focusChangeInfo->pid_ = pid;
    info->OnFocused(focusChangeInfo);
    EXPECT_NE(focusChangeInfo, nullptr);
}

/**
 * @tc.number: DumpFfrtHelperTest_001
 * @tc.name: DumpFfrt
 * @tc.desc: Test whether GetBundleName is called normally.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(WindowFocusChangedListenerTest, OnUnfocused_001, Function | MediumTest | Level1)
{
    std::shared_ptr<AbilityManagerService> owner;
    std::shared_ptr<AAFwk::TaskHandlerWrap> handler;
    auto info = std::make_shared<WindowFocusChangedListener>(owner, handler);
    sptr<Rosen::FocusChangeInfo> focusChangeInfo;
    info->OnUnfocused(focusChangeInfo);
    EXPECT_EQ(focusChangeInfo, nullptr);
}

/**
 * @tc.number: DumpFfrtHelperTest_001
 * @tc.name: DumpFfrt
 * @tc.desc: Test whether GetBundleName is called normally.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(WindowFocusChangedListenerTest, OnUnfocused_002, Function | MediumTest | Level1)
{
    std::shared_ptr<AbilityManagerService> owner;
    std::shared_ptr<AAFwk::TaskHandlerWrap> handler;
    auto info = std::make_shared<WindowFocusChangedListener>(owner, handler);
    sptr<Rosen::FocusChangeInfo> focusChangeInfo;
    pid_t pid = 1;
    focusChangeInfo = new Rosen::FocusChangeInfo();
    focusChangeInfo->pid_ = pid;
    info->OnUnfocused(focusChangeInfo);
    EXPECT_NE(focusChangeInfo, nullptr);
}

/**
 * @tc.number: DumpFfrtHelperTest_001
 * @tc.name: DumpFfrt
 * @tc.desc: Test whether GetBundleName is called normally.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(WindowFocusChangedListenerTest, OnUnfocused_003, Function | MediumTest | Level1)
{
    std::shared_ptr<AbilityManagerService> owner;
    std::string queueName = "queueName";
    std::shared_ptr<AAFwk::TaskHandlerWrap> handler = AAFwk::TaskHandlerWrap::CreateQueueHandler(queueName);
    EXPECT_NE(handler, nullptr);
    auto info = std::make_shared<WindowFocusChangedListener>(owner, handler);
    sptr<Rosen::FocusChangeInfo> focusChangeInfo;
    pid_t pid = 1;
    focusChangeInfo = new Rosen::FocusChangeInfo();
    focusChangeInfo->pid_ = pid;
    info->OnUnfocused(focusChangeInfo);
    EXPECT_NE(focusChangeInfo, nullptr);
}
}
}
