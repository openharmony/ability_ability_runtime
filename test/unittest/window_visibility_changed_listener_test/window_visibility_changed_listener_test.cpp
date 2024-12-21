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
#include <gtest/hwext/gtest-multithread.h>

#define private public
#include "app_running_manager.h"
#ifdef SUPPORT_CHILD_PROCESS
#include "child_process_record.h"
#endif // SUPPORT_CHILD_PROCESS
#include "window_visibility_changed_listener.h"
#undef private
#include "hilog_tag_wrapper.h"
#include "window_visibility_info.h"

using namespace testing;
using namespace testing::ext;
using namespace testing::mt;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t DEBUGINFOS_SIZE = 0;
constexpr int32_t ABILITYTOKENS_SIZE = 0;
constexpr int32_t RECORD_ID = 1;
constexpr uint32_t WINDOW_ID = 100;
constexpr pid_t PID = 10;
constexpr int32_t RECORD_MAP_SIZE = 1;
constexpr int32_t DEBUG_INFOS_SIZE = 1;
constexpr int32_t ABILITY_TOKENS_SIZE = 1;
}
class WindowVisibilityChangedListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void WindowVisibilityChangedListenerTest::SetUpTestCase(void)
{}

void WindowVisibilityChangedListenerTest::TearDownTestCase(void)
{}

void WindowVisibilityChangedListenerTest::SetUp()
{}

void WindowVisibilityChangedListenerTest::TearDown()
{}

/**
 * @tc.name: WindowVisibilityChangedListener_OnWindowVisibilityChanged_0100
 * @tc.desc: Test the state of OnWindowVisibilityChanged
 * @tc.type: FUNC
 */
HWTEST_F(WindowVisibilityChangedListenerTest, OnWindowVisibilityChanged_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnWindowVisibilityChanged_0100 called start.");
    std::weak_ptr<AppMgrServiceInner> appInner;
    std::shared_ptr<AAFwk::TaskHandlerWrap> handler;
    auto Info = std::make_shared<WindowVisibilityChangedListener>(appInner, handler);
    std::vector<sptr<OHOS::Rosen::WindowVisibilityInfo>> windowVisibilityInfos;
    Info->OnWindowVisibilityChanged(windowVisibilityInfos);
    EXPECT_EQ(windowVisibilityInfos.empty(), true);
    TAG_LOGI(AAFwkTag::TEST, "OnWindowVisibilityChanged_0100 called end.");
}

/**
 * @tc.name: WindowVisibilityChangedListener_OnWindowVisibilityChanged_0200
 * @tc.desc: Test the state of OnWindowVisibilityChanged
 * @tc.type: FUNC
 */
HWTEST_F(WindowVisibilityChangedListenerTest, OnWindowVisibilityChanged_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnWindowVisibilityChanged_0200 called start.");
    std::weak_ptr<AppMgrServiceInner> appInner;
    std::shared_ptr<AAFwk::TaskHandlerWrap> handler;
    auto Info = std::make_shared<WindowVisibilityChangedListener>(appInner, handler);
    std::vector<sptr<OHOS::Rosen::WindowVisibilityInfo>> windowVisibilityInfos;
    auto infos = new (std::nothrow) Rosen::WindowVisibilityInfo();
    EXPECT_NE(infos, nullptr);
    infos->windowId_ = WINDOW_ID;
    infos->pid_ = PID;
    infos->visibilityState_ = Rosen::WindowVisibilityState::WINDOW_VISIBILITY_STATE_NO_OCCLUSION;
    windowVisibilityInfos.push_back(infos);
    Info->taskHandler_ = nullptr;
    Info->OnWindowVisibilityChanged(windowVisibilityInfos);
    EXPECT_EQ(Info->taskHandler_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "OnWindowVisibilityChanged_0200 called end.");
}

/**
 * @tc.name: WindowVisibilityChangedListener_OnWindowVisibilityChanged_0300
 * @tc.desc: Test the state of OnWindowVisibilityChanged
 * @tc.type: FUNC
 */
HWTEST_F(WindowVisibilityChangedListenerTest, OnWindowVisibilityChanged_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnWindowVisibilityChanged_0300 called start.");
    std::weak_ptr<AppMgrServiceInner> appInner;
    std::shared_ptr<AAFwk::TaskHandlerWrap> handler =
    AAFwk::TaskHandlerWrap::CreateQueueHandler("WindowVisibilityChangedListenerTest");
    auto Info = std::make_shared<WindowVisibilityChangedListener>(appInner, handler);
    std::vector<sptr<OHOS::Rosen::WindowVisibilityInfo>> windowVisibilityInfos;
    auto infos = new (std::nothrow) Rosen::WindowVisibilityInfo();
    EXPECT_NE(infos, nullptr);
    infos->windowId_ = WINDOW_ID;
    infos->pid_ = PID;
    infos->visibilityState_ = Rosen::WindowVisibilityState::WINDOW_VISIBILITY_STATE_NO_OCCLUSION;
    windowVisibilityInfos.push_back(infos);
    Info->OnWindowVisibilityChanged(windowVisibilityInfos);
    EXPECT_NE(Info->taskHandler_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "OnWindowVisibilityChanged_0300 called end.");
}

} // namespace AppExecFwk
} // namespace OHOS
