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
#define private public
#define protected public
#include "agent_card_mgr.h"
#undef private
#undef protected

using namespace OHOS;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AgentRuntime {
class AgentCardMgrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void AgentCardMgrTest::SetUpTestCase(void)
{}

void AgentCardMgrTest::TearDownTestCase(void)
{}

void AgentCardMgrTest::SetUp(void)
{}

void AgentCardMgrTest::TearDown(void)
{}

/**
 * @tc.name: HandleBundleRemoveTest_001
 * @tc.desc: HandleBundleRemoveTest_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardMgrTest, HandleBundleRemoveTest_001, TestSize.Level1)
{
    AgentCardMgr agentCardMgr;
    int ret = agentCardMgr.HandleBundleRemove("", 100);
    EXPECT_TRUE(ret == -1);

    ret = agentCardMgr.HandleBundleRemove("test", 100);
    EXPECT_TRUE(ret != -1);
}

/**
 * @tc.name: HandleBundleInstallTest_001
 * @tc.desc: HandleBundleInstallTest_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardMgrTest, HandleBundleInstallTest_001, TestSize.Level1)
{
    AgentCardMgr agentCardMgr;
    int ret = agentCardMgr.HandleBundleInstall("", 100);
    EXPECT_TRUE(ret == -1);

    ret = agentCardMgr.HandleBundleInstall("test", 100);
    EXPECT_TRUE(ret == -1);

    ret = agentCardMgr.HandleBundleInstall("test1", 100);
    EXPECT_TRUE(ret != -1);
}

/**
 * @tc.name: GetAgentCardByAgentId_001
 * @tc.desc: GetAgentCardByAgentId_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardMgrTest, GetAgentCardByAgentId_001, TestSize.Level1)
{
    AgentCardMgr agentCardMgr;
    AgentCard card;
    int ret = agentCardMgr.GetAgentCardByAgentId("test", "test", card);
    EXPECT_TRUE(ret != 0);
}
} // namespace AgentRuntime
} // namespace OHOS