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
#include "agent_card_db_mgr.h"
#undef private
#undef protected

using namespace OHOS;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AgentRuntime {
class AgentCardDbMgrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void AgentCardDbMgrTest::SetUpTestCase(void)
{}

void AgentCardDbMgrTest::TearDownTestCase(void)
{}

void AgentCardDbMgrTest::SetUp(void)
{}

void AgentCardDbMgrTest::TearDown(void)
{}

/**
 * @tc.name: RestoreKvStoreTest_001
 * @tc.desc: RestoreKvStoreTest_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardDbMgrTest, RestoreKvStoreTest_001, TestSize.Level1)
{
    AgentCardDbMgr agentCardDbMgr;
    DistributedKv::Status ret = agentCardDbMgr.RestoreKvStore(DistributedKv::Status::DATA_CORRUPTED);
    EXPECT_TRUE(ret != DistributedKv::Status::DATA_CORRUPTED);

    ret = agentCardDbMgr.RestoreKvStore(DistributedKv::Status::SUCCESS);
    EXPECT_TRUE(ret == DistributedKv::Status::SUCCESS);
}

/**
 * @tc.name: GetKvStoreTest_001
 * @tc.desc: GetKvStoreTest_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardDbMgrTest, GetKvStoreTest_001, TestSize.Level1)
{
    AgentCardDbMgr agentCardDbMgr;
    DistributedKv::Status ret = agentCardDbMgr.GetKvStore();
    EXPECT_TRUE(ret == DistributedKv::Status::SUCCESS);
}

/**
 * @tc.name: CheckKvStoreTest_001
 * @tc.desc: CheckKvStoreTest_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardDbMgrTest, CheckKvStoreTest_001, TestSize.Level1)
{
    AgentCardDbMgr agentCardDbMgr;
    bool ret = agentCardDbMgr.CheckKvStore();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: InsertDataTest_001
 * @tc.desc: InsertDataTest_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardDbMgrTest, InsertDataTest_001, TestSize.Level1)
{
    std::vector<AgentCard> cards;
    AgentCardDbMgr agentCardDbMgr;
    int ret = agentCardDbMgr.InsertData("test", 100, cards);
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DeleteDataTest_001
 * @tc.desc: DeleteDataTest_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardDbMgrTest, DeleteDataTest_001, TestSize.Level1)
{
    AgentCardDbMgr agentCardDbMgr;
    int ret = agentCardDbMgr.DeleteData("test", 100);
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: QueryDataTest_001
 * @tc.desc: QueryDataTest_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardDbMgrTest, QueryDataTest_001, TestSize.Level1)
{
    std::vector<AgentCard> cards;
    AgentCardDbMgr agentCardDbMgr;
    int ret = agentCardDbMgr.QueryData("test", 100, cards);
    EXPECT_TRUE(ret != ERR_OK);
}
} // namespace AgentRuntime
} // namespace OHOS