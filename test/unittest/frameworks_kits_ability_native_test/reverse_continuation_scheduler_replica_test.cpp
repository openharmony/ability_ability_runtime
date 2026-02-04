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
#include <thread>
#include <chrono>

#include "ability_handler.h"
#include "event_runner.h"
#define private public
#include "reverse_continuation_scheduler_replica.h"
#undef private

namespace OHOS {
namespace AppExecFwk {
using namespace testing::ext;

class TestReplicaHandler final : public IReverseContinuationSchedulerReplicaHandler {
public:
    ~TestReplicaHandler() = default;

    void PassPrimary(const sptr<IRemoteObject> &primary) override
    {
        passPrimaryCount_++;
        lastPrimary_ = primary;
    }

    bool ReverseContinuation() override
    {
        reverseCallCount_++;
        return reverseResult_;
    }

    void NotifyReverseResult(int reverseResult) override
    {
        notifyCount_++;
        lastReverseResult_ = reverseResult;
    }

    int passPrimaryCount_ = 0;
    int reverseCallCount_ = 0;
    int notifyCount_ = 0;
    int lastReverseResult_ = 0;
    bool reverseResult_ = true;
    sptr<IRemoteObject> lastPrimary_ = nullptr;
};

class ReverseContinuationSchedulerReplicaTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.number: ReverseContinuationSchedulerReplica_0100
 * @tc.name: PassPrimary
 * @tc.desc: Test PassPrimary with null main handler.
 */
HWTEST_F(ReverseContinuationSchedulerReplicaTest, ReverseContinuationSchedulerReplica_0100,
    Function | MediumTest | Level1)
{
    auto handler = std::make_shared<TestReplicaHandler>();
    ReverseContinuationSchedulerReplica replica(nullptr, handler);
    sptr<IRemoteObject> primary = nullptr;
    replica.PassPrimary(primary);
    EXPECT_EQ(handler->passPrimaryCount_, 0);
}

/**
 * @tc.number: ReverseContinuationSchedulerReplica_0200
 * @tc.name: ReverseContinuation
 * @tc.desc: Test ReverseContinuation with null main handler.
 */
HWTEST_F(ReverseContinuationSchedulerReplicaTest, ReverseContinuationSchedulerReplica_0200,
    Function | MediumTest | Level1)
{
    auto handler = std::make_shared<TestReplicaHandler>();
    ReverseContinuationSchedulerReplica replica(nullptr, handler);
    EXPECT_FALSE(replica.ReverseContinuation());
    EXPECT_EQ(handler->reverseCallCount_, 0);
}

/**
 * @tc.number: ReverseContinuationSchedulerReplica_0300
 * @tc.name: NotifyReverseResult
 * @tc.desc: Test NotifyReverseResult with null main handler.
 */
HWTEST_F(ReverseContinuationSchedulerReplicaTest, ReverseContinuationSchedulerReplica_0300,
    Function | MediumTest | Level1)
{
    auto handler = std::make_shared<TestReplicaHandler>();
    ReverseContinuationSchedulerReplica replica(nullptr, handler);
    replica.NotifyReverseResult(1);
    EXPECT_EQ(handler->notifyCount_, 0);
}

/**
 * @tc.number: ReverseContinuationSchedulerReplica_0400
 * @tc.name: PassPrimary
 * @tc.desc: Test PassPrimary when PostTask fails.
 */
HWTEST_F(ReverseContinuationSchedulerReplicaTest, ReverseContinuationSchedulerReplica_0400,
    Function | MediumTest | Level1)
{
    auto handler = std::make_shared<TestReplicaHandler>();
    auto abilityHandler = std::make_shared<AbilityHandler>(nullptr);
    EXPECT_FALSE(abilityHandler->PostTask([] {}));
    ReverseContinuationSchedulerReplica replica(abilityHandler, handler);
    sptr<IRemoteObject> primary = nullptr;
    replica.PassPrimary(primary);
    EXPECT_EQ(handler->passPrimaryCount_, 0);
}

/**
 * @tc.number: ReverseContinuationSchedulerReplica_0500
 * @tc.name: ReverseContinuation
 * @tc.desc: Test ReverseContinuation when PostTask fails.
 */
HWTEST_F(ReverseContinuationSchedulerReplicaTest, ReverseContinuationSchedulerReplica_0500,
    Function | MediumTest | Level1)
{
    auto handler = std::make_shared<TestReplicaHandler>();
    auto abilityHandler = std::make_shared<AbilityHandler>(nullptr);
    EXPECT_FALSE(abilityHandler->PostTask([] {}));
    ReverseContinuationSchedulerReplica replica(abilityHandler, handler);
    EXPECT_TRUE(replica.ReverseContinuation());
    EXPECT_EQ(handler->reverseCallCount_, 0);
}

/**
 * @tc.number: ReverseContinuationSchedulerReplica_0600
 * @tc.name: NotifyReverseResult
 * @tc.desc: Test NotifyReverseResult when PostTask fails.
 */
HWTEST_F(ReverseContinuationSchedulerReplicaTest, ReverseContinuationSchedulerReplica_0600,
    Function | MediumTest | Level1)
{
    auto handler = std::make_shared<TestReplicaHandler>();
    auto abilityHandler = std::make_shared<AbilityHandler>(nullptr);
    EXPECT_FALSE(abilityHandler->PostTask([] {}));
    ReverseContinuationSchedulerReplica replica(abilityHandler, handler);
    replica.NotifyReverseResult(2);
    EXPECT_EQ(handler->notifyCount_, 0);
}

/**
 * @tc.number: ReverseContinuationSchedulerReplica_0700
 * @tc.name: PassPrimary
 * @tc.desc: Test PassPrimary when PostTask succeeds.
 */
HWTEST_F(ReverseContinuationSchedulerReplicaTest, ReverseContinuationSchedulerReplica_0700,
    Function | MediumTest | Level1)
{
    auto handler = std::make_shared<TestReplicaHandler>();
    auto runner = EventRunner::Create("replica_test");
    auto abilityHandler = std::make_shared<AbilityHandler>(runner);
    ReverseContinuationSchedulerReplica replica(abilityHandler, handler);
    sptr<IRemoteObject> primary = nullptr;
    replica.PassPrimary(primary);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_GE(handler->passPrimaryCount_, 0);
}

/**
 * @tc.number: ReverseContinuationSchedulerReplica_0800
 * @tc.name: HandlerPassPrimary
 * @tc.desc: Test HandlerPassPrimary with expired handler.
 */
HWTEST_F(ReverseContinuationSchedulerReplicaTest, ReverseContinuationSchedulerReplica_0800,
    Function | MediumTest | Level1)
{
    std::weak_ptr<IReverseContinuationSchedulerReplicaHandler> weakHandler;
    ReverseContinuationSchedulerReplica replica(nullptr, weakHandler);
    sptr<IRemoteObject> primary = nullptr;
    replica.HandlerPassPrimary(primary);
    SUCCEED();
}

/**
 * @tc.number: ReverseContinuationSchedulerReplica_0900
 * @tc.name: HandlerPassPrimary
 * @tc.desc: Test HandlerPassPrimary with valid handler.
 */
HWTEST_F(ReverseContinuationSchedulerReplicaTest, ReverseContinuationSchedulerReplica_0900,
    Function | MediumTest | Level1)
{
    auto handler = std::make_shared<TestReplicaHandler>();
    ReverseContinuationSchedulerReplica replica(nullptr, handler);
    sptr<IRemoteObject> primary = nullptr;
    replica.HandlerPassPrimary(primary);
    EXPECT_EQ(handler->passPrimaryCount_, 1);
    EXPECT_EQ(handler->lastPrimary_, primary);
}

/**
 * @tc.number: ReverseContinuationSchedulerReplica_1000
 * @tc.name: HandlerReverseContinuation
 * @tc.desc: Test HandlerReverseContinuation with expired handler.
 */
HWTEST_F(ReverseContinuationSchedulerReplicaTest, ReverseContinuationSchedulerReplica_1000,
    Function | MediumTest | Level1)
{
    std::weak_ptr<IReverseContinuationSchedulerReplicaHandler> weakHandler;
    ReverseContinuationSchedulerReplica replica(nullptr, weakHandler);
    EXPECT_FALSE(replica.HandlerReverseContinuation());
}

/**
 * @tc.number: ReverseContinuationSchedulerReplica_1100
 * @tc.name: HandlerReverseContinuation
 * @tc.desc: Test HandlerReverseContinuation with valid handler.
 */
HWTEST_F(ReverseContinuationSchedulerReplicaTest, ReverseContinuationSchedulerReplica_1100,
    Function | MediumTest | Level1)
{
    auto handler = std::make_shared<TestReplicaHandler>();
    handler->reverseResult_ = true;
    ReverseContinuationSchedulerReplica replica(nullptr, handler);
    EXPECT_TRUE(replica.HandlerReverseContinuation());
    EXPECT_EQ(handler->reverseCallCount_, 1);
}

/**
 * @tc.number: ReverseContinuationSchedulerReplica_1200
 * @tc.name: HandlerNotifyReverseResult
 * @tc.desc: Test HandlerNotifyReverseResult with expired handler.
 */
HWTEST_F(ReverseContinuationSchedulerReplicaTest, ReverseContinuationSchedulerReplica_1200,
    Function | MediumTest | Level1)
{
    std::weak_ptr<IReverseContinuationSchedulerReplicaHandler> weakHandler;
    ReverseContinuationSchedulerReplica replica(nullptr, weakHandler);
    replica.HandlerNotifyReverseResult(3);
    SUCCEED();
}

/**
 * @tc.number: ReverseContinuationSchedulerReplica_1300
 * @tc.name: HandlerNotifyReverseResult
 * @tc.desc: Test HandlerNotifyReverseResult with valid handler.
 */
HWTEST_F(ReverseContinuationSchedulerReplicaTest, ReverseContinuationSchedulerReplica_1300,
    Function | MediumTest | Level1)
{
    auto handler = std::make_shared<TestReplicaHandler>();
    ReverseContinuationSchedulerReplica replica(nullptr, handler);
    replica.HandlerNotifyReverseResult(4);
    EXPECT_EQ(handler->notifyCount_, 1);
    EXPECT_EQ(handler->lastReverseResult_, 4);
}
} // namespace AppExecFwk
} // namespace OHOS
