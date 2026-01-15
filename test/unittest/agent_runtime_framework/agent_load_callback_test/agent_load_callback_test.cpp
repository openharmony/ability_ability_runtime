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

#include "agent_load_callback.h"
#include "mock_i_remote_object.h"
#include "mock_my_flag.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AgentRuntime;

namespace OHOS {
namespace AgentRuntime {
const int32_t AGENT_MGR_SERVICE_ID = 185;
class AgentLoadCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void AgentLoadCallbackTest::SetUpTestCase(void)
{}

void AgentLoadCallbackTest::TearDownTestCase(void)
{}

void AgentLoadCallbackTest::SetUp(void)
{
    MyFlag::isOnLoadSystemAbilitySuccessCalled = false;
    MyFlag::isOnLoadSystemAbilityFailCalled = false;
}

void AgentLoadCallbackTest::TearDown(void)
{}

/**
* @tc.name  : OnLoadSystemAbilitySuccess_ShouldLogError_WhenSystemAbilityIdMismatch
* @tc.number: OnLoadSystemAbilitySuccess_001
* @tc.desc  : Test the function with a systemAbilityId that does not match AGENT_MGR_SERVICE_ID.
*/
HWTEST_F(AgentLoadCallbackTest, OnLoadSystemAbilitySuccess_001, TestSize.Level1)
{
    AgentLoadCallback callback;
    int32_t invalidSystemAbilityId = AGENT_MGR_SERVICE_ID + 1; // Invalid ID
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockIRemoteObject();

    callback.OnLoadSystemAbilitySuccess(invalidSystemAbilityId, remoteObject);

    EXPECT_FALSE(MyFlag::isOnLoadSystemAbilitySuccessCalled);
}

/**
* @tc.name  : OnLoadSystemAbilitySuccess_ShouldLogError_WhenRemoteObjectIsNull
* @tc.number: OnLoadSystemAbilitySuccess_002
* @tc.desc  : Test the function with a remoteObject that is nullptr.
*/
HWTEST_F(AgentLoadCallbackTest, OnLoadSystemAbilitySuccess_002, TestSize.Level1)
{
    AgentLoadCallback callback;
    int32_t validSystemAbilityId = AGENT_MGR_SERVICE_ID;
    sptr<IRemoteObject> remoteObject = nullptr; // Invalid remote object

    callback.OnLoadSystemAbilitySuccess(validSystemAbilityId, remoteObject);

    EXPECT_FALSE(MyFlag::isOnLoadSystemAbilitySuccessCalled);
}

/**
* @tc.name  : OnLoadSystemAbilitySuccess_ShouldCallAgentManagerClient_WhenSuccess
* @tc.number: OnLoadSystemAbilitySuccess_003
* @tc.desc  : Test the function with a valid systemAbilityId and a non-null remoteObject.
*/
HWTEST_F(AgentLoadCallbackTest, OnLoadSystemAbilitySuccess_003, TestSize.Level1)
{
    AgentLoadCallback callback;
    int32_t validSystemAbilityId = AGENT_MGR_SERVICE_ID;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockIRemoteObject();

    callback.OnLoadSystemAbilitySuccess(validSystemAbilityId, remoteObject);

    EXPECT_TRUE(MyFlag::isOnLoadSystemAbilitySuccessCalled);
}

/**
* @tc.name  : OnLoadSystemAbilityFail_ShouldLogErrorAndReturn_WhenSystemAbilityIdMismatch
* @tc.number: OnLoadSystemAbilityFail_001
* @tc.desc  : Test when the systemAbilityId does not match AGENT_MGR_SERVICE_ID.
*/
HWTEST_F(AgentLoadCallbackTest, OnLoadSystemAbilityFail_001, TestSize.Level1)
{
    AgentLoadCallback callback;
    int32_t mismatchedId = AGENT_MGR_SERVICE_ID + 1; // Any ID that is not AGENT_MGR_SERVICE_ID

    callback.OnLoadSystemAbilityFail(mismatchedId);

    EXPECT_FALSE(MyFlag::isOnLoadSystemAbilityFailCalled);
}

/**
* @tc.name  : OnLoadSystemAbilityFail_ShouldLogDebugAndCallOnLoadSystemAbilityFail_WhenSystemAbilityIdMatches
* @tc.number: OnLoadSystemAbilityFail_002
* @tc.desc  : Test when the systemAbilityId matches AGENT_MGR_SERVICE_ID.
*/
HWTEST_F(AgentLoadCallbackTest, OnLoadSystemAbilityFail_002, TestSize.Level1)
{
    AgentLoadCallback callback;
    int32_t matchedId = AGENT_MGR_SERVICE_ID;

    callback.OnLoadSystemAbilityFail(matchedId);

    EXPECT_TRUE(MyFlag::isOnLoadSystemAbilityFailCalled);
}
} // namespace AgentRuntime
} // namespace OHOS