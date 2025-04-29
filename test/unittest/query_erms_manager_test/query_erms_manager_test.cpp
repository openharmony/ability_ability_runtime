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

#define private public
#include "ability_manager_service.h"
#include "query_erms_manager.h"
#include "query_erms_observer_manager.h"
#undef private
#include "singleton.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using AtomicServiceStartupRule = OHOS::AbilityRuntime::AtomicServiceStartupRule;
namespace OHOS {
namespace AAFwk {
class QueryERMSManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void QueryERMSManagerTest::SetUpTestCase()
{
}

void QueryERMSManagerTest::TearDownTestCase()
{
}

void QueryERMSManagerTest::SetUp()
{
}

void QueryERMSManagerTest::TearDown()
{
}

/*
 * @tc.number: GetInstance_0100
 * @tc.name: GetInstance
 * @tc.desc: Verify GetInstance returns the singleton instance
 */
HWTEST_F(QueryERMSManagerTest, GetInstance_0100, TestSize.Level1)
{
    QueryERMSManager& instance1 = QueryERMSManager::GetInstance();
    QueryERMSManager& instance2 = QueryERMSManager::GetInstance();
    
    // Verify we're getting the same instance
    EXPECT_EQ(&instance1, &instance2);
}

/*
 * @tc.number: HandleOnQueryERMSSuccess_0100
 * @tc.name: HandleOnQueryERMSSuccess
 * @tc.desc: Verify HandleOnQueryERMSSuccess functionality
 */
HWTEST_F(QueryERMSManagerTest, HandleOnQueryERMSSuccess_0100, TestSize.Level1)
{
    int32_t recordId = 1;
    std::string appId = "appId";
    std::string startTime = "12:00";
    AbilityRuntime::AtomicServiceStartupRule rule;
    
    QueryERMSManager::GetInstance().HandleOnQueryERMSSuccess(recordId, appId, startTime, rule);
    EXPECT_EQ(QueryERMSObserverManager::GetInstance().observerMap_.size(), 1);
    EXPECT_NE(QueryERMSObserverManager::GetInstance().observerMap_[recordId], nullptr);
}

/*
 * @tc.number: HandleOnQueryERMSFail_0100
 * @tc.name: HandleOnQueryERMSFail
 * @tc.desc: Verify HandleOnQueryERMSFail functionality
 */
HWTEST_F(QueryERMSManagerTest, HandleOnQueryERMSFail_0100, TestSize.Level1)
{
    int32_t recordId = 1;
    std::string appId = "appId";
    std::string startTime = "12:00";
    AbilityRuntime::AtomicServiceStartupRule rule;
    int resultCode = -1;
    
    QueryERMSManager::GetInstance().HandleOnQueryERMSFail(recordId, appId, startTime, rule, resultCode);
    EXPECT_EQ(QueryERMSObserverManager::GetInstance().observerMap_.size(), 1);
    EXPECT_EQ(QueryERMSObserverManager::GetInstance().observerMap_[recordId], nullptr);
}

/*
 * @tc.number: HandleQueryERMSResult_0100
 * @tc.name: HandleQueryERMSResult
 * @tc.desc: Verify HandleQueryERMSResult with success result code
 */
HWTEST_F(QueryERMSManagerTest, HandleQueryERMSResult_0100, TestSize.Level1)
{
    int32_t recordId = 1;
    std::string appId = "appId";
    std::string startTime = "12:00";
    AbilityRuntime::AtomicServiceStartupRule rule;
    int resultCode = ERR_OK;
    QueryERMSManager::GetInstance().HandleQueryERMSResult(recordId, appId, startTime, rule, resultCode);
    EXPECT_EQ(QueryERMSObserverManager::GetInstance().observerMap_.size(), 1);
    EXPECT_NE(QueryERMSObserverManager::GetInstance().observerMap_[recordId], nullptr);
}

/*
 * @tc.number: HandleQueryERMSResult_0200
 * @tc.name: HandleQueryERMSResult
 * @tc.desc: Verify HandleQueryERMSResult with failure result code
 */
HWTEST_F(QueryERMSManagerTest, HandleQueryERMSResult_0200, TestSize.Level1)
{
    int32_t recordId = 1;
    std::string appId = "appId";
    std::string startTime = "12:00";
    AbilityRuntime::AtomicServiceStartupRule rule;
    int resultCode = -1;
    
    QueryERMSManager::GetInstance().HandleQueryERMSResult(recordId, appId, startTime, rule, resultCode);
    EXPECT_EQ(QueryERMSObserverManager::GetInstance().observerMap_.size(), 1);
    EXPECT_EQ(QueryERMSObserverManager::GetInstance().observerMap_[recordId], nullptr);
}

/*
 * @tc.number: OnQueryFinished_0100
 * @tc.name: OnQueryFinished
 * @tc.desc: Verify OnQueryFinished functionality
 */
HWTEST_F(QueryERMSManagerTest, OnQueryFinished_0100, TestSize.Level1)
{
    int32_t recordId = 1;
    std::string appId = "appId";
    std::string startTime = "12:00";
    AbilityRuntime::AtomicServiceStartupRule rule;
    int resultCode = ERR_OK;
    
    QueryERMSManager::GetInstance().OnQueryFinished(recordId, appId, startTime, rule, resultCode);
    EXPECT_EQ(QueryERMSObserverManager::GetInstance().observerMap_.size(), 1);
    EXPECT_NE(QueryERMSObserverManager::GetInstance().observerMap_[recordId], nullptr);
}

/*
 * @tc.number: AddQueryERMSObserver_0100
 * @tc.name: AddQueryERMSObserver
 * @tc.desc: Verify AddQueryERMSObserver with null token
 */
HWTEST_F(QueryERMSManagerTest, AddQueryERMSObserver_0100, TestSize.Level1)
{
    sptr<IRemoteObject> callerToken = nullptr;
    sptr<AbilityRuntime::IQueryERMSObserver> observer = nullptr;
    int result = QueryERMSManager::GetInstance().AddQueryERMSObserver(callerToken, observer);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

} // namespace AAFwk
} // namespace OHOS