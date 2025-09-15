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
#define protected public
#include "load_ability_callback_manager.h"
#undef private
#undef protected
#include "hilog_tag_wrapper.h"
#include "mock_load_ability_callback.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::AbilityRuntime;
namespace OHOS {
namespace AppExecFwk {
class LoadAbilityCallbackManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void LoadAbilityCallbackManagerTest::SetUpTestCase(void)
{
    LoadAbilityCallbackManager::GetInstance().callbacks_.clear();
}
void LoadAbilityCallbackManagerTest::TearDownTestCase(void) {}
void LoadAbilityCallbackManagerTest::TearDown() {}
void LoadAbilityCallbackManagerTest::SetUp() {}

/**
 * @tc.name: AddLoadAbilityCallback_0001
 * @tc.desc: Test AddLoadAbilityCallback
 * @tc.type: FUNC
 */
HWTEST_F(LoadAbilityCallbackManagerTest, AddLoadAbilityCallback_0001, TestSize.Level1)
{
    uint64_t callbackId = 0;
    auto ret = LoadAbilityCallbackManager::GetInstance().AddLoadAbilityCallback(callbackId, nullptr);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: AddLoadAbilityCallback_0002
 * @tc.desc: Test AddLoadAbilityCallback
 * @tc.type: FUNC
 */
HWTEST_F(LoadAbilityCallbackManagerTest, AddLoadAbilityCallback_0002, TestSize.Level1)
{
    uint64_t callbackId = 1234;
    auto ret = LoadAbilityCallbackManager::GetInstance().AddLoadAbilityCallback(callbackId, nullptr);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: AddLoadAbilityCallback_0003
 * @tc.desc: Test AddLoadAbilityCallback
 * @tc.type: FUNC
 */
HWTEST_F(LoadAbilityCallbackManagerTest, AddLoadAbilityCallback_0003, TestSize.Level1)
{
    uint64_t callbackId = 1234;
    OnFinishTask task = [](int32_t pid) {};
    auto mockCallback = sptr<MockLoadAbilityCallback>::MakeSptr(std::move(task));
    auto ret = LoadAbilityCallbackManager::GetInstance().AddLoadAbilityCallback(callbackId, mockCallback);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(LoadAbilityCallbackManager::GetInstance().callbacks_.empty());
}

/**
 * @tc.name: LoadAbilityCallbackManagerTest_RemoveCallback_0001
 * @tc.desc: Test the state of Cancel
 * @tc.type: FUNC
 */
HWTEST_F(LoadAbilityCallbackManagerTest, RemoveCallback_0001, TestSize.Level1)
{
    auto ret = LoadAbilityCallbackManager::GetInstance().RemoveCallback(nullptr);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: LoadAbilityCallbackManagerTest_RemoveCallback_0002
 * @tc.desc: Test the state of Cancel
 * @tc.type: FUNC
 */
HWTEST_F(LoadAbilityCallbackManagerTest, RemoveCallback_0002, TestSize.Level1)
{
    uint64_t callbackId = 1234;
    OnFinishTask task = [](int32_t pid) {};
    auto mockCallback = sptr<MockLoadAbilityCallback>::MakeSptr(std::move(task));

    auto ret = LoadAbilityCallbackManager::GetInstance().RemoveCallback(mockCallback);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: LoadAbilityCallbackManagerTest_RemoveCallback_0003
 * @tc.desc: Test the state of Cancel
 * @tc.type: FUNC
 */
HWTEST_F(LoadAbilityCallbackManagerTest, RemoveCallback_0003, TestSize.Level1)
{
    uint64_t callbackId = 1234;
    OnFinishTask task = [](int32_t pid) {};
    auto mockCallback = sptr<MockLoadAbilityCallback>::MakeSptr(std::move(task));

    auto ret = LoadAbilityCallbackManager::GetInstance().AddLoadAbilityCallback(callbackId, mockCallback);
    EXPECT_EQ(ret, ERR_OK);
    ret = LoadAbilityCallbackManager::GetInstance().RemoveCallback(mockCallback);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(LoadAbilityCallbackManager::GetInstance().callbacks_.empty());
}

/**
 * @tc.name: LoadAbilityCallbackManagerTest_OnLoadAbilityFinished_0001
 * @tc.desc: Test the state of OnLoadAbilityFinished
 * @tc.type: FUNC
 */
HWTEST_F(LoadAbilityCallbackManagerTest, OnLoadAbilityFinished_0001, TestSize.Level1)
{
    uint64_t callbackId = 1234;
    int32_t pid = 9876;
    LoadAbilityCallbackManager::GetInstance().OnLoadAbilityFinished(callbackId, pid);
    EXPECT_TRUE(LoadAbilityCallbackManager::GetInstance().callbacks_.empty());
}

/**
 * @tc.name: LoadAbilityCallbackManagerTest_OnLoadAbilityFinished_0002
 * @tc.desc: Test the state of OnLoadAbilityFinished
 * @tc.type: FUNC
 */
HWTEST_F(LoadAbilityCallbackManagerTest, OnLoadAbilityFinished_0002, TestSize.Level1)
{
    uint64_t callbackId = 1234;
    int32_t pid = 9876;
    bool called = false;
    int32_t targetPid = -1;
    OnFinishTask task = [&called, &targetPid](int32_t pid) {
        called = true;
        targetPid = pid;
    };
    auto mockCallback = sptr<MockLoadAbilityCallback>::MakeSptr(std::move(task));
    auto ret = LoadAbilityCallbackManager::GetInstance().AddLoadAbilityCallback(callbackId, mockCallback);
    EXPECT_EQ(ret, ERR_OK);

    LoadAbilityCallbackManager::GetInstance().OnLoadAbilityFinished(9876, 1234);
    EXPECT_FALSE(called);
    EXPECT_EQ(targetPid, -1);
    EXPECT_FALSE(LoadAbilityCallbackManager::GetInstance().callbacks_.empty());
}

/**
 * @tc.name: LoadAbilityCallbackManagerTest_OnLoadAbilityFinished_0003
 * @tc.desc: Test the state of OnLoadAbilityFinished
 * @tc.type: FUNC
 */
HWTEST_F(LoadAbilityCallbackManagerTest, OnLoadAbilityFinished_0003, TestSize.Level1)
{
    uint64_t callbackId = 1234;
    int32_t pid = 9876;
    bool called = false;
    int32_t targetPid = -1;
    OnFinishTask task = [&called, &targetPid](int32_t pid) {
        called = true;
        targetPid = pid;
    };
    auto mockCallback = sptr<MockLoadAbilityCallback>::MakeSptr(std::move(task));
    auto ret = LoadAbilityCallbackManager::GetInstance().AddLoadAbilityCallback(callbackId, mockCallback);
    EXPECT_EQ(ret, ERR_OK);

    LoadAbilityCallbackManager::GetInstance().OnLoadAbilityFinished(callbackId, pid);
    EXPECT_TRUE(called);
    EXPECT_EQ(targetPid, 9876);
    EXPECT_TRUE(LoadAbilityCallbackManager::GetInstance().callbacks_.empty());
}
} // namespace AAFwk
} // namespace OHOS
