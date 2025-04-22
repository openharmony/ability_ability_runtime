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
#include "ability_manager_errors.h"
#include "app_native_spawn_manager.h"
#include "native_child_notify_proxy.h"
#include "hilog_tag_wrapper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class AppNativeSpawnManagerTest : public testing::Test {
public:
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<AppRunningManager> appRunningManager_ = nullptr;
};

void AppNativeSpawnManagerTest::SetUp()
{
    appRunningManager_ = std::make_shared<AppRunningManager>();
    AppNativeSpawnManager::GetInstance().InitNativeSpawnMsgPipe(appRunningManager_);
}

void AppNativeSpawnManagerTest::TearDown()
{
}

/**
 * @tc.number: AppNativeSpawnManagerTest_RegisterNativeChildExitNotify_0100
 * @tc.desc: Test RegisterNativeChildExitNotify works
 * @tc.type: FUNC
 * @tc.Function: RegisterNativeChildExitNotify
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppNativeSpawnManagerTest, AppNativeSpawnManagerTest_RegisterNativeChildExitNotify_0100, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppNativeSpawnManagerTest_RegisterNativeChildExitNotify_0100 start.");
    sptr<INativeChildNotify> notify;
    auto ret = AppNativeSpawnManager::GetInstance().RegisterNativeChildExitNotify(notify);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    notify = sptr<NativeChildNotifyProxy>::MakeSptr(nullptr);
    ret = AppNativeSpawnManager::GetInstance().RegisterNativeChildExitNotify(notify);
    EXPECT_EQ(ret, OHOS::AAFwk::ERR_CALLER_NOT_EXISTS);
}

/**
 * @tc.number: AppNativeSpawnManagerTest_UnregisterNativeChildExitNotify_0200
 * @tc.desc: Test UnregisterNativeChildExitNotify works
 * @tc.type: FUNC
 * @tc.Function: UnregisterNativeChildExitNotify
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppNativeSpawnManagerTest, AppNativeSpawnManagerTest_UnregisterNativeChildExitNotify_0200, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppNativeSpawnManagerTest_UnregisterNativeChildExitNotify_0200 start.");
    sptr<INativeChildNotify> notify;
    auto ret = AppNativeSpawnManager::GetInstance().UnregisterNativeChildExitNotify(notify);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    notify = sptr<NativeChildNotifyProxy>::MakeSptr(nullptr);
    ret = AppNativeSpawnManager::GetInstance().UnregisterNativeChildExitNotify(notify);
    EXPECT_EQ(ret, OHOS::AAFwk::ERR_INVALID_CALLER);
}

/**
 * @tc.number: AppNativeSpawnManagerTest_GetNativeChildCallbackByPid_0300
 * @tc.desc: Test UnregisterNativeChildExitNotify works
 * @tc.type: FUNC
 * @tc.Function: UnregisterNativeChildExitNotify
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppNativeSpawnManagerTest, AppNativeSpawnManagerTest_GetNativeChildCallbackByPid_0300, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppNativeSpawnManagerTest_GetNativeChildCallbackByPid_0300 start.");
    int32_t pid = 1;
    auto notify = AppNativeSpawnManager::GetInstance().GetNativeChildCallbackByPid(pid);
    EXPECT_EQ(notify, nullptr);
}


/**
 * @tc.number: AppNativeSpawnManagerTest_RemoveNativeChildCallbackByPid_0400
 * @tc.desc: Test RemoveNativeChildCallbackByPid works
 * @tc.type: FUNC
 * @tc.Function: RemoveNativeChildCallbackByPid
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppNativeSpawnManagerTest, AppNativeSpawnManagerTest_RemoveNativeChildCallbackByPid_0400, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppNativeSpawnManagerTest_RemoveNativeChildCallbackByPid_0400 start.");
    int32_t pid = 1;
    AppNativeSpawnManager::GetInstance().RemoveNativeChildCallbackByPid(pid);
    auto notify = AppNativeSpawnManager::GetInstance().GetNativeChildCallbackByPid(pid);
    EXPECT_EQ(notify, nullptr);
}

/**
 * @tc.number: AppNativeSpawnManagerTest_ChildRelation_0500
 * @tc.desc: Test ChildRelation works
 * @tc.type: FUNC
 * @tc.Function: ChildRelation
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppNativeSpawnManagerTest, AppNativeSpawnManagerTest_ChildRelation_0500, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "AppNativeSpawnManagerTest_ChildRelation_0500 start.");
    int32_t childPid = 1;
    int32_t parentPid = 2;
    AppNativeSpawnManager::GetInstance().AddChildRelation(childPid, parentPid);
    auto parent = AppNativeSpawnManager::GetInstance().GetChildRelation(childPid);
    EXPECT_EQ(parent, 2);
    AppNativeSpawnManager::GetInstance().RemoveChildRelation(childPid);
    parent = AppNativeSpawnManager::GetInstance().GetChildRelation(childPid);
    EXPECT_EQ(parent, 0);
}


}  // namespace AppExecFwk
}  // namespace OHOS
