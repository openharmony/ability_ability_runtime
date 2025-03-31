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

#define private public
#include "native_child_ipc_process.h"
#undef private
#include "hilog_tag_wrapper.h"
#include "runtime.h"
#include "mock_bundle_manager.h"
#include "mock_app_mgr_service.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class NativeChildIpcProcessTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void NativeChildIpcProcessTest::SetUpTestCase()
{}

void NativeChildIpcProcessTest::TearDownTestCase()
{}

void NativeChildIpcProcessTest::SetUp()
{}

void NativeChildIpcProcessTest::TearDown()
{}

/**
 * @tc.number: Init_0100
 * @tc.desc: Test NativeChildIpcProcessTest works
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildIpcProcessTest, Init_0100, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "Init_0100 called.");
    auto childProcess = NativeChildIpcProcess::Create();
    EXPECT_TRUE(childProcess != nullptr);
    auto ret = childProcess->Init(nullptr);
    EXPECT_FALSE(ret);
    TAG_LOGD(AAFwkTag::TEST, "Init_0100 end.");
}

/**
 * @tc.number: Init_0200
 * @tc.desc: Test NativeChildIpcProcessTest works
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildIpcProcessTest, Init_0200, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "Init_0200 called. start");
    auto childProcess = NativeChildIpcProcess::Create();
    EXPECT_TRUE(childProcess != nullptr);
    std::shared_ptr<ChildProcessStartInfo> info = std::make_shared<ChildProcessStartInfo>();
    sptr<IRemoteObject> ipcObj = sptr<IRemoteObject>(new (std::nothrow) AppExecFwk::MockAppMgrService());
    info->ipcObj = ipcObj;
    auto ret = childProcess->Init(info);
    EXPECT_FALSE(ret);
    TAG_LOGD(AAFwkTag::TEST, "Init_0200 called. end");
}
/**
 * @tc.number: Init_0300
 * @tc.desc: Test NativeChildIpcProcessTest works
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildIpcProcessTest, Init_0300, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "Init_0300 called.");
    auto childProcess = NativeChildIpcProcess::Create();
    std::shared_ptr<ChildProcessStartInfo> info = std::make_shared<ChildProcessStartInfo>();
    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
    OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    OHOS::sptr<OHOS::IRemoteObject> ipcObj = systemAbilityManager->GetSystemAbility(501);
    info->ipcObj = ipcObj;
    bool ret = childProcess->Init(info);
    EXPECT_FALSE(ret);
    TAG_LOGD(AAFwkTag::TEST, "Init_0300 called. end");
}

/**
 * @tc.number: Init_0400
 * @tc.desc: Test NativeChildIpcProcessTest works
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildIpcProcessTest, Init_0400, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "Init_0400 called.");
    auto childProcess = NativeChildIpcProcess::Create();
    std::shared_ptr<ChildProcessStartInfo> info = std::make_shared<ChildProcessStartInfo>();
    info->name = "AProcess";
    info->moduleName = "entry";
    info->srcEntry = "entry/./ets/process/AProcess.ts";
    info->hapPath = "/data/app/entry-1/base.hap";
    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
    OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    OHOS::sptr<OHOS::IRemoteObject> ipcObj = systemAbilityManager->GetSystemAbility(501);
    info->ipcObj = ipcObj;
    bool ret = childProcess->Init(info);
    EXPECT_FALSE(ret);
    TAG_LOGD(AAFwkTag::TEST, "Init_0400 end.");
}

/**
 * @tc.number: Init_0500
 * @tc.desc: Test NativeChildIpcProcessTest works
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildIpcProcessTest, Init_0500, TestSize.Level0)
{
    TAG_LOGD(AAFwkTag::TEST, "Init_0500 called.");
    auto childProcess = NativeChildIpcProcess::Create();
    std::shared_ptr<ChildProcessStartInfo> info = std::make_shared<ChildProcessStartInfo>();
    info->name = "AProcess";
    info->moduleName = "";
    info->srcEntry = "entry/./ets/process/AProcess.ts";
    info->hapPath = "/data/test/hapPath";
    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
    OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    OHOS::sptr<OHOS::IRemoteObject> ipcObjs = systemAbilityManager->GetSystemAbility(501);
    info->ipcObj = ipcObjs;
    auto ret = childProcess->Init(info);
    EXPECT_FALSE(ret);
    TAG_LOGD(AAFwkTag::TEST, "Init_0500 called. end");
}

/**
 * @tc.number: UnloadNativeLib_0100
 * @tc.desc: Test NativeChildIpcProcessTest works
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildIpcProcessTest, UnloadNativeLib_0100, TestSize.Level2)
{
    TAG_LOGD(AAFwkTag::TEST, "UnloadNativeLib_0100 called.");
    auto childProcess = std::make_shared<NativeChildIpcProcess>();
    childProcess->UnloadNativeLib();
    EXPECT_EQ(nullptr, childProcess->nativeLibHandle_);
    TAG_LOGD(AAFwkTag::TEST, "UnloadNativeLib_0100 end.");
}
} // namespace AbilityRuntime
} // namespace OHOS