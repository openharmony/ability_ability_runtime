/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "native_child_process.h"
#include "app_utils.h"
#include "child_process_args_manager.h"

namespace OHOS {
namespace AbilityRuntime {

using namespace testing;
using namespace testing::ext;

class ChildProcessCapiTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    static void OnNativeChildProcessStarted(int errCode, OHIPCRemoteProxy *remoteProxy);
    static void OnNativeChildProcessExit(int32_t pid, int32_t signal);

    void SetUp();
    void TearDown();
};

void ChildProcessCapiTest::SetUpTestCase(void)
{}

void ChildProcessCapiTest::TearDownTestCase(void)
{}

void ChildProcessCapiTest::SetUp(void)
{}

void ChildProcessCapiTest::TearDown(void)
{}

void ChildProcessCapiTest::OnNativeChildProcessStarted(int errCode, OHIPCRemoteProxy *remoteProxy)
{
}

void ChildProcessCapiTest::OnNativeChildProcessExit(int32_t pid, int32_t signal)
{
}

/**
 * @tc.number: OH_Ability_CreateNativeChildProcess_001
 * @tc.desc: Test API OH_Ability_CreateNativeChildProcess works
 * @tc.type: FUNC
 */
HWTEST_F(ChildProcessCapiTest, OH_Ability_CreateNativeChildProcess_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "OH_Ability_CreateNativeChildProcess_001 begin";
    int ret = OH_Ability_CreateNativeChildProcess(nullptr, ChildProcessCapiTest::OnNativeChildProcessStarted);
    EXPECT_EQ(ret, NCP_ERR_INVALID_PARAM);

    ret = OH_Ability_CreateNativeChildProcess("test.so", nullptr);
    EXPECT_EQ(ret, NCP_ERR_INVALID_PARAM);

    ret = OH_Ability_CreateNativeChildProcess("test.so", ChildProcessCapiTest::OnNativeChildProcessStarted);
    if (!AAFwk::AppUtils::GetInstance().IsMultiProcessModel()) {
        EXPECT_EQ(ret, NCP_ERR_SERVICE_ERROR);
        return;
    } else if (!AAFwk::AppUtils::GetInstance().IsSupportNativeChildProcess()) {
        EXPECT_EQ(ret, NCP_ERR_MULTI_PROCESS_DISABLED);
        return;
    }

    GTEST_LOG_(INFO) << "OH_Ability_CreateNativeChildProcess return " << ret;
    EXPECT_NE(ret, NCP_ERR_NOT_SUPPORTED);
}

/**
 * @tc.number: OH_Ability_StartNativeChildProcess_001
 * @tc.desc: Test API OH_Ability_StartNativeChildProcess_001 works
 * @tc.type: FUNC
 */
HWTEST_F(ChildProcessCapiTest, OH_Ability_StartNativeChildProcess_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "OH_Ability_StartNativeChildProcess_001 begin";
    NativeChildProcess_Args args;
    NativeChildProcess_Options options;
    int32_t pid = 0;
    auto ret = OH_Ability_StartNativeChildProcess(nullptr, args, options, &pid);
    EXPECT_EQ(ret, NCP_ERR_INVALID_PARAM);
    GTEST_LOG_(INFO) << "OH_Ability_StartNativeChildProcess_001 begin";
}

/**
 * @tc.number: OH_Ability_RegisterNativeChildProcessExitCallback_001
 * @tc.desc: Test API OH_Ability_RegisterNativeChildProcessExitCallback_001 works
 * @tc.type: FUNC
 */
HWTEST_F(ChildProcessCapiTest, OH_Ability_RegisterNativeChildProcessExitCallback_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OH_Ability_RegisterNativeChildProcessExitCallback_001 begin";
    auto ret = OH_Ability_RegisterNativeChildProcessExitCallback(nullptr);
    EXPECT_EQ(ret, NCP_ERR_INVALID_PARAM);
    ret = OH_Ability_RegisterNativeChildProcessExitCallback(ChildProcessCapiTest::OnNativeChildProcessExit);
    EXPECT_EQ(ret, NCP_ERR_INTERNAL);
    ret = OH_Ability_UnregisterNativeChildProcessExitCallback(ChildProcessCapiTest::OnNativeChildProcessExit);
    EXPECT_EQ(ret, NCP_ERR_INTERNAL);
    GTEST_LOG_(INFO) << "OH_Ability_RegisterNativeChildProcessExitCallback_001 end";
}

/**
 * @tc.number: OH_Ability_UnregisterNativeChildProcessExitCallback_001
 * @tc.desc: Test API OH_Ability_UnregisterNativeChildProcessExitCallback_001 works
 * @tc.type: FUNC
 */
HWTEST_F(ChildProcessCapiTest, OH_Ability_UnregisterNativeChildProcessExitCallback_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OH_Ability_UnregisterNativeChildProcessExitCallback_001 begin";
    auto ret = OH_Ability_UnregisterNativeChildProcessExitCallback(nullptr);
    EXPECT_EQ(ret, NCP_ERR_INVALID_PARAM);
    ret = OH_Ability_UnregisterNativeChildProcessExitCallback(ChildProcessCapiTest::OnNativeChildProcessExit);
    EXPECT_EQ(ret, NCP_ERR_CALLBACK_NOT_EXIST);
    GTEST_LOG_(INFO) << "OH_Ability_UnregisterNativeChildProcessExitCallback_001 end";
}

/**
 * @tc.number: OH_Ability_GetCurrentChildProcessArgs_001
 * @tc.desc: Test API OH_Ability_GetCurrentChildProcessArgs_001 works
 * @tc.type: FUNC
 */
HWTEST_F(ChildProcessCapiTest, OH_Ability_GetCurrentChildProcessArgs_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "OH_Ability_GetCurrentChildProcessArgs_001 begin";
    EXPECT_EQ(OH_Ability_GetCurrentChildProcessArgs(), nullptr);
    NativeChildProcess_Args args = { 0 };
    ChildProcessArgsManager::GetInstance().SetChildProcessArgs(args);
    EXPECT_NE(OH_Ability_GetCurrentChildProcessArgs(), nullptr);
    GTEST_LOG_(INFO) << "OH_Ability_GetCurrentChildProcessArgs_001 end";
}
}  // namespace AbilityRuntime
}  // namespace OHOS
