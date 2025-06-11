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
#include "child_process_args.h"
#include "child_process_configs.h"
#include "child_process_manager_error_utils.h"
#include "mock_child_process_manager.h"
#include "native_child_process.h"
#undef protected
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
namespace {
#ifdef WITH_DLP
const std::string DLP_INDEX = "ohos.dlp.params.index";
#endif // WITH_DLP
constexpr int32_t TEST_UID = 20010001;
};
class NativeChildProcessTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static void MyProcessStartCallback(int errCode, OHIPCRemoteProxy *remoteProxy);
};

void NativeChildProcessTest::SetUpTestCase() {}

void NativeChildProcessTest::TearDownTestCase() {}

void NativeChildProcessTest::SetUp() {}

void NativeChildProcessTest::TearDown() {}

void NativeChildProcessTest::MyProcessStartCallback(int errCode, OHIPCRemoteProxy *remoteProxy)
{
    if (errCode == 0) {
        std::cout << "Child process started successfully." << std::endl;
    } else {
        std::cout << "Failed to start child process, error code: " << errCode << std::endl;
    }
}

/**
 * @tc.name: UIAbilityLifecycleManager_OH_Ability_ChildProcessConfigs_SetProcessName_0100
 * @tc.desc: OH_Ability_ChildProcessConfigs_SetProcessName
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildProcessTest, OH_Ability_ChildProcessConfigs_SetProcessName_001, TestSize.Level1)
{
    Ability_ChildProcessConfigs configs;
    std::string processName = "";
    constexpr int32_t MAX_PROCESS_NAME_LENGTH = 64;
    for (int i = 0; i < MAX_PROCESS_NAME_LENGTH + 10; ++i)
    {
        processName += "A";
    }

    auto ret = OH_Ability_ChildProcessConfigs_SetProcessName(&configs, processName.c_str());

    EXPECT_EQ(ret, NCP_ERR_INVALID_PARAM);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OH_Ability_ChildProcessConfigs_SetProcessName_0200
 * @tc.desc: OH_Ability_ChildProcessConfigs_SetProcessName
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildProcessTest, OH_Ability_ChildProcessConfigs_SetProcessName_002, TestSize.Level1)
{
    Ability_ChildProcessConfigs configs;
    std::string processName = "";
    constexpr int32_t MAX_PROCESS_NAME_LENGTH = 64;
    for (size_t i = 0; i < MAX_PROCESS_NAME_LENGTH + 10; ++i)
    {
        processName += "A";
    }

    auto ret = OH_Ability_ChildProcessConfigs_SetProcessName(&configs, processName.c_str());

    EXPECT_EQ(ret, NCP_ERR_INVALID_PARAM);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OH_Ability_CreateNativeChildProcessWithConfigs_0100
 * @tc.desc: OH_Ability_CreateNativeChildProcessWithConfigs
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildProcessTest, OH_Ability_CreateNativeChildProcessWithConfigs_001, TestSize.Level1)
{
    Ability_ChildProcessConfigs configs;
    std::string libName = "../ABCD/abcd";

    auto ret = OH_Ability_CreateNativeChildProcessWithConfigs(
        libName.c_str(), &configs, &NativeChildProcessTest::MyProcessStartCallback);

    EXPECT_EQ(ret, NCP_ERR_INVALID_PARAM);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OH_Ability_StartNativeChildProcess_0100
 * @tc.desc: OH_Ability_StartNativeChildProcess
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildProcessTest, OH_Ability_StartNativeChildProcess_001, TestSize.Level1)
{
    std::string entry = "HeavenlyMe";
    NativeChildProcess_Args args = {};
    NativeChildProcess_Options options = {};
    int32_t pid = 0;

    auto ret = OH_Ability_StartNativeChildProcess(entry.c_str(), args, options, &pid);

    EXPECT_EQ(ret, NCP_ERR_INVALID_PARAM);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OH_Ability_StartNativeChildProcess_0200
 * @tc.desc: OH_Ability_StartNativeChildProcess
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildProcessTest, OH_Ability_StartNativeChildProcess_002, TestSize.Level1)
{
    std::string entry = ":HeavenlyMe:KON";
    NativeChildProcess_Args args = {};
    NativeChildProcess_Options options = {};

    auto ret = OH_Ability_StartNativeChildProcess(entry.c_str(), args, options, nullptr);

    EXPECT_EQ(ret, NCP_ERR_INVALID_PARAM);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OH_Ability_StartNativeChildProcess_0300
 * @tc.desc: OH_Ability_StartNativeChildProcess
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildProcessTest, OH_Ability_StartNativeChildProcess_003, TestSize.Level1)
{
    std::string entry = ":HeavenlyMe:KON";
    NativeChildProcess_Fd head;
    head.next = nullptr;
    head.fdName = nullptr;
    NativeChildProcess_Args args = {};
    args.fdList.head = &head;
    NativeChildProcess_Options options = {};
    int32_t pid = 0;

    auto ret = OH_Ability_StartNativeChildProcess(entry.c_str(), args, options, &pid);

    EXPECT_EQ(ret, NCP_ERR_INVALID_PARAM);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OH_Ability_StartNativeChildProcess_0400
 * @tc.desc: OH_Ability_StartNativeChildProcess
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildProcessTest, OH_Ability_StartNativeChildProcess_004, TestSize.Level1)
{
    std::string entry = ":HeavenlyMe:KON";
    NativeChildProcess_Args args = {};
    args.fdList.head = nullptr;
    NativeChildProcess_Options options = {};
    int32_t pid = 0;
    auto &instance = AbilityRuntime::ChildProcessManager::GetInstance();
    instance.startErrorCode_ = AbilityRuntime::ChildProcessManagerErrorCode::ERR_OK;

    auto ret = OH_Ability_StartNativeChildProcess(entry.c_str(), args, options, &pid);

    EXPECT_EQ(ret, NCP_NO_ERROR);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OH_Ability_StartNativeChildProcess_0500
 * @tc.desc: OH_Ability_StartNativeChildProcess
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildProcessTest, OH_Ability_StartNativeChildProcess_005, TestSize.Level1)
{
    std::string entry = ":HeavenlyMe:KON";
    NativeChildProcess_Args args = {};
    args.fdList.head = nullptr;
    NativeChildProcess_Options options = {};
    int32_t pid = 0;
    auto &instance = AbilityRuntime::ChildProcessManager::GetInstance();
    instance.startErrorCode_ = AbilityRuntime::ChildProcessManagerErrorCode::ERR_GET_APP_MGR_FAILED;

    auto ret = OH_Ability_StartNativeChildProcess(entry.c_str(), args, options, &pid);

    EXPECT_EQ(ret, NCP_ERR_SERVICE_ERROR);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OH_Ability_StartNativeChildProcessWithConfigs_0100
 * @tc.desc: OH_Ability_StartNativeChildProcessWithConfigs
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildProcessTest, OH_Ability_StartNativeChildProcessWithConfigs_001, TestSize.Level1)
{
    std::string entry = "HeavenlyMe";
    NativeChildProcess_Args args = {};
    args.fdList.head = nullptr;
    Ability_ChildProcessConfigs configs;

    auto ret = OH_Ability_StartNativeChildProcessWithConfigs(entry.c_str(), args, &configs, nullptr);

    EXPECT_EQ(ret, NCP_ERR_INVALID_PARAM);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OH_Ability_StartNativeChildProcessWithConfigs_0200
 * @tc.desc: OH_Ability_StartNativeChildProcessWithConfigs
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildProcessTest, OH_Ability_StartNativeChildProcessWithConfigs_002, TestSize.Level1)
{
    std::string entry = ":HeavenlyMe:KON";
    NativeChildProcess_Args args = {};
    args.fdList.head = nullptr;
    Ability_ChildProcessConfigs configs;

    auto ret = OH_Ability_StartNativeChildProcessWithConfigs(entry.c_str(), args, &configs, nullptr);

    EXPECT_EQ(ret, NCP_ERR_INVALID_PARAM);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OH_Ability_StartNativeChildProcessWithConfigs_0300
 * @tc.desc: OH_Ability_StartNativeChildProcessWithConfigs
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildProcessTest, OH_Ability_StartNativeChildProcessWithConfigs_003, TestSize.Level1)
{
    std::string entry = ":HeavenlyMe:KON";
    NativeChildProcess_Fd head;
    head.fdName = nullptr;
    NativeChildProcess_Args args = {};
    args.fdList.head = &head;
    Ability_ChildProcessConfigs configs;
    int32_t pid = 1;

    auto ret = OH_Ability_StartNativeChildProcessWithConfigs(entry.c_str(), args, &configs, &pid);

    EXPECT_EQ(ret, NCP_ERR_INVALID_PARAM);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OH_Ability_StartNativeChildProcessWithConfigs_0400
 * @tc.desc: OH_Ability_StartNativeChildProcessWithConfigs
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildProcessTest, OH_Ability_StartNativeChildProcessWithConfigs_004, TestSize.Level1)
{
    std::string entry = ":HeavenlyMe:KON";
    NativeChildProcess_Args args = {};
    args.fdList.head = nullptr;
    Ability_ChildProcessConfigs configs;
    int32_t pid = 1;
    auto &instance = AbilityRuntime::ChildProcessManager::GetInstance();
    instance.startErrorCode_ = AbilityRuntime::ChildProcessManagerErrorCode::ERR_OK;

    auto ret = OH_Ability_StartNativeChildProcessWithConfigs(entry.c_str(), args, &configs, &pid);

    EXPECT_EQ(ret, NCP_NO_ERROR);
}

/**
 * @tc.name: UIAbilityLifecycleManager_OH_Ability_StartNativeChildProcessWithConfigs_0500
 * @tc.desc: OH_Ability_StartNativeChildProcessWithConfigs
 * @tc.type: FUNC
 */
HWTEST_F(NativeChildProcessTest, OH_Ability_StartNativeChildProcessWithConfigs_005, TestSize.Level1)
{
    std::string entry = ":HeavenlyMe:KON";
    NativeChildProcess_Args args = {};
    args.fdList.head = nullptr;
    Ability_ChildProcessConfigs configs;
    int32_t pid = 1;
    auto &instance = AbilityRuntime::ChildProcessManager::GetInstance();
    instance.startErrorCode_ = AbilityRuntime::ChildProcessManagerErrorCode::ERR_GET_APP_MGR_FAILED;

    auto ret = OH_Ability_StartNativeChildProcessWithConfigs(entry.c_str(), args, &configs, &pid);

    EXPECT_EQ(ret, NCP_ERR_SERVICE_ERROR);
}
}  // namespace AAFwk
}  // namespace OHOS
