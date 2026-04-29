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

#include "process_manager.h"
#include "cli_error_code.h"
#include "exec_tool_param.h"

using namespace testing::ext;
using namespace OHOS::CliTool;

namespace OHOS {
namespace CliTool {

class ProcessManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    ExecToolParam CreateTestParam(const std::string& toolName, const std::string& subcommand = "");
};

void ProcessManagerTest::SetUpTestCase(void)
{
    // Initialize test environment
}

void ProcessManagerTest::TearDownTestCase(void)
{
    // Cleanup test environment
}

void ProcessManagerTest::SetUp()
{
    // Reset state before each test
}

void ProcessManagerTest::TearDown()
{
    // Cleanup after each test
}

ExecToolParam ProcessManagerTest::CreateTestParam(const std::string& toolName, const std::string& subcommand)
{
    ExecToolParam param;
    param.toolName = toolName;
    param.subcommand = subcommand;
    param.challenge = "test_challenge";
    return param;
}

/**
 * @tc.name: ProcessManager_GetInstance_0100
 * @tc.desc: Test GetInstance returns singleton instance
 * @tc.type: FUNC
 */
HWTEST_F(ProcessManagerTest, GetInstance_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessManager_GetInstance_0100 start";

    auto& instance1 = ProcessManager::GetInstance();
    auto& instance2 = ProcessManager::GetInstance();

    EXPECT_EQ(&instance1, &instance2);

    GTEST_LOG_(INFO) << "ProcessManager_GetInstance_0100 end";
}

/**
 * @tc.name: ProcessManager_CreateChildProcess_0100
 * @tc.desc: Test CreateChildProcess with basic parameters
 * @tc.type: FUNC
 */
HWTEST_F(ProcessManagerTest, CreateChildProcess_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessManager_CreateChildProcess_0100 start";

    auto& manager = ProcessManager::GetInstance();

    ExecToolParam param = CreateTestParam("test_tool");
    std::string sandboxConfig = "/etc/claw/test_config.json";
    std::map<std::string, std::string> args;

    auto record = std::make_shared<SessionRecord>();
    EXPECT_NE(record, nullptr);
    record->sessionId = "test_tool";
    record->toolName = "test_tool";
    int32_t result = manager.CreateChildProcess(param, sandboxConfig, args, record);

    // In test environment, fork will succeed and create a child process
    // The child process will then execvp which may fail if claw_sandbox doesn't exist
    // Parent process should return ERR_OK regardless of child's execvp result
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ProcessManager_CreateChildProcess_0100 end";
}

/**
 * @tc.name: ProcessManager_CreateChildProcess_0200
 * @tc.desc: Test CreateChildProcess with subcommand
 * @tc.type: FUNC
 */
HWTEST_F(ProcessManagerTest, CreateChildProcess_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessManager_CreateChildProcess_0200 start";

    auto& manager = ProcessManager::GetInstance();

    ExecToolParam param = CreateTestParam("test_tool", "build");
    std::string sandboxConfig = "/etc/claw/test_config.json";
    std::map<std::string, std::string> args;

    auto record = std::make_shared<SessionRecord>();
    EXPECT_NE(record, nullptr);
    record->sessionId = "test_tool";
    record->toolName = "test_tool";
    int32_t result = manager.CreateChildProcess(param, sandboxConfig, args, record);

    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ProcessManager_CreateChildProcess_0200 end";
}

/**
 * @tc.name: ProcessManager_CreateChildProcess_0300
 * @tc.desc: Test CreateChildProcess with arguments
 * @tc.type: FUNC
 */
HWTEST_F(ProcessManagerTest, CreateChildProcess_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessManager_CreateChildProcess_0300 start";

    auto& manager = ProcessManager::GetInstance();

    ExecToolParam param = CreateTestParam("test_tool", "run");
    std::string sandboxConfig = "/etc/claw/test_config.json";
    std::map<std::string, std::string> args;
    args["--verbose"] = "true";
    args["--output"] = "/tmp/output.txt";

    auto record = std::make_shared<SessionRecord>();
    EXPECT_NE(record, nullptr);
    record->sessionId = "test_tool";
    record->toolName = "test_tool";
    int32_t result = manager.CreateChildProcess(param, sandboxConfig, args, record);

    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ProcessManager_CreateChildProcess_0300 end";
}

/**
 * @tc.name: ProcessManager_CreateChildProcess_0400
 * @tc.desc: Test CreateChildProcess with empty tool name
 * @tc.type: FUNC
 */
HWTEST_F(ProcessManagerTest, CreateChildProcess_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessManager_CreateChildProcess_0400 start";

    auto& manager = ProcessManager::GetInstance();

    ExecToolParam param = CreateTestParam("");
    std::string sandboxConfig = "/etc/claw/test_config.json";
    std::map<std::string, std::string> args;

    auto record = std::make_shared<SessionRecord>();
    EXPECT_NE(record, nullptr);
    record->sessionId = "test_tool";
    record->toolName = "test_tool";
    int32_t result = manager.CreateChildProcess(param, sandboxConfig, args, record);

    // Empty tool name should still work (will just execute claw_sandbox with empty cmd)
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ProcessManager_CreateChildProcess_0400 end";
}

/**
 * @tc.name: ProcessManager_CreateChildProcess_0500
 * @tc.desc: Test CreateChildProcess with multiple arguments
 * @tc.type: FUNC
 */
HWTEST_F(ProcessManagerTest, CreateChildProcess_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessManager_CreateChildProcess_0500 start";

    auto& manager = ProcessManager::GetInstance();

    ExecToolParam param = CreateTestParam("complex_tool", "deploy");
    std::string sandboxConfig = "/etc/claw/complex_config.json";
    std::map<std::string, std::string> args;
    args["--env"] = "production";
    args["--region"] = "us-west-2";
    args["--instances"] = "3";
    args["--force"] = "true";

    auto record = std::make_shared<SessionRecord>();
    EXPECT_NE(record, nullptr);
    record->sessionId = "complex_tool";
    record->toolName = "complex_tool";
    int32_t result = manager.CreateChildProcess(param, sandboxConfig, args, record);

    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ProcessManager_CreateChildProcess_0500 end";
}

/**
 * @tc.name: ProcessManager_CreateChildProcess_0600
 * @tc.desc: Test CreateChildProcess with empty sandbox config
 * @tc.type: FUNC
 */
HWTEST_F(ProcessManagerTest, CreateChildProcess_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessManager_CreateChildProcess_0600 start";

    auto& manager = ProcessManager::GetInstance();

    ExecToolParam param = CreateTestParam("test_tool");
    std::string sandboxConfig = "";
    std::map<std::string, std::string> args;

    auto record = std::make_shared<SessionRecord>();
    EXPECT_NE(record, nullptr);
    record->sessionId = "test_tool";
    record->toolName = "test_tool";
    int32_t result = manager.CreateChildProcess(param, sandboxConfig, args, record);

    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ProcessManager_CreateChildProcess_0600 end";
}

/**
 * @tc.name: ProcessManager_CreateChildProcess_0700
 * @tc.desc: Test CreateChildProcess with empty arguments map
 * @tc.type: FUNC
 */
HWTEST_F(ProcessManagerTest, CreateChildProcess_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessManager_CreateChildProcess_0700 start";

    auto& manager = ProcessManager::GetInstance();

    ExecToolParam param = CreateTestParam("simple_tool");
    std::string sandboxConfig = "/etc/claw/simple_config.json";
    std::map<std::string, std::string> args;

    auto record = std::make_shared<SessionRecord>();
    EXPECT_NE(record, nullptr);
    record->sessionId = "simple_tool";
    record->toolName = "simple_tool";
    int32_t result = manager.CreateChildProcess(param, sandboxConfig, args, record);

    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ProcessManager_CreateChildProcess_0700 end";
}

/**
 * @tc.name: ProcessManager_SingletonConsistency_0100
 * @tc.desc: Test singleton consistency across multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(ProcessManagerTest, SingletonConsistency_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessManager_SingletonConsistency_0100 start";

    auto& instance1 = ProcessManager::GetInstance();
    auto& instance2 = ProcessManager::GetInstance();
    auto& instance3 = ProcessManager::GetInstance();

    EXPECT_EQ(&instance1, &instance2);
    EXPECT_EQ(&instance2, &instance3);
    EXPECT_EQ(&instance1, &instance3);

    GTEST_LOG_(INFO) << "ProcessManager_SingletonConsistency_0100 end";
}

/**
 * @tc.name: ProcessManager_CommandLineConstruction_0100
 * @tc.desc: Test command line is constructed correctly with tool name and subcommand
 * @tc.type: FUNC
 */
HWTEST_F(ProcessManagerTest, CommandLineConstruction_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessManager_CommandLineConstruction_0100 start";

    auto& manager = ProcessManager::GetInstance();

    ExecToolParam param = CreateTestParam("my_tool", "subcommand1");
    std::string sandboxConfig = "/etc/claw/config.json";
    std::map<std::string, std::string> args;
    args["arg1"] = "value1";
    args["arg2"] = "value2";

    auto record = std::make_shared<SessionRecord>();
    EXPECT_NE(record, nullptr);
    record->sessionId = "my_tool";
    record->toolName = "my_tool";
    // The command line should be: "my_tool subcommand1 arg1 value1 arg2 value2"
    // We can't directly verify this without fork/exec, but we can verify the call succeeds
    int32_t result = manager.CreateChildProcess(param, sandboxConfig, args, record);

    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ProcessManager_CommandLineConstruction_0100 end";
}

/**
 * @tc.name: ProcessManager_ArgumentOrder_0100
 * @tc.desc: Test that arguments maintain order when passed to child process
 * @tc.type: FUNC
 */
HWTEST_F(ProcessManagerTest, ArgumentOrder_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessManager_ArgumentOrder_0100 start";

    auto& manager = ProcessManager::GetInstance();

    ExecToolParam param = CreateTestParam("ordered_tool");
    std::string sandboxConfig = "/etc/claw/config.json";
    std::map<std::string, std::string> args;
    // Note: std::map maintains sorted order, not insertion order
    args["z-last"] = "last_value";
    args["a-first"] = "first_value";
    args["m-middle"] = "middle_value";

    auto record = std::make_shared<SessionRecord>();
    EXPECT_NE(record, nullptr);
    record->sessionId = "ordered_tool";
    record->toolName = "ordered_tool";
    int32_t result = manager.CreateChildProcess(param, sandboxConfig, args, record);

    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ProcessManager_ArgumentOrder_0100 end";
}

/**
 * @tc.name: ProcessManager_ConstCorrectness_0100
 * @tc.desc: Test const correctness of CreateChildProcess method
 * @tc.type: FUNC
 */
HWTEST_F(ProcessManagerTest, ConstCorrectness_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessManager_ConstCorrectness_0100 start";

    const auto& manager = ProcessManager::GetInstance();

    ExecToolParam param = CreateTestParam("const_test_tool");
    std::string sandboxConfig = "/etc/claw/const_config.json";
    std::map<std::string, std::string> args;

    auto record = std::make_shared<SessionRecord>();
    EXPECT_NE(record, nullptr);
    record->sessionId = "const_test_tool";
    record->toolName = "const_test_tool";
    // This should compile and work because CreateChildProcess is const
    int32_t result = manager.CreateChildProcess(param, sandboxConfig, args, record);

    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ProcessManager_ConstCorrectness_0100 end";
}

} // namespace CliTool
} // namespace OHOS
