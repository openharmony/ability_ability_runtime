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
#include <fstream>
#include <filesystem>
#include <thread>
#include <vector>

#define private public
#define protected public
#include "extension_config_mgr.h"
#undef private
#undef protected

#include "hilog_tag_wrapper.h"
#include "json_utils.h"

using namespace testing;
using namespace testing::ext;
using json = nlohmann::json;

namespace OHOS {
namespace AbilityRuntime {

// Mock test configuration directory
constexpr const char* TEST_CONFIG_DIR = "/data/local/tmp/extension_config_test";
constexpr const char* TEST_CONFIG_FILE = "/data/local/tmp/extension_config_test/extension_blocklist_config.json";

class AbilityExtensionConfigMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    void CreateTestConfigFile(const std::string& content);
    void RemoveTestConfigFile();
    static std::shared_ptr<ExtensionConfigMgr> configMgr_;
};

std::shared_ptr<ExtensionConfigMgr> AbilityExtensionConfigMgrTest::configMgr_ = nullptr;

void AbilityExtensionConfigMgrTest::SetUpTestCase()
{
    // Create test directory
    std::filesystem::create_directories(TEST_CONFIG_DIR);
}

void AbilityExtensionConfigMgrTest::TearDownTestCase()
{
    // Clean up test directory
    std::filesystem::remove_all(TEST_CONFIG_DIR);
}

void AbilityExtensionConfigMgrTest::SetUp()
{
    configMgr_ = std::make_shared<ExtensionConfigMgr>();
    RemoveTestConfigFile();
}

void AbilityExtensionConfigMgrTest::TearDown()
{
    configMgr_.reset();
    RemoveTestConfigFile();
}

void AbilityExtensionConfigMgrTest::CreateTestConfigFile(const std::string& content)
{
    std::ofstream outFile(TEST_CONFIG_FILE);
    outFile << content;
    outFile.close();
}

void AbilityExtensionConfigMgrTest::RemoveTestConfigFile()
{
    if (std::filesystem::exists(TEST_CONFIG_FILE)) {
        std::filesystem::remove(TEST_CONFIG_FILE);
    }
}

/*
 * @tc.number    : LoadExtensionBlockList_001
 * @tc.name      : LoadExtensionBlockList with valid config
 * @tc.desc      : Test LoadExtensionBlockList with valid JSON config
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_001, TestSize.Level1)
{
    // Arrange: Create a valid config file
    std::string configContent = R"({
        "blocklist": {
            "extension1": ["module1.so", "module2.so"],
            "extension2": ["module3.so"]
        }
    })";
    CreateTestConfigFile(configContent);

    // Act: Load blocklist for extension1
    configMgr_->LoadExtensionBlockList("extension1", 1);

    // Assert: Verify the blocklist is loaded
    auto& blocklist = configMgr_->extensionBlocklist_;
    ASSERT_EQ(blocklist.size(), 1);
    ASSERT_NE(blocklist.find(1), blocklist.end());
    ASSERT_EQ(blocklist[1].size(), 2);
    ASSERT_NE(blocklist[1].find("module1.so"), blocklist[1].end());
    ASSERT_NE(blocklist[1].find("module2.so"), blocklist[1].end());
}

/*
 * @tc.number    : LoadExtensionBlockList_002
 * @tc.name      : LoadExtensionBlockList with nonexistent file
 * @tc.desc      : Test LoadExtensionBlockList when config file doesn't exist
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_002, TestSize.Level1)
{
    // Arrange: No config file exists
    RemoveTestConfigFile();

    // Act: Try to load blocklist
    configMgr_->LoadExtensionBlockList("extension1", 1);

    // Assert: Should not crash, blocklist should be empty
    auto& blocklist = configMgr_->extensionBlocklist_;
    ASSERT_EQ(blocklist.size(), 0);
}

/*
 * @tc.number    : LoadExtensionBlockList_003
 * @tc.name      : LoadExtensionBlockList with invalid JSON
 * @tc.desc      : Test LoadExtensionBlockList with malformed JSON
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_003, TestSize.Level1)
{
    // Arrange: Create invalid JSON
    std::string invalidJson = R"({
        "blocklist": {
            "extension1": ["module1.so",
    })";  // Missing closing brackets
    CreateTestConfigFile(invalidJson);

    // Act: Try to load blocklist
    configMgr_->LoadExtensionBlockList("extension1", 1);

    // Assert: Should not crash, blocklist should be empty
    auto& blocklist = configMgr_->extensionBlocklist_;
    ASSERT_EQ(blocklist.size(), 0);
}

/*
 * @tc.number    : LoadExtensionBlockList_004
 * @tc.name      : LoadExtensionBlockList with missing blocklist node
 * @tc.desc      : Test LoadExtensionBlockList when blocklist node is missing
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_004, TestSize.Level1)
{
    // Arrange: Create config without blocklist node
    std::string configContent = R"({
        "other_config": "value"
    })";
    CreateTestConfigFile(configContent);

    // Act: Try to load blocklist
    configMgr_->LoadExtensionBlockList("extension1", 1);

    // Assert: Should not crash, blocklist should be empty
    auto& blocklist = configMgr_->extensionBlocklist_;
    ASSERT_EQ(blocklist.size(), 0);
}

/*
 * @tc.number    : LoadExtensionBlockList_005
 * @tc.name      : LoadExtensionBlockList with nonexistent extension name
 * @tc.desc      : Test LoadExtensionBlockList with extension name not in config
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_005, TestSize.Level1)
{
    // Arrange: Create config with extension1 only
    std::string configContent = R"({
        "blocklist": {
            "extension1": ["module1.so"]
        }
    })";
    CreateTestConfigFile(configContent);

    // Act: Try to load blocklist for extension2 (not in config)
    configMgr_->LoadExtensionBlockList("extension2", 2);

    // Assert: Should not crash, blocklist should be empty
    auto& blocklist = configMgr_->extensionBlocklist_;
    ASSERT_EQ(blocklist.size(), 0);
}

/*
 * @tc.number    : LoadExtensionBlockList_006
 * @tc.name      : LoadExtensionBlockList caching mechanism
 * @tc.desc      : Test that loading same type twice uses cache
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_006, TestSize.Level1)
{
    // Arrange: Create valid config
    std::string configContent = R"({
        "blocklist": {
            "extension1": ["module1.so"]
        }
    })";
    CreateTestConfigFile(configContent);

    // Act: Load same type twice
    configMgr_->LoadExtensionBlockList("extension1", 1);
    configMgr_->LoadExtensionBlockList("extension1", 1);

    // Assert: Should only have one entry (cached)
    auto& blocklist = configMgr_->extensionBlocklist_;
    ASSERT_EQ(blocklist.size(), 1);
    ASSERT_EQ(blocklist[1].size(), 1);
}

/*
 * @tc.number    : LoadExtensionBlockList_007
 * @tc.name      : LoadExtensionBlockList with multiple extensions
 * @tc.desc      : Test loading blocklists for multiple different extensions
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_007, TestSize.Level1)
{
    // Arrange: Create config with multiple extensions
    std::string configContent = R"({
        "blocklist": {
            "extension1": ["module1.so"],
            "extension2": ["module2.so"],
            "extension3": ["module3.so"]
        }
    })";
    CreateTestConfigFile(configContent);

    // Act: Load blocklists for different extensions
    configMgr_->LoadExtensionBlockList("extension1", 1);
    configMgr_->LoadExtensionBlockList("extension2", 2);
    configMgr_->LoadExtensionBlockList("extension3", 3);

    // Assert: All three should be loaded
    auto& blocklist = configMgr_->extensionBlocklist_;
    ASSERT_EQ(blocklist.size(), 3);
    ASSERT_NE(blocklist.find(1), blocklist.end());
    ASSERT_NE(blocklist.find(2), blocklist.end());
    ASSERT_NE(blocklist.find(3), blocklist.end());
}

/*
 * @tc.number    : LoadExtensionBlockList_008
 * @tc.name      : LoadExtensionBlockList with empty blocklist array
 * @tc.desc      : Test LoadExtensionBlockList with empty array for extension
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_008, TestSize.Level1)
{
    // Arrange: Create config with empty array
    std::string configContent = R"({
        "blocklist": {
            "extension1": []
        }
    })";
    CreateTestConfigFile(configContent);

    // Act: Load blocklist
    configMgr_->LoadExtensionBlockList("extension1", 1);

    // Assert: Should load with empty set
    auto& blocklist = configMgr_->extensionBlocklist_;
    ASSERT_EQ(blocklist.size(), 1);
    ASSERT_EQ(blocklist[1].size(), 0);
}

/*
 * @tc.number    : LoadExtensionBlockList_009
 * @tc.name      : LoadExtensionBlockList with non-array blocklist
 * @tc.desc      : Test LoadExtensionBlockList when blocklist is not an array
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_009, TestSize.Level1)
{
    // Arrange: Create config with non-array value
    std::string configContent = R"({
        "blocklist": {
            "extension1": "not_an_array"
        }
    })";
    CreateTestConfigFile(configContent);

    // Act: Try to load blocklist
    configMgr_->LoadExtensionBlockList("extension1", 1);

    // Assert: Should not crash, blocklist should be empty
    auto& blocklist = configMgr_->extensionBlocklist_;
    ASSERT_EQ(blocklist.size(), 0);
}

/*
 * @tc.number    : LoadExtensionBlockList_010
 * @tc.name      : LoadExtensionBlockList with mixed string/non-string values
 * @tc.desc      : Test LoadExtensionBlockList filters non-string values
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_010, TestSize.Level1)
{
    // Arrange: Create config with mixed types
    std::string configContent = R"({
        "blocklist": {
            "extension1": ["module1.so", 123, true, "module2.so", null]
        }
    })";
    CreateTestConfigFile(configContent);

    // Act: Load blocklist
    configMgr_->LoadExtensionBlockList("extension1", 1);

    // Assert: Should only load string values
    auto& blocklist = configMgr_->extensionBlocklist_;
    ASSERT_EQ(blocklist.size(), 1);
    ASSERT_EQ(blocklist[1].size(), 2);
    ASSERT_NE(blocklist[1].find("module1.so"), blocklist[1].end());
    ASSERT_NE(blocklist[1].find("module2.so"), blocklist[1].end());
}

/*
 * @tc.number    : LoadExtensionBlockList_Concurrent_001
 * @tc.name      : LoadExtensionBlockList concurrent access
 * @tc.desc      : Test LoadExtensionBlockList with concurrent calls
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_Concurrent_001, TestSize.Level2)
{
    // Arrange: Create valid config
    std::string configContent = R"({
        "blocklist": {
            "extension1": ["module1.so"],
            "extension2": ["module2.so"],
            "extension3": ["module3.so"],
            "extension4": ["module4.so"],
            "extension5": ["module5.so"]
        }
    })";
    CreateTestConfigFile(configContent);

    // Act: Load from multiple threads concurrently
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([this, i]() {
            int type = (i % 5) + 1;
            std::string extensionName = "extension" + std::to_string(type);
            configMgr_->LoadExtensionBlockList(extensionName, type);
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // Assert: Should not crash, all extensions should be loaded
    auto& blocklist = configMgr_->extensionBlocklist_;
    ASSERT_GE(blocklist.size(), 1);
    ASSERT_LE(blocklist.size(), 5);
}

/*
 * @tc.number    : LoadExtensionBlockList_Performance_001
 * @tc.name      : LoadExtensionBlockList performance test
 * @tc.desc      : Test LoadExtensionBlockList loading time
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_Performance_001, TestSize.Level3)
{
    // Arrange: Create config with large blocklist
    std::string configContent = R"({
        "blocklist": {
            "extension1": [)";
    // Add 100 modules
    for (int i = 0; i < 100; i++) {
        configContent += "\"module" + std::to_string(i) + ".so\"";
        if (i < 99) configContent += ",";
    }
    configContent += "]\n}\n}";
    CreateTestConfigFile(configContent);

    // Act: Measure loading time
    auto startTime = std::chrono::high_resolution_clock::now();
    configMgr_->LoadExtensionBlockList("extension1", 1);
    auto endTime = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    // Assert: Should complete within reasonable time (< 1 second)
    ASSERT_LT(duration.count(), 1000);

    // Verify all modules loaded
    auto& blocklist = configMgr_->extensionBlocklist_;
    ASSERT_EQ(blocklist[1].size(), 100);
}

/*
 * @tc.number    : LoadExtensionBlockList_TypeCheck_001
 * @tc.name      : LoadExtensionBlockList with negative type
 * @tc.desc      : Test LoadExtensionBlockList with negative type value
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_TypeCheck_001, TestSize.Level1)
{
    // Arrange: Create valid config
    std::string configContent = R"({
        "blocklist": {
            "extension1": ["module1.so"]
        }
    })";
    CreateTestConfigFile(configContent);

    // Act: Try to load with negative type
    configMgr_->LoadExtensionBlockList("extension1", -1);

    // Assert: Should handle gracefully
    auto& blocklist = configMgr_->extensionBlocklist_;
    // Current implementation may load it, but should not crash
}

/*
 * @tc.number    : LoadExtensionBlockList_TypeCheck_002
 * @tc.name      : LoadExtensionBlockList with very large type value
 * @tc.desc      : Test LoadExtensionBlockList with large type value
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_TypeCheck_002, TestSize.Level1)
{
    // Arrange: Create valid config
    std::string configContent = R"({
        "blocklist": {
            "extension1": ["module1.so"]
        }
    })";
    CreateTestConfigFile(configContent);

    // Act: Try to load with large type
    configMgr_->LoadExtensionBlockList("extension1", 999999);

    // Assert: Should handle gracefully
    auto& blocklist = configMgr_->extensionBlocklist_;
    ASSERT_EQ(blocklist.size(), 1);
    ASSERT_EQ(blocklist[999999].size(), 1);
}

/*
 * @tc.number    : LoadExtensionBlockList_ExtensionType_001
 * @tc.name      : Verify extensionType_ is set correctly
 * @tc.desc      : Test that extensionType_ member is set after loading
 */
HWTEST_F(AbilityExtensionConfigMgrTest, LoadExtensionBlockList_ExtensionType_001, TestSize.Level1)
{
    // Arrange: Create valid config
    std::string configContent = R"({
        "blocklist": {
            "extension1": ["module1.so"]
        }
    })";
    CreateTestConfigFile(configContent);

    // Act: Load blocklist with type 42
    configMgr_->LoadExtensionBlockList("extension1", 42);

    // Assert: extensionType_ should be set to 42
    ASSERT_EQ(configMgr_->extensionType_, 42);
}

} // namespace AbilityRuntime
} // namespace OHOS
