/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include <utility>

#include "ability_business_error_utils.h"
#include "ability_manager_errors.h"
#include "ability_runtime/context.h"
#include "context/context.h"
#include "context/context_impl.h"
#include "context_constant.h"
#include "native_extension/context_impl.h"

namespace OHOS::AbilityRuntime {
namespace {
constexpr const char* DATA_STORAGE = "/data/storage/";
constexpr const char* BASE_CACHE = "/base/cache";
constexpr const char* BASE_TEMP = "/base/temp";
constexpr const char* BASE_FILES = "/base/files";
constexpr const char* BASE_DATABASE = "/base/database";
constexpr const char* BASE_PREFERENCES = "/base/preferences";
constexpr const char* BASE_BUNDLE_CODE = "/base/bundleCode";
constexpr const char* BASE_DISTRIBUTED_FILES = "/base/distributedFiles";
constexpr const char* BASE_CLOUD_FILE = "/base/cloudFile";
constexpr const char* BASE_RESOURCE_DIR = "/base/resources/resfile";
constexpr const char* ENTRY_MODULE_NAME = "entry";
constexpr const char* EL_LIST[] = { "el1", "el2", "el3", "el4", "el5" };
constexpr int32_t BUFFER_SIZE = 1024;
const std::string TEST_BUNDLE_NAME = "com.example.myapplication";
}

using namespace testing;
using namespace testing::ext;

class TestContextImpl final : public ContextImpl {
public:
    explicit TestContextImpl(std::string bundleName) : bundleName_(std::move(bundleName))
    {
        SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL2);
    }

    std::string GetBundleName() const override
    {
        return bundleName_;
    }

    std::string GetCacheDir() override
    {
        std::string dir;
        dir.append(DATA_STORAGE);
        dir.append(areaMode_);
        dir.append(BASE_CACHE);
        return dir;
    }

    std::string GetTempDir() override
    {
        std::string dir;
        dir.append(DATA_STORAGE);
        dir.append(areaMode_);
        dir.append(BASE_TEMP);
        return dir;
    }

    std::string GetFilesDir() override
    {
        std::string dir;
        dir.append(DATA_STORAGE);
        dir.append(areaMode_);
        dir.append(BASE_FILES);
        return dir;
    }

    std::string GetDatabaseDir() override
    {
        std::string dir;
        dir.append(DATA_STORAGE);
        dir.append(areaMode_);
        dir.append(BASE_DATABASE);
        return dir;
    }

    std::string GetPreferencesDir() override
    {
        std::string dir;
        dir.append(DATA_STORAGE);
        dir.append(areaMode_);
        dir.append(BASE_PREFERENCES);
        return dir;
    }

    std::string GetBundleCodeDir() override
    {
        std::string dir;
        dir.append(DATA_STORAGE);
        dir.append(areaMode_);
        dir.append(BASE_BUNDLE_CODE);
        return dir;
    }

    std::string GetDistributedFilesDir() override
    {
        std::string dir;
        dir.append(DATA_STORAGE);
        dir.append(areaMode_);
        dir.append(BASE_DISTRIBUTED_FILES);
        return dir;
    }

    std::string GetCloudFileDir() override
    {
        std::string dir;
        dir.append(DATA_STORAGE);
        dir.append(areaMode_);
        dir.append(BASE_CLOUD_FILE);
        return dir;
    }

    std::string GetResourceDir(const std::string &moduleName = "") override
    {
        std::string dir;
        dir.append(DATA_STORAGE);
        dir.append(areaMode_);
        dir.append(BASE_RESOURCE_DIR);
        return dir;
    }

    void SwitchArea(const int32_t mode) override
    {
        if (mode < 0 || mode >= std::size(EL_LIST)) {
            return;
        }
        areaMode_ = EL_LIST[mode];
    }

    int32_t GetArea() override
    {
        int32_t mode = -1;
        for (int i = 0; i < std::size(EL_LIST); i++) {
            if (areaMode_ == EL_LIST[i]) {
                mode = i;
                break;
            }
        }
        if (mode == -1) {
            return EL_DEFAULT;
        }
        return mode;
    }

    std::string GetProcessName() override
    {
        std::string processName;
        processName.append(bundleName_);
        processName.append(ENTRY_MODULE_NAME);
        return processName;
    }

private:
    std::string bundleName_;
    std::string areaMode_;
};

class CapiAbilityRuntimeContextTest : public Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    AbilityRuntime_ContextHandle context = new AbilityRuntime_Context;
    static std::shared_ptr<Context> sharedContext = std::make_shared<TestContextImpl>(TEST_BUNDLE_NAME);
};

void CapiAbilityRuntimeContextTest::SetUpTestCase()
{
}

void CapiAbilityRuntimeContextTest::TearDownTestCase()
{
}

void CapiAbilityRuntimeContextTest::SetUp()
{
}

void CapiAbilityRuntimeContextTest::TearDown()
{
    context->context.reset();
}

/**
 * @tc.number: OH_AbilityRuntime_Context_GetCacheDir_Test
 * @tc.desc: Function test with OH_AbilityRuntime_Context_GetCacheDir
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeContextTest, OH_AbilityRuntime_Context_GetCacheDir_Test, TestSize.Level2)
{
    char buffer[BUFFER_SIZE];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_Context_GetCacheDir(nullptr,
        buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetCacheDir(context, nullptr, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetCacheDir(context, buffer, BUFFER_SIZE, nullptr);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetCacheDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);

    context->context = sharedContext;
    code = OH_AbilityRuntime_Context_GetCacheDir(context, buffer, 0, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetCacheDir(context, buffer, -1, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);

    std::string cacheDir = sharedContext->GetCacheDir();
    code = OH_AbilityRuntime_Context_GetCacheDir(context, buffer, cacheDir.length(), &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetCacheDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(writeLength, cacheDir.length());
    EXPECT_STREQ(buffer, cacheDir.c_str());
}

/**
 * @tc.number: OH_AbilityRuntime_Context_GetTempDir_Test
 * @tc.desc: Function test with OH_AbilityRuntime_Context_GetTempDir
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeContextTest, OH_AbilityRuntime_Context_GetTempDir_Test, TestSize.Level2)
{
    char buffer[BUFFER_SIZE];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_Context_GetTempDir(nullptr,
        buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetTempDir(context, nullptr, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetTempDir(context, buffer, BUFFER_SIZE, nullptr);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetTempDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);

    context->context = sharedContext;
    code = OH_AbilityRuntime_Context_GetTempDir(context, buffer, 0, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetTempDir(context, buffer, -1, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);

    std::string tempDir = sharedContext->GetTempDir();
    code = OH_AbilityRuntime_Context_GetTempDir(context, buffer, tempDir.length(), &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetTempDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(writeLength, tempDir.length());
    EXPECT_STREQ(buffer, tempDir.c_str());
}

/**
 * @tc.number: OH_AbilityRuntime_Context_GetFilesDir_Test
 * @tc.desc: Function test with OH_AbilityRuntime_Context_GetFilesDir
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeContextTest, OH_AbilityRuntime_Context_GetFilesDir_Test, TestSize.Level2)
{
    char buffer[BUFFER_SIZE];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_Context_GetFilesDir(nullptr,
        buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetFilesDir(context, nullptr, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetFilesDir(context, buffer, BUFFER_SIZE, nullptr);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetFilesDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);

    context->context = sharedContext;
    code = OH_AbilityRuntime_Context_GetFilesDir(context, buffer, 0, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetFilesDir(context, buffer, -1, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);

    std::string filesDir = sharedContext->GetFilesDir();
    code = OH_AbilityRuntime_Context_GetFilesDir(context, buffer, filesDir.length(), &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetFilesDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(writeLength, filesDir.length());
    EXPECT_STREQ(buffer, filesDir.c_str());
}

/**
 * @tc.number: OH_AbilityRuntime_Context_GetDatabaseDir_Test
 * @tc.desc: Function test with OH_AbilityRuntime_Context_GetDatabaseDir
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeContextTest, OH_AbilityRuntime_Context_GetDatabaseDir_Test, TestSize.Level2)
{
    char buffer[BUFFER_SIZE];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_Context_GetDatabaseDir(nullptr,
        buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetDatabaseDir(context, nullptr, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetDatabaseDir(context, buffer, BUFFER_SIZE, nullptr);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetDatabaseDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);

    context->context = sharedContext;
    code = OH_AbilityRuntime_Context_GetDatabaseDir(context, buffer, 0, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetDatabaseDir(context, buffer, -1, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);

    std::string databaseDir = sharedContext->GetDatabaseDir();
    code = OH_AbilityRuntime_Context_GetDatabaseDir(context, buffer, databaseDir.length(), &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetDatabaseDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(writeLength, databaseDir.length());
    EXPECT_STREQ(buffer, databaseDir.c_str());
}

/**
 * @tc.number: OH_AbilityRuntime_Context_GetPreferencesDir_Test
 * @tc.desc: Function test with OH_AbilityRuntime_Context_GetPreferencesDir
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeContextTest, OH_AbilityRuntime_Context_GetPreferencesDir_Test, TestSize.Level2)
{
    char buffer[BUFFER_SIZE];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_Context_GetPreferencesDir(nullptr,
        buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetPreferencesDir(context, nullptr, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetPreferencesDir(context, buffer, BUFFER_SIZE, nullptr);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetPreferencesDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);

    context->context = sharedContext;
    code = OH_AbilityRuntime_Context_GetPreferencesDir(context, buffer, 0, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetPreferencesDir(context, buffer, -1, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);

    std::string preferencesDir = sharedContext->GetPreferencesDir();
    code = OH_AbilityRuntime_Context_GetPreferencesDir(context, buffer, preferencesDir.length(), &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetPreferencesDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(writeLength, preferencesDir.length());
    EXPECT_STREQ(buffer, preferencesDir.c_str());
}

/**
 * @tc.number: OH_AbilityRuntime_Context_GetBundleCodeDir_Test
 * @tc.desc: Function test with OH_AbilityRuntime_Context_GetBundleCodeDir
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeContextTest, OH_AbilityRuntime_Context_GetBundleCodeDir_Test, TestSize.Level2)
{
    char buffer[BUFFER_SIZE];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_Context_GetBundleCodeDir(nullptr,
        buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetBundleCodeDir(context, nullptr, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetBundleCodeDir(context, buffer, BUFFER_SIZE, nullptr);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetBundleCodeDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);

    context->context = sharedContext;
    code = OH_AbilityRuntime_Context_GetBundleCodeDir(context, buffer, 0, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetBundleCodeDir(context, buffer, -1, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);

    std::string bundleCodeDir = sharedContext->GetBundleCodeDir();
    code = OH_AbilityRuntime_Context_GetBundleCodeDir(context, buffer, bundleCodeDir.length(), &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetBundleCodeDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(writeLength, bundleCodeDir.length());
    EXPECT_STREQ(buffer, bundleCodeDir.c_str());
}

/**
 * @tc.number: OH_AbilityRuntime_Context_GetDistributedFilesDir_Test
 * @tc.desc: Function test with OH_AbilityRuntime_Context_GetDistributedFilesDir
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeContextTest, OH_AbilityRuntime_Context_GetDistributedFilesDir_Test, TestSize.Level2)
{
    char buffer[BUFFER_SIZE];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_Context_GetDistributedFilesDir(nullptr,
        buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetDistributedFilesDir(context, nullptr, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetDistributedFilesDir(context, buffer, BUFFER_SIZE, nullptr);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetDistributedFilesDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);

    context->context = sharedContext;
    code = OH_AbilityRuntime_Context_GetDistributedFilesDir(context, buffer, 0, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetDistributedFilesDir(context, buffer, -1, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);

    std::string distributedFilesDir = sharedContext->GetDistributedFilesDir();
    code = OH_AbilityRuntime_Context_GetDistributedFilesDir(context, buffer,
        distributedFilesDir.length(), &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetDistributedFilesDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(writeLength, distributedFilesDir.length());
    EXPECT_STREQ(buffer, distributedFilesDir.c_str());
}

/**
 * @tc.number: OH_AbilityRuntime_Context_GetResourceDir_Test
 * @tc.desc: Function test with OH_AbilityRuntime_Context_GetResourceDir
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeContextTest, OH_AbilityRuntime_Context_GetResourceDir_Test, TestSize.Level2)
{
    char buffer[BUFFER_SIZE];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_Context_GetResourceDir(nullptr,
        buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetResourceDir(context, nullptr, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetResourceDir(context, buffer, BUFFER_SIZE, nullptr);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetResourceDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);

    context->context = sharedContext;
    code = OH_AbilityRuntime_Context_GetResourceDir(context, buffer, 0, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetResourceDir(context, buffer, -1, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);

    std::string resourceDir = sharedContext->GetResourceDir();
    code = OH_AbilityRuntime_Context_GetResourceDir(context, buffer, resourceDir.length(), &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetResourceDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(writeLength, resourceDir.length());
    EXPECT_STREQ(buffer, resourceDir.c_str());
}

/**
 * @tc.number: OH_AbilityRuntime_Context_GetCloudFileDir_Test
 * @tc.desc: Function test with OH_AbilityRuntime_Context_GetCloudFileDir
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeContextTest, OH_AbilityRuntime_Context_GetCloudFileDir_Test, TestSize.Level2)
{
    char buffer[BUFFER_SIZE];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_Context_GetCloudFileDir(nullptr,
        buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetCloudFileDir(context, nullptr, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetCloudFileDir(context, buffer, BUFFER_SIZE, nullptr);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetCloudFileDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);

    context->context = sharedContext;
    code = OH_AbilityRuntime_Context_GetCloudFileDir(context, buffer, 0, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetCloudFileDir(context, buffer, -1, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);

    std::string cloudFileDir = sharedContext->GetCloudFileDir();
    code = OH_AbilityRuntime_Context_GetCloudFileDir(context, buffer, cloudFileDir.length(), &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetCloudFileDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(writeLength, cloudFileDir.length());
    EXPECT_STREQ(buffer, cloudFileDir.c_str());
}

/**
 * @tc.number: OH_AbilityRuntime_Context_GetLogFileDir_Test
 * @tc.desc: Function test with OH_AbilityRuntime_Context_GetLogFileDir
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeContextTest, OH_AbilityRuntime_Context_GetLogFileDir_Test, TestSize.Level2)
{
    char buffer[BUFFER_SIZE];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_Context_GetLogFileDir(nullptr,
        buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetLogFileDir(context, nullptr, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetLogFileDir(context, buffer, BUFFER_SIZE, nullptr);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetLogFileDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);

    context->context = sharedContext;
    code = OH_AbilityRuntime_Context_GetLogFileDir(context, buffer, 0, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetLogFileDir(context, buffer, -1, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);

    std::string logFileDir = sharedContext->GetLogFileDir();
    code = OH_AbilityRuntime_Context_GetLogFileDir(context, buffer, logFileDir.length(), &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetLogFileDir(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(writeLength, logFileDir.length());
    EXPECT_STREQ(buffer, logFileDir.c_str());
}

/**
 * @tc.number: OH_AbilityRuntime_Context_GetProcessName_Test
 * @tc.desc: Function test with OH_AbilityRuntime_Context_GetProcessName
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeContextTest, OH_AbilityRuntime_Context_GetProcessName_Test, TestSize.Level2)
{
    char buffer[BUFFER_SIZE];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_Context_GetProcessName(nullptr,
        buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetProcessName(context, nullptr, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetProcessName(context, buffer, BUFFER_SIZE, nullptr);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetProcessName(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);

    context->context = sharedContext;
    code = OH_AbilityRuntime_Context_GetProcessName(context, buffer, 0, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetProcessName(context, buffer, -1, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);

    std::string processName = sharedContext->GetProcessName();
    code = OH_AbilityRuntime_Context_GetProcessName(context, buffer, processName.length(), &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    EXPECT_EQ(writeLength, 0);
    code = OH_AbilityRuntime_Context_GetProcessName(context, buffer, BUFFER_SIZE, &writeLength);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(writeLength, processName.length());
    EXPECT_STREQ(buffer, processName.c_str());
}

/**
 * @tc.number: OH_AbilityRuntime_Context_GetAreaMode_Test
 * @tc.desc: Function test with OH_AbilityRuntime_Context_GetAreaMode
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeContextTest, OH_AbilityRuntime_Context_GetAreaMode_Test, TestSize.Level2)
{
    AbilityRuntime_AreaMode mode = ABILITY_RUNTIME_AREA_MODE_EL1;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_Context_GetAreaMode(nullptr, &mode);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetAreaMode(context, nullptr);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_GetAreaMode(context, &mode);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);

    context->context = sharedContext;
    code = OH_AbilityRuntime_Context_GetAreaMode(context, &mode);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    EXPECT_EQ(mode, ABILITY_RUNTIME_AREA_MODE_EL2);
}

/**
 * @tc.number: OH_AbilityRuntime_Context_SetAreaMode_Test
 * @tc.desc: Function test with OH_AbilityRuntime_Context_SetAreaMode
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeContextTest, OH_AbilityRuntime_Context_SetAreaMode_Test, TestSize.Level2)
{
    AbilityRuntime_AreaMode mode = ABILITY_RUNTIME_AREA_MODE_EL1;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_Context_SetAreaMode(nullptr, mode);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    code = OH_AbilityRuntime_Context_SetAreaMode(context, mode);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);

    context->context = sharedContext;
    code = OH_AbilityRuntime_Context_SetAreaMode(context, mode);
    EXPECT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    AbilityRuntime_AreaMode result = static_cast<AbilityRuntime_AreaMode>(sharedContext->GetArea());
    EXPECT_EQ(mode, result);
}
} // namespace OHOS::AbilityRuntime