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

#include <utility>
#include "ability_business_error_utils.h"
#include "ability_manager_errors.h"
#include "application_context.h"
#include "context/application_context.h"
#include "securec.h"
#include "start_options_impl.h"
#include "want_manager.h"
#include "want_utils.h"

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

    static void ResetApplicationContext()
    {
        applicationContext_ = nullptr;
    }

private:
    std::string bundleName_;
    std::string areaMode_;
};

class CapiAbilityRuntimeApplicationContextTest : public Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;

protected:
    static void InitApplicationContext();

    static std::shared_ptr<TestContextImpl> InitApplicationContextImpl(const std::string &bundleName);
};

void CapiAbilityRuntimeApplicationContextTest::SetUpTestCase()
{
}

void CapiAbilityRuntimeApplicationContextTest::TearDownTestCase()
{
}

void CapiAbilityRuntimeApplicationContextTest::SetUp()
{
}

void CapiAbilityRuntimeApplicationContextTest::TearDown()
{
    const auto applicationContext = ApplicationContext::GetApplicationContext();
    if (applicationContext != nullptr) {
        applicationContext->AttachContextImpl(nullptr);
        TestContextImpl::ResetApplicationContext();
    }
}

void CapiAbilityRuntimeApplicationContextTest::InitApplicationContext()
{
    ApplicationContext::GetInstance();
}

std::shared_ptr<TestContextImpl> CapiAbilityRuntimeApplicationContextTest::InitApplicationContextImpl(
    const std::string &bundleName)
{
    auto applicationContext = ApplicationContext::GetInstance();
    if (applicationContext != nullptr) {
        auto contextImpl = std::make_shared<TestContextImpl>(bundleName);
        applicationContext->AttachContextImpl(contextImpl);
        return contextImpl;
    }
    return nullptr;
}

/**
 * @tc.number: GetCacheDirTest_001
 * @tc.desc: Function test with applicationContext is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetCacheDirTest_001, TestSize.Level0)
{
    constexpr int32_t bufferSize = 1024;
    char buffer[bufferSize];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetCacheDir(NULL, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(nullptr, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, bufferSize, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, bufferSize, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetCacheDirTest_002
 * @tc.desc: Function test with applicationContextImpl is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetCacheDirTest_002, TestSize.Level0)
{
    InitApplicationContext();
    constexpr int32_t bufferSize = 1024;
    char buffer[bufferSize];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetCacheDir(NULL, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(nullptr, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, bufferSize, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, bufferSize, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetCacheDirTest_003
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetCacheDirTest_003, TestSize.Level0)
{
    constexpr int32_t bufferSize = 1024;
    char buffer[bufferSize];
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetCacheDir(NULL, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(nullptr, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, bufferSize, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, bufferSize, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    std::string cacheDir = contextImpl->GetCacheDir();
    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, cacheDir.length(), &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    cacheDir = contextImpl->GetCacheDir();
    ASSERT_EQ(writeLength, cacheDir.length());
    ASSERT_STREQ(buffer, cacheDir.c_str());
}

/**
 * @tc.number: GetCacheDirTest_004
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetCacheDirTest_004, TestSize.Level0)
{
    constexpr int32_t bufferSize = 1024;
    char buffer[bufferSize];
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL1);
    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    std::string cacheDir = contextImpl->GetCacheDir();
    ASSERT_EQ(writeLength, cacheDir.length());
    ASSERT_STREQ(buffer, cacheDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL2);
    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    cacheDir = contextImpl->GetCacheDir();
    ASSERT_EQ(writeLength, cacheDir.length());
    ASSERT_STREQ(buffer, cacheDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL3);
    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    cacheDir = contextImpl->GetCacheDir();
    ASSERT_EQ(writeLength, cacheDir.length());
    ASSERT_STREQ(buffer, cacheDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL4);
    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    cacheDir = contextImpl->GetCacheDir();
    ASSERT_EQ(writeLength, cacheDir.length());
    ASSERT_STREQ(buffer, cacheDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL5);
    code = OH_AbilityRuntime_ApplicationContextGetCacheDir(buffer, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    cacheDir = contextImpl->GetCacheDir();
    ASSERT_EQ(writeLength, cacheDir.length());
    ASSERT_STREQ(buffer, cacheDir.c_str());
}

/**
 * @tc.number: GetAreaModeTest_001
 * @tc.desc: Function test with applicationContext is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetAreaModeTest_001, TestSize.Level0)
{
    AbilityRuntime_AreaMode mode = ABILITY_RUNTIME_AREA_MODE_EL1;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetAreaMode(NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetAreaMode(nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetAreaMode(&mode);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(mode, ABILITY_RUNTIME_AREA_MODE_EL1);
}

/**
 * @tc.number: GetAreaModeTest_002
 * @tc.desc: Function test with applicationContextImpl is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetAreaModeTest_002, TestSize.Level0)
{
    InitApplicationContext();
    AbilityRuntime_AreaMode mode = ABILITY_RUNTIME_AREA_MODE_EL1;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetAreaMode(NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetAreaMode(nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetAreaMode(&mode);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    ASSERT_EQ(mode, ABILITY_RUNTIME_AREA_MODE_EL2);
}

/**
 * @tc.number: GetAreaModeTest_003
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetAreaModeTest_003, TestSize.Level0)
{
    AbilityRuntime_AreaMode mode = ABILITY_RUNTIME_AREA_MODE_EL1;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetAreaMode(NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetAreaMode(nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetAreaMode(&mode);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    ASSERT_EQ(mode, ABILITY_RUNTIME_AREA_MODE_EL2);

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL1);
    code = OH_AbilityRuntime_ApplicationContextGetAreaMode(&mode);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    ASSERT_EQ(mode, ABILITY_RUNTIME_AREA_MODE_EL1);

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL2);
    code = OH_AbilityRuntime_ApplicationContextGetAreaMode(&mode);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    ASSERT_EQ(mode, ABILITY_RUNTIME_AREA_MODE_EL2);

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL3);
    code = OH_AbilityRuntime_ApplicationContextGetAreaMode(&mode);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    ASSERT_EQ(mode, ABILITY_RUNTIME_AREA_MODE_EL3);

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL4);
    code = OH_AbilityRuntime_ApplicationContextGetAreaMode(&mode);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    ASSERT_EQ(mode, ABILITY_RUNTIME_AREA_MODE_EL4);

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL5);
    code = OH_AbilityRuntime_ApplicationContextGetAreaMode(&mode);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    ASSERT_EQ(mode, ABILITY_RUNTIME_AREA_MODE_EL5);
}

/**
 * @tc.number: GetBundleNameTest_001
 * @tc.desc: Function test with applicationContext is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetBundleNameTest_001, TestSize.Level0)
{
    constexpr int32_t bufferSize = 1024;
    char buffer[bufferSize];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetBundleName(NULL, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(nullptr, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, bufferSize, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, bufferSize, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, TEST_BUNDLE_NAME.length(), &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetBundleNameTest_002
 * @tc.desc: Function test with applicationContextImpl is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetBundleNameTest_002, TestSize.Level0)
{
    InitApplicationContext();
    constexpr int32_t bufferSize = 1024;
    char buffer[bufferSize];
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetBundleName(NULL, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(nullptr, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, bufferSize, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, bufferSize, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, TEST_BUNDLE_NAME.length(), &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetBundleNameTest_003
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetBundleNameTest_003, TestSize.Level0)
{
    constexpr int32_t bufferSize = 1024;
    char buffer[bufferSize];
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetBundleName(NULL, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(nullptr, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, bufferSize, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, bufferSize, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, TEST_BUNDLE_NAME.length(), &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleName(buffer, bufferSize, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    ASSERT_EQ(writeLength, TEST_BUNDLE_NAME.length());
    ASSERT_STREQ(buffer, TEST_BUNDLE_NAME.c_str());
}

/**
 * @tc.number: GetTempDirTest_001
 * @tc.desc: Function test with applicationContext is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetTempDirTest_001, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetTempDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetTempDirTest_002
 * @tc.desc: Function test with applicationContextImpl is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetTempDirTest_002, TestSize.Level0)
{
    InitApplicationContext();
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetTempDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetTempDirTest_003
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetTempDirTest_003, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetTempDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    std::string tempDir = contextImpl->GetTempDir();
    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, tempDir.length(), &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    tempDir = contextImpl->GetTempDir();
    ASSERT_EQ(writeLength, tempDir.length());
    ASSERT_STREQ(buffer, tempDir.c_str());
}

/**
 * @tc.number: GetTempDirTest_004
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetTempDirTest_004, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL1);
    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    std::string tempDir = contextImpl->GetTempDir();
    ASSERT_EQ(writeLength, tempDir.length());
    ASSERT_STREQ(buffer, tempDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL2);
    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    tempDir = contextImpl->GetTempDir();
    ASSERT_EQ(writeLength, tempDir.length());
    ASSERT_STREQ(buffer, tempDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL3);
    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    tempDir = contextImpl->GetTempDir();
    ASSERT_EQ(writeLength, tempDir.length());
    ASSERT_STREQ(buffer, tempDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL4);
    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    tempDir = contextImpl->GetTempDir();
    ASSERT_EQ(writeLength, tempDir.length());
    ASSERT_STREQ(buffer, tempDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL5);
    code = OH_AbilityRuntime_ApplicationContextGetTempDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    tempDir = contextImpl->GetTempDir();
    ASSERT_EQ(writeLength, tempDir.length());
    ASSERT_STREQ(buffer, tempDir.c_str());
}

/**
 * @tc.number: GetFilesDirTest_001
 * @tc.desc: Function test with applicationContext is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetFilesDirTest_001, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetFilesDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetFilesDirTest_002
 * @tc.desc: Function test with applicationContextImpl is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetFilesDirTest_002, TestSize.Level0)
{
    InitApplicationContext();
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetFilesDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetFilesDirTest_003
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetFilesDirTest_003, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetFilesDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    std::string filesDir = contextImpl->GetFilesDir();
    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, filesDir.length(), &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    filesDir = contextImpl->GetFilesDir();
    ASSERT_EQ(writeLength, filesDir.length());
    ASSERT_STREQ(buffer, filesDir.c_str());
}

/**
 * @tc.number: GetFilesDirTest_004
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetFilesDirTest_004, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL1);
    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    std::string filesDir = contextImpl->GetFilesDir();
    ASSERT_EQ(writeLength, filesDir.length());
    ASSERT_STREQ(buffer, filesDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL2);
    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    filesDir = contextImpl->GetFilesDir();
    ASSERT_EQ(writeLength, filesDir.length());
    ASSERT_STREQ(buffer, filesDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL3);
    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    filesDir = contextImpl->GetFilesDir();
    ASSERT_EQ(writeLength, filesDir.length());
    ASSERT_STREQ(buffer, filesDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL4);
    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    filesDir = contextImpl->GetFilesDir();
    ASSERT_EQ(writeLength, filesDir.length());
    ASSERT_STREQ(buffer, filesDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL5);
    code = OH_AbilityRuntime_ApplicationContextGetFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    filesDir = contextImpl->GetFilesDir();
    ASSERT_EQ(writeLength, filesDir.length());
    ASSERT_STREQ(buffer, filesDir.c_str());
}

/**
 * @tc.number: GetDatabaseDirTest_001
 * @tc.desc: Function test with applicationContext is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetDatabaseDirTest_001, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetDatabaseDirTest_002
 * @tc.desc: Function test with applicationContextImpl is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetDatabaseDirTest_002, TestSize.Level0)
{
    InitApplicationContext();
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetDatabaseDirTest_003
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetDatabaseDirTest_003, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    AbilityRuntime_ErrorCode code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, -1, &writeLength);

    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    std::string databaseDir = contextImpl->GetDatabaseDir();
    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, databaseDir.length(), &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    databaseDir = contextImpl->GetDatabaseDir();
    ASSERT_EQ(writeLength, databaseDir.length());
    ASSERT_STREQ(buffer, databaseDir.c_str());
}

/**
 * @tc.number: GetDatabaseDirTest_004
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetDatabaseDirTest_004, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL1);
    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    std::string databaseDir = contextImpl->GetDatabaseDir();
    ASSERT_EQ(writeLength, databaseDir.length());
    ASSERT_STREQ(buffer, databaseDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL2);
    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    databaseDir = contextImpl->GetDatabaseDir();
    ASSERT_EQ(writeLength, databaseDir.length());
    ASSERT_STREQ(buffer, databaseDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL3);
    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    databaseDir = contextImpl->GetDatabaseDir();
    ASSERT_EQ(writeLength, databaseDir.length());
    ASSERT_STREQ(buffer, databaseDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL4);
    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    databaseDir = contextImpl->GetDatabaseDir();
    ASSERT_EQ(writeLength, databaseDir.length());
    ASSERT_STREQ(buffer, databaseDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL5);
    code = OH_AbilityRuntime_ApplicationContextGetDatabaseDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    databaseDir = contextImpl->GetDatabaseDir();
    ASSERT_EQ(writeLength, databaseDir.length());
    ASSERT_STREQ(buffer, databaseDir.c_str());
}

/**
 * @tc.number: GetPreferencesDirTest_001
 * @tc.desc: Function test with applicationContext is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetPreferencesDirTest_001, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetPreferencesDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetPreferencesDirTest_002
 * @tc.desc: Function test with applicationContextImpl is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetPreferencesDirTest_002, TestSize.Level0)
{
    InitApplicationContext();
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetPreferencesDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetPreferencesDirTest_003
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetPreferencesDirTest_003, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetPreferencesDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    std::string preferencesDir = contextImpl->GetPreferencesDir();
    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, preferencesDir.length(), &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    preferencesDir = contextImpl->GetPreferencesDir();
    ASSERT_EQ(writeLength, preferencesDir.length());
    ASSERT_STREQ(buffer, preferencesDir.c_str());
}

/**
 * @tc.number: GetPreferencesDirTest_004
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetPreferencesDirTest_004, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL1);
    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    std::string preferencesDir = contextImpl->GetPreferencesDir();
    ASSERT_EQ(writeLength, preferencesDir.length());
    ASSERT_STREQ(buffer, preferencesDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL2);
    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    preferencesDir = contextImpl->GetPreferencesDir();
    ASSERT_EQ(writeLength, preferencesDir.length());
    ASSERT_STREQ(buffer, preferencesDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL3);
    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    preferencesDir = contextImpl->GetPreferencesDir();
    ASSERT_EQ(writeLength, preferencesDir.length());
    ASSERT_STREQ(buffer, preferencesDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL4);
    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    preferencesDir = contextImpl->GetPreferencesDir();
    ASSERT_EQ(writeLength, preferencesDir.length());
    ASSERT_STREQ(buffer, preferencesDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL5);
    code = OH_AbilityRuntime_ApplicationContextGetPreferencesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    preferencesDir = contextImpl->GetPreferencesDir();
    ASSERT_EQ(writeLength, preferencesDir.length());
    ASSERT_STREQ(buffer, preferencesDir.c_str());
}

/**
 * @tc.number: GetBundleCodeDirTest_001
 * @tc.desc: Function test with applicationContext is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetBundleCodeDirTest_001, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetBundleCodeDirTest_002
 * @tc.desc: Function test with applicationContextImpl is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetBundleCodeDirTest_002, TestSize.Level0)
{
    InitApplicationContext();
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetBundleCodeDirTest_003
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetBundleCodeDirTest_003, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    std::string bundleCodeDir = contextImpl->GetBundleCodeDir();
    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, bundleCodeDir.length(), &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    bundleCodeDir = contextImpl->GetBundleCodeDir();
    ASSERT_EQ(writeLength, bundleCodeDir.length());
    ASSERT_STREQ(buffer, bundleCodeDir.c_str());
}

/**
 * @tc.number: GetBundleCodeDirTest_004
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetBundleCodeDirTest_004, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL1);
    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    std::string bundleCodeDir = contextImpl->GetBundleCodeDir();
    ASSERT_EQ(writeLength, bundleCodeDir.length());
    ASSERT_STREQ(buffer, bundleCodeDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL2);
    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    bundleCodeDir = contextImpl->GetBundleCodeDir();
    ASSERT_EQ(writeLength, bundleCodeDir.length());
    ASSERT_STREQ(buffer, bundleCodeDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL3);
    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    bundleCodeDir = contextImpl->GetBundleCodeDir();
    ASSERT_EQ(writeLength, bundleCodeDir.length());
    ASSERT_STREQ(buffer, bundleCodeDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL4);
    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    bundleCodeDir = contextImpl->GetBundleCodeDir();
    ASSERT_EQ(writeLength, bundleCodeDir.length());
    ASSERT_STREQ(buffer, bundleCodeDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL5);
    code = OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    bundleCodeDir = contextImpl->GetBundleCodeDir();
    ASSERT_EQ(writeLength, bundleCodeDir.length());
    ASSERT_STREQ(buffer, bundleCodeDir.c_str());
}

/**
 * @tc.number: GetDistributedFilesDirTest_001
 * @tc.desc: Function test with applicationContext is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetDistributedFilesDirTest_001, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetDistributedFilesDirTest_002
 * @tc.desc: Function test with applicationContextImpl is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetDistributedFilesDirTest_002, TestSize.Level0)
{
    InitApplicationContext();
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetDistributedFilesDirTest_003
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetDistributedFilesDirTest_003, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    std::string distributedFilesDir = contextImpl->GetDistributedFilesDir();
    code =
        OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, distributedFilesDir.length(), &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    distributedFilesDir = contextImpl->GetDistributedFilesDir();
    ASSERT_EQ(writeLength, distributedFilesDir.length());
    ASSERT_STREQ(buffer, distributedFilesDir.c_str());
}

/**
 * @tc.number: GetDistributedFilesDirTest_004
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetDistributedFilesDirTest_004, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL1);
    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    std::string distributedFilesDir = contextImpl->GetDistributedFilesDir();
    ASSERT_EQ(writeLength, distributedFilesDir.length());
    ASSERT_STREQ(buffer, distributedFilesDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL2);
    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    distributedFilesDir = contextImpl->GetDistributedFilesDir();
    ASSERT_EQ(writeLength, distributedFilesDir.length());
    ASSERT_STREQ(buffer, distributedFilesDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL3);
    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    distributedFilesDir = contextImpl->GetDistributedFilesDir();
    ASSERT_EQ(writeLength, distributedFilesDir.length());
    ASSERT_STREQ(buffer, distributedFilesDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL4);
    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    distributedFilesDir = contextImpl->GetDistributedFilesDir();
    ASSERT_EQ(writeLength, distributedFilesDir.length());
    ASSERT_STREQ(buffer, distributedFilesDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL5);
    code = OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    distributedFilesDir = contextImpl->GetDistributedFilesDir();
    ASSERT_EQ(writeLength, distributedFilesDir.length());
    ASSERT_STREQ(buffer, distributedFilesDir.c_str());
}

/**
 * @tc.number: GetCloudFileDirTest_001
 * @tc.desc: Function test with applicationContext is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetCloudFileDirTest_001, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetCloudFileDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetCloudFileDirTest_002
 * @tc.desc: Function test with applicationContextImpl is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetCloudFileDirTest_002, TestSize.Level0)
{
    InitApplicationContext();
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetCloudFileDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetCloudFileDirTest_003
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetCloudFileDirTest_003, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetCloudFileDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    std::string cloudFileDir = contextImpl->GetCloudFileDir();
    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, cloudFileDir.length(), &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    cloudFileDir = contextImpl->GetCloudFileDir();
    ASSERT_EQ(writeLength, cloudFileDir.length());
    ASSERT_STREQ(buffer, cloudFileDir.c_str());
}

/**
 * @tc.number: GetCloudFileDirTest_004
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, GetCloudFileDirTest_004, TestSize.Level0)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL1);
    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    std::string cloudFileDir = contextImpl->GetCloudFileDir();
    ASSERT_EQ(writeLength, cloudFileDir.length());
    ASSERT_STREQ(buffer, cloudFileDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL2);
    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    cloudFileDir = contextImpl->GetCloudFileDir();
    ASSERT_EQ(writeLength, cloudFileDir.length());
    ASSERT_STREQ(buffer, cloudFileDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL3);
    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    cloudFileDir = contextImpl->GetCloudFileDir();
    ASSERT_EQ(writeLength, cloudFileDir.length());
    ASSERT_STREQ(buffer, cloudFileDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL4);
    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    cloudFileDir = contextImpl->GetCloudFileDir();
    ASSERT_EQ(writeLength, cloudFileDir.length());
    ASSERT_STREQ(buffer, cloudFileDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL5);
    code = OH_AbilityRuntime_ApplicationContextGetCloudFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    cloudFileDir = contextImpl->GetCloudFileDir();
    ASSERT_EQ(writeLength, cloudFileDir.length());
    ASSERT_STREQ(buffer, cloudFileDir.c_str());
}

// CheckWant - Normal
/**
 * @tc.number: CheckWant_001
 * @tc.desc: CheckWant succeeds
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, CheckWant_001, TestSize.Level0)
{
    // Arrange
    AbilityBase_Want want;
    char bundleName[] = "com.example.myapplication";
    want.element.bundleName = bundleName;

    char abilityName[] = "com.test.Ability";
    want.element.abilityName = abilityName;

    char moduleName[] = "com.test.module";
    want.element.moduleName = moduleName;

    // Act
    AbilityRuntime_ErrorCode result = CheckWant(&want);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_NO_ERROR, result);
}

// CheckWant - nullptr
/**
 * @tc.number: CheckWant_002
 * @tc.desc: CheckWant fails when want is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, CheckWant_002, TestSize.Level0)
{
    // Arrange
    AbilityBase_Want* want = nullptr;

    // Act
    AbilityRuntime_ErrorCode result = CheckWant(want);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

// CheckWant - bundleName nullptr
/**
 * @tc.number: CheckWant_003
 * @tc.desc: CheckWant fails when bundle name is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, CheckWant_003, TestSize.Level0)
{
    // Arrange
    AbilityBase_Want want;
    want.element.bundleName = nullptr;

    char abilityName[] = "com.test.Ability";
    want.element.abilityName = abilityName;

    char moduleName[] = "com.test.module";
    want.element.moduleName = moduleName;

    // Act
    AbilityRuntime_ErrorCode result = CheckWant(&want);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

// CheckWant - abilityName nullptr
/**
 * @tc.number: CheckWant_004
 * @tc.desc: CheckWant fails when ability name is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, CheckWant_004, TestSize.Level0)
{
    // Arrange
    AbilityBase_Want want;
    char bundleName[] = "com.example.myapplication";
    want.element.bundleName = bundleName;

    want.element.abilityName = nullptr;

    char moduleName[] = "com.test.module";
    want.element.moduleName = moduleName;

    // Act
    AbilityRuntime_ErrorCode result = CheckWant(&want);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

// CheckWant - moduleName nullptr
/**
 * @tc.number: CheckWant_005
 * @tc.desc: CheckWant fails when module name is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, CheckWant_005, TestSize.Level0)
{
    // Arrange
    AbilityBase_Want want;
    char bundleName[] = "com.example.myapplication";
    want.element.bundleName = bundleName;

    char abilityName[] = "com.test.Ability";
    want.element.abilityName = abilityName;

    want.element.moduleName = nullptr;

    // Act
    AbilityRuntime_ErrorCode result = CheckWant(&want);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.number: OH_AbilityRuntime_StartSelfUIAbility_001
 * @tc.desc: OH_AbilityRuntime_StartSelfUIAbility does not return 401 when everything is ok
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, OH_AbilityRuntime_StartSelfUIAbility_001, TestSize.Level0)
{
    AbilityBase_Want want;
    char bundleName[] = "com.example.myapplication";
    want.element.bundleName = bundleName;

    char abilityName[] = "com.test.Ability";
    want.element.abilityName = abilityName;

    char moduleName[] = "com.test.module";
    want.element.moduleName = moduleName;
    want.params = std::map<std::string, std::string>();
    want.fds = std::map<std::string, int32_t>();
    AbilityRuntime_ErrorCode errCode = OH_AbilityRuntime_StartSelfUIAbility(&want);
    EXPECT_NE(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, errCode);
}

/**
 * @tc.number: OH_AbilityRuntime_StartSelfUIAbility_002
 * @tc.desc: OH_AbilityRuntime_StartSelfUIAbility returns 401 when module name is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, OH_AbilityRuntime_StartSelfUIAbility_002, TestSize.Level0)
{
    // Arrange
    AbilityBase_Want want;
    char bundleName[] = "com.example.myapplication";
    want.element.bundleName = bundleName;

    char abilityName[] = "com.test.Ability";
    want.element.abilityName = abilityName;

    want.element.moduleName = nullptr;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_StartSelfUIAbility(&want);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.number: OH_AbilityRuntime_StartSelfUIAbility_003
 * @tc.desc: OH_AbilityRuntime_StartSelfUIAbility does not return 401 when everything is ok
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, OH_AbilityRuntime_StartSelfUIAbility_003, TestSize.Level0)
{
    // Arrange
    AbilityBase_Want want;
    char bundleName[] = "com.example.myapplication";
    want.element.bundleName = bundleName;

    char abilityName[] = "com.test.Ability";
    want.element.abilityName = abilityName;

    char moduleName[] = "com.test.module";
    want.element.moduleName = moduleName;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_StartSelfUIAbility(&want);

    // Assert
    EXPECT_NE(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.number: OH_AbilityRuntime_StartSelfUIAbility_004
 * @tc.desc: OH_AbilityRuntime_StartSelfUIAbility returns 401 when bundle name is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, OH_AbilityRuntime_StartSelfUIAbility_004, TestSize.Level0)
{
    // Arrange
    AbilityBase_Want want;
    want.element.bundleName = nullptr;

    char abilityName[] = "com.test.Ability";
    want.element.abilityName = abilityName;

    char moduleName[] = "com.test.module";
    want.element.moduleName = moduleName;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_StartSelfUIAbility(&want);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.number: OH_AbilityRuntime_StartSelfUIAbility_005
 * @tc.desc: OH_AbilityRuntime_StartSelfUIAbility returns 401 when ability name is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, OH_AbilityRuntime_StartSelfUIAbility_005, TestSize.Level0)
{
    // Arrange
    AbilityBase_Want want;
    char bundleName[] = "com.example.myapplication";
    want.element.bundleName = bundleName;

    want.element.abilityName = nullptr;

    char moduleName[] = "com.test.module";
    want.element.moduleName = moduleName;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_StartSelfUIAbility(&want);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.number: OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions_001
 * @tc.desc: OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions returns 401 when bundle name is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions_001,
    TestSize.Level0)
{
    // Arrange
    AbilityBase_Want want;
    want.element.bundleName = nullptr;

    char abilityName[] = "com.test.Ability";
    want.element.abilityName = abilityName;

    char moduleName[] = "com.test.module";
    want.element.moduleName = moduleName;

    AbilityRuntime_StartOptions options;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions(&want, &options);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.number: OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions_002
 * @tc.desc: OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions returns 401 when ability name is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions_002,
    TestSize.Level0)
{
    // Arrange
    AbilityBase_Want want;
    char bundleName[] = "com.example.myapplication";
    want.element.bundleName = bundleName;

    want.element.abilityName = nullptr;

    char moduleName[] = "com.test.module";
    want.element.moduleName = moduleName;

    AbilityRuntime_StartOptions options;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions(&want, &options);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.number: OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions_003
 * @tc.desc: OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions returns 401 when module name is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions_003,
    TestSize.Level0)
{
    // Arrange
    AbilityBase_Want want;
    char bundleName[] = "com.example.myapplication";
    want.element.bundleName = bundleName;

    char abilityName[] = "com.test.Ability";
    want.element.abilityName = abilityName;

    want.element.moduleName = nullptr;

    AbilityRuntime_StartOptions options;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions(&want, &options);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.number: OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions_004
 * @tc.desc: OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions returns 401 when start options is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions_004,
    TestSize.Level0)
{
    // Arrange
    AbilityBase_Want want;
    char bundleName[] = "com.example.myapplication";
    want.element.bundleName = bundleName;

    char abilityName[] = "com.test.Ability";
    want.element.abilityName = abilityName;

    char moduleName[] = "com.test.module";
    want.element.moduleName = moduleName;

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions(&want, nullptr);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.number: OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions_005
 * @tc.desc: OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions does not return 401 when everything is ok
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions_005,
    TestSize.Level0)
{
    // Arrange
    AbilityBase_Want want;
    char bundleName[] = "com.example.myapplication";
    want.element.bundleName = bundleName;

    char abilityName[] = "com.test.Ability";
    want.element.abilityName = abilityName;

    char moduleName[] = "com.test.module";
    want.element.moduleName = moduleName;

    AbilityRuntime_StartOptions *options = OH_AbilityRuntime_CreateStartOptions();
    ASSERT_NE(options, nullptr);

    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions(&want, options);

    // Assert
    EXPECT_NE(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);

    ASSERT_EQ(OH_AbilityRuntime_DestroyStartOptions(&options), ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    ASSERT_EQ(options, nullptr);
}

/**
 * @tc.number: OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions_006
 * @tc.desc: OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions returns 401 when want is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions_006,
    TestSize.Level0)
{
    // Act
    AbilityRuntime_ErrorCode result = OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions(nullptr, nullptr);

    // Assert
    EXPECT_EQ(ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID, result);
}

/**
 * @tc.number: ConvertToCommonBusinessErrorCode_001
 * @tc.desc: ConvertToCommonBusinessErrorCode
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, ConvertToCommonBusinessErrorCode_001, TestSize.Level0)
{
    int32_t abilityManagerError = OHOS::ERR_OK;
    AbilityRuntime_ErrorCode errCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    abilityManagerError = OHOS::ERR_OK;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);

    abilityManagerError = OHOS::AAFwk::CHECK_PERMISSION_FAILED;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_PERMISSION_DENIED);

    abilityManagerError = OHOS::ERR_PERMISSION_DENIED;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_PERMISSION_DENIED);

    abilityManagerError = OHOS::AAFwk::ERR_CAPABILITY_NOT_SUPPORT;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_NOT_SUPPORTED);

    abilityManagerError = OHOS::AAFwk::RESOLVE_ABILITY_ERR;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_NO_SUCH_ABILITY);

    abilityManagerError = OHOS::AAFwk::TARGET_BUNDLE_NOT_EXIST;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_NO_SUCH_ABILITY);

    abilityManagerError = OHOS::AAFwk::ERR_NOT_ALLOW_IMPLICIT_START;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_NO_SUCH_ABILITY);

    abilityManagerError = OHOS::AAFwk::ERR_WRONG_INTERFACE_CALL;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_INCORRECT_ABILITY_TYPE);

    abilityManagerError = OHOS::AAFwk::TARGET_ABILITY_NOT_SERVICE;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_INCORRECT_ABILITY_TYPE);

    abilityManagerError = OHOS::AAFwk::RESOLVE_CALL_ABILITY_TYPE_ERR;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_INCORRECT_ABILITY_TYPE);

    abilityManagerError = -1;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_INTERNAL);
}

/**
 * @tc.number: ConvertToCommonBusinessErrorCode_002
 * @tc.desc: ConvertToCommonBusinessErrorCode
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, ConvertToCommonBusinessErrorCode_002, TestSize.Level0)
{
    int32_t abilityManagerError = OHOS::ERR_OK;
    AbilityRuntime_ErrorCode errCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    abilityManagerError = OHOS::AAFwk::ERR_CROWDTEST_EXPIRED;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_CROWDTEST_EXPIRED);

    abilityManagerError = OHOS::ERR_WOULD_BLOCK;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_WUKONG_MODE);

    abilityManagerError = OHOS::AAFwk::ERR_APP_CONTROLLED;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_CONTROLLED);

    abilityManagerError = OHOS::AAFwk::ERR_EDM_APP_CONTROLLED;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_EDM_CONTROLLED);

    abilityManagerError = OHOS::AAFwk::ERR_START_OTHER_APP_FAILED;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_CROSS_APP);

    abilityManagerError = OHOS::AAFwk::NOT_TOP_ABILITY;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_NOT_TOP_ABILITY);

    abilityManagerError = OHOS::AAFwk::ERR_START_OPTIONS_CHECK_FAILED;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_VISIBILITY_SETTING_DISABLED);

    abilityManagerError = OHOS::AAFwk::ERR_UPPER_LIMIT;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_UPPER_LIMIT_REACHED);

    abilityManagerError = OHOS::AAFwk::ERR_APP_INSTANCE_KEY_NOT_SUPPORT;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_APP_INSTANCE_KEY_NOT_SUPPORTED);

    abilityManagerError = OHOS::AAFwk::ERR_NOT_SELF_APPLICATION;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_CROSS_APP);

    abilityManagerError = -1;
    errCode = ConvertToCommonBusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_INTERNAL);
}

/**
 * @tc.number: ConvertToAPI18BusinessErrorCode_001
 * @tc.desc: ConvertToAPI18BusinessErrorCode
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, ConvertToAPI18BusinessErrorCode_001, TestSize.Level0)
{
    int32_t abilityManagerError = OHOS::ERR_OK;
    AbilityRuntime_ErrorCode errCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    abilityManagerError = OHOS::ERR_OK;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);

    abilityManagerError = OHOS::AAFwk::CHECK_PERMISSION_FAILED;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_PERMISSION_DENIED);

    abilityManagerError = OHOS::ERR_PERMISSION_DENIED;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_PERMISSION_DENIED);

    abilityManagerError = OHOS::AAFwk::ERR_CAPABILITY_NOT_SUPPORT;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_NOT_SUPPORTED);

    abilityManagerError = OHOS::AAFwk::RESOLVE_ABILITY_ERR;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_NO_SUCH_ABILITY);

    abilityManagerError = OHOS::AAFwk::TARGET_BUNDLE_NOT_EXIST;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_NO_SUCH_ABILITY);

    abilityManagerError = OHOS::AAFwk::ERR_NOT_ALLOW_IMPLICIT_START;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_NO_SUCH_ABILITY);

    abilityManagerError = OHOS::AAFwk::ERR_WRONG_INTERFACE_CALL;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_INCORRECT_ABILITY_TYPE);

    abilityManagerError = OHOS::AAFwk::TARGET_ABILITY_NOT_SERVICE;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_INCORRECT_ABILITY_TYPE);

    abilityManagerError = OHOS::AAFwk::RESOLVE_CALL_ABILITY_TYPE_ERR;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_INCORRECT_ABILITY_TYPE);

    abilityManagerError = OHOS::AAFwk::ERR_CROWDTEST_EXPIRED;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_CROWDTEST_EXPIRED);

    abilityManagerError = OHOS::ERR_WOULD_BLOCK;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_WUKONG_MODE);

    abilityManagerError = -1;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_INTERNAL);
}

/**
 * @tc.number: ConvertToAPI18BusinessErrorCode_002
 * @tc.desc: ConvertToAPI18BusinessErrorCode
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextTest, ConvertToAPI18BusinessErrorCode_002, TestSize.Level0)
{
    int32_t abilityManagerError = OHOS::ERR_OK;
    AbilityRuntime_ErrorCode errCode = ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;

    abilityManagerError = OHOS::AAFwk::ERR_APP_CONTROLLED;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_CONTROLLED);

    abilityManagerError = OHOS::AAFwk::ERR_EDM_APP_CONTROLLED;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_EDM_CONTROLLED);

    abilityManagerError = OHOS::AAFwk::ERR_START_OTHER_APP_FAILED;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_CROSS_APP);

    abilityManagerError = OHOS::AAFwk::NOT_TOP_ABILITY;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_NOT_TOP_ABILITY);

    abilityManagerError = OHOS::AAFwk::ERR_START_OPTIONS_CHECK_FAILED;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_VISIBILITY_SETTING_DISABLED);

    abilityManagerError = OHOS::AAFwk::ERR_UPPER_LIMIT;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_UPPER_LIMIT_REACHED);

    abilityManagerError = OHOS::AAFwk::ERR_APP_INSTANCE_KEY_NOT_SUPPORT;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_APP_INSTANCE_KEY_NOT_SUPPORTED);

    abilityManagerError = OHOS::AAFwk::ERR_NOT_SELF_APPLICATION;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_CROSS_APP);

    abilityManagerError = OHOS::AAFwk::ERR_MULTI_APP_NOT_SUPPORTED;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_MULTI_APP_NOT_SUPPORTED);

    abilityManagerError = OHOS::AAFwk::ERR_INVALID_APP_INSTANCE_KEY;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_INVALID_APP_INSTANCE_KEY);

    abilityManagerError = OHOS::AAFwk::ERR_MULTI_INSTANCE_NOT_SUPPORTED;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_MULTI_INSTANCE_NOT_SUPPORTED);

    abilityManagerError = -1;
    errCode = ConvertToAPI18BusinessErrorCode(abilityManagerError);
    EXPECT_EQ(errCode, ABILITY_RUNTIME_ERROR_CODE_INTERNAL);
}
} // namespace OHOS::AbilityRuntime
