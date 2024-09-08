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
#include "application_context.h"
#include "context/application_context.h"

namespace OHOS::AbilityRuntime {
namespace {
constexpr const char* DATA_STORAGE = "/data/storage/";
constexpr const char* BASE_CACHE = "/base/cache";
constexpr const char* EL_LIST[] = { "el1", "el2", "el3", "el4", "el5" };
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
} // namespace OHOS::AbilityRuntime
