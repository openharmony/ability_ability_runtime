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
#include "application_context.h"
#include "context/application_context.h"
#include "securec.h"
#include "start_options_impl.h"
#include "string_wrapper.h"
#include "want_manager.h"
#include "want_utils.h"

namespace OHOS::AbilityRuntime {
namespace {
constexpr const char* DATA_STORAGE = "/data/storage/";
constexpr const char* BASE_LOG_FILE = "/log";
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

    std::string GetLogFileDir() override
    {
        std::string dir;
        dir.append(DATA_STORAGE);
        dir.append(EL_LIST[1]);
        dir.append(BASE_LOG_FILE);
        return dir;
    }

    void SwitchArea(const int32_t mode) override
    {
        if (mode < 0 || mode >= std::size(EL_LIST)) {
            return;
        }
        areaMode_ = EL_LIST[mode];
    }

    static void ResetApplicationContext()
    {
        applicationContext_ = nullptr;
    }

private:
    std::string bundleName_;
    std::string areaMode_;
};

class CapiAbilityRuntimeApplicationContextSecondTest : public Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;

protected:
    static void InitApplicationContext();

    static std::shared_ptr<TestContextImpl> InitApplicationContextImpl(const std::string &bundleName);
};

void CapiAbilityRuntimeApplicationContextSecondTest::SetUpTestCase()
{
}

void CapiAbilityRuntimeApplicationContextSecondTest::TearDownTestCase()
{
}

void CapiAbilityRuntimeApplicationContextSecondTest::SetUp()
{
}

void CapiAbilityRuntimeApplicationContextSecondTest::TearDown()
{
    const auto applicationContext = ApplicationContext::GetApplicationContext();
    if (applicationContext != nullptr) {
        applicationContext->AttachContextImpl(nullptr);
        TestContextImpl::ResetApplicationContext();
    }
}

void CapiAbilityRuntimeApplicationContextSecondTest::InitApplicationContext()
{
    ApplicationContext::GetInstance();
}

std::shared_ptr<TestContextImpl> CapiAbilityRuntimeApplicationContextSecondTest::InitApplicationContextImpl(
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
 * @tc.number: GetLogFileDirTest_001
 * @tc.desc: Function test with applicationContext is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextSecondTest, GetLogFileDirTest_001, TestSize.Level2)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetLogFileDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetLogFileDirTest_002
 * @tc.desc: Function test with applicationContextImpl is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextSecondTest, GetLogFileDirTest_002, TestSize.Level2)
{
    InitApplicationContext();
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetLogFileDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST);
    ASSERT_EQ(writeLength, 0);
}

/**
 * @tc.number: GetLogFileDirTest_003
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextSecondTest, GetLogFileDirTest_003, TestSize.Level2)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetLogFileDir(NULL, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(nullptr, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, BUFFER_SIZE, NULL);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, BUFFER_SIZE, nullptr);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, -1, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, 0, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    std::string logFileDir = contextImpl->GetLogFileDir();
    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, logFileDir.length(), &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
    ASSERT_EQ(writeLength, 0);

    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    logFileDir = contextImpl->GetLogFileDir();
    ASSERT_EQ(writeLength, logFileDir.length());
    ASSERT_STREQ(buffer, logFileDir.c_str());
}

/**
 * @tc.number: GetLogFileDirTest_004
 * @tc.desc: Function test
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextSecondTest, GetLogFileDirTest_004, TestSize.Level2)
{
    char buffer[BUFFER_SIZE] = { 0 };
    int32_t writeLength = 0;

    const auto contextImpl = InitApplicationContextImpl(TEST_BUNDLE_NAME);
    ASSERT_NE(contextImpl, nullptr);

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL1);
    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    std::string logFileDir = contextImpl->GetLogFileDir();
    ASSERT_STREQ(buffer, logFileDir.c_str());
    ASSERT_EQ(writeLength, logFileDir.length());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL2);
    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    logFileDir = contextImpl->GetLogFileDir();
    ASSERT_EQ(writeLength, logFileDir.length());
    ASSERT_STREQ(buffer, logFileDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL3);
    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    logFileDir = contextImpl->GetLogFileDir();
    ASSERT_EQ(writeLength, logFileDir.length());
    ASSERT_STREQ(buffer, logFileDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL4);
    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    logFileDir = contextImpl->GetLogFileDir();
    ASSERT_EQ(writeLength, logFileDir.length());
    ASSERT_STREQ(buffer, logFileDir.c_str());

    contextImpl->SwitchArea(ABILITY_RUNTIME_AREA_MODE_EL5);
    code = OH_AbilityRuntime_ApplicationContextGetLogFileDir(buffer, BUFFER_SIZE, &writeLength);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_NO_ERROR);
    logFileDir = contextImpl->GetLogFileDir();
    ASSERT_EQ(writeLength, logFileDir.length());
    ASSERT_STREQ(buffer, logFileDir.c_str());
}

/**
 * @tc.number: NotifyPageChanged_001
 * @tc.desc: Function test with targetPageName is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextSecondTest, NotifyPageChanged_001, TestSize.Level2)
{
    const char* targetPage = "";
    int32_t targetPageNameLength = 0;
    int32_t windowId = 0;
    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextNotifyPageChanged("", targetPageNameLength, windowId);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextNotifyPageChanged(NULL, targetPageNameLength, windowId);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextNotifyPageChanged(nullptr, targetPageNameLength, windowId);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextNotifyPageChanged(targetPage, -1, windowId);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

}

/**
 * @tc.number: NotifyPageChanged_002
 * @tc.desc: Function test with targetPageNameLength is invalid
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextSecondTest, NotifyPageChanged_002, TestSize.Level2)
{
    const char* targetPage = "";
    int32_t targetPageNameLength = 0;
    int32_t windowId = 0;
    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextNotifyPageChanged(targetPage, 0, windowId);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextNotifyPageChanged(targetPage, -1, windowId);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextNotifyPageChanged(targetPage, targetPageNameLength, windowId);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
}

/**
 * @tc.number: NotifyPageChanged_003
 * @tc.desc: Function test with windowId is invalid
 * @tc.type: FUNC
 */
HWTEST_F(CapiAbilityRuntimeApplicationContextSecondTest, NotifyPageChanged_003, TestSize.Level2)
{
    const char* targetPage = "";
    int32_t targetPageNameLength = 0;
    int32_t windowId = 0;
    AbilityRuntime_ErrorCode code =
        OH_AbilityRuntime_ApplicationContextNotifyPageChanged(targetPage, targetPageNameLength, 0);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextNotifyPageChanged(targetPage, targetPageNameLength, -12);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);

    code = OH_AbilityRuntime_ApplicationContextNotifyPageChanged(targetPage, targetPageNameLength, windowId);
    ASSERT_EQ(code, ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID);
}
}