/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "auto_fill_manager.h"
#include "auto_fill_error.h"
#include "auto_fill_extension_callback.h"
#include "extension_ability_info.h"
#include "hilog_tag_wrapper.h"
#include "mock_ui_content.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
namespace {
const int32_t EVENT_ID = 1;
}  // namespace
class AutoFillManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    virtual Ace::UIContent* GetUIContent()
    {
        return nullptr;
    }
};

class MockModalUIExtensionProxy : public Ace::ModalUIExtensionProxy {
public:
    MOCK_METHOD1(SendData, void(const AAFwk::WantParams &params));
};

void AutoFillManagerTest::SetUpTestCase(void)
{}

void AutoFillManagerTest::TearDownTestCase(void)
{}

void AutoFillManagerTest::SetUp()
{}

void AutoFillManagerTest::TearDown()
{}

/*
 * Feature: AutoFillManager
 * Function: RequestAutoFill
 * SubFunction: NA
 * FunctionPoints:Calling to the RequestAutoFill function parameter is invalid.
 * EnvConditions: NA
 * CaseDescription: Verify the parameter UIContent or fillCallback is nullptr.
 */
HWTEST_F(AutoFillManagerTest, RequestAutoFill_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AutoFillManagerTest, RequestAutoFill_0100, TestSize.Level1";
    auto &manager = AbilityRuntime::AutoFillManager::GetInstance();
    const AbilityRuntime::AutoFill::AutoFillRequest autoFillRequest;
    const std::shared_ptr<AbilityRuntime::IFillRequestCallback> fillCallback = nullptr;
    AbilityRuntime::AutoFill::AutoFillResult result;
    int32_t ret = manager.RequestAutoFill(GetUIContent(), autoFillRequest, fillCallback, result);
    EXPECT_EQ(ret, AbilityRuntime::AutoFill::AUTO_FILL_OBJECT_IS_NULL);
}

/*
 * Feature: AutoFillManager
 * Function: RequestAutoSave
 * SubFunction: NA
 * FunctionPoints:Calling to the RequestAutoSave function parameter is invalid.
 * EnvConditions: NA
 * CaseDescription: Verify the parameter UIContent or saveCallback is nullptr.
 */
HWTEST_F(AutoFillManagerTest, RequestAutoSave_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AutoFillManagerTest, RequestAutoSave_0100, TestSize.Level1";
    auto &manager = AbilityRuntime::AutoFillManager::GetInstance();
    const AbilityRuntime::AutoFill::AutoFillRequest autoFillRequest;
    const std::shared_ptr<AbilityRuntime::ISaveRequestCallback> saveCallback = nullptr;
    AbilityRuntime::AutoFill::AutoFillResult result;
    int32_t ret = manager.RequestAutoSave(GetUIContent(), autoFillRequest, saveCallback, result);
    EXPECT_EQ(ret, AbilityRuntime::AutoFill::AUTO_FILL_OBJECT_IS_NULL);
}

/*
 * Feature: AutoFillManager
 * Function: HandleRequestExecuteInner
 * SubFunction: NA
 * FunctionPoints:Calling to the HandleRequestExecuteInner function parameter is invalid.
 * EnvConditions: NA
 * CaseDescription: Verify the parameter UIContent or fillCallback or saveCallback is nullptr.
 */
HWTEST_F(AutoFillManagerTest, HandleRequestExecuteInner_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AutoFillManagerTest, HandleRequestExecuteInner_0100, TestSize.Level1";
    auto &manager = AbilityRuntime::AutoFillManager::GetInstance();
    const AbilityBase::AutoFillType autoFillType = AbilityBase::AutoFillType::UNSPECIFIED;
    const AbilityRuntime::AutoFill::AutoFillRequest autoFillRequest;
    const std::shared_ptr<AbilityRuntime::IFillRequestCallback> fillCallback = nullptr;
    const std::shared_ptr<AbilityRuntime::ISaveRequestCallback> saveCallback = nullptr;
    AbilityRuntime::AutoFill::AutoFillResult result;
    int32_t ret =
        manager.HandleRequestExecuteInner(GetUIContent(), autoFillRequest, fillCallback, saveCallback, result);
    EXPECT_EQ(ret, AbilityRuntime::AutoFill::AUTO_FILL_OBJECT_IS_NULL);
}

/*
 * Feature: AutoFillManager
 * Function: UpdateCustomPopupUIExtension
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify if the UpdateCustomPopupUIExtension is valid.
 */
HWTEST_F(AutoFillManagerTest, UpdateCustomPopupUIExtension_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AutoFillManagerTest, UpdateCustomPopupUIExtension_0100, TestSize.Level1";
    auto &manager = AbilityRuntime::AutoFillManager::GetInstance();
    EXPECT_EQ(manager.extensionCallbacks_.size(), 0);
    const AbilityBase::ViewData viewdata;
    manager.UpdateCustomPopupUIExtension(1, viewdata);
}

/*
 * Feature: AutoFillManager
 * Function: ConvertAutoFillWindowType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify Based on whether the requestType value can correctly convert
 * the windowType and extension types.
 */
HWTEST_F(AutoFillManagerTest, ConvertAutoFillWindowType_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AutoFillManagerTest, ConvertAutoFillWindowType_0100, TestSize.Level1";
    AbilityRuntime::AutoFill::AutoFillRequest autoFillRequest;
    autoFillRequest.autoFillCommand = AbilityRuntime::AutoFill::AutoFillCommand::FILL;
    autoFillRequest.autoFillType = AbilityBase::AutoFillType::PASSWORD;
    auto &manager = AbilityRuntime::AutoFillManager::GetInstance();
    bool isSmartAutoFill = false;
    AbilityRuntime::AutoFill::AutoFillWindowType autoFillWindowType
        = AbilityRuntime::AutoFill::AutoFillWindowType::MODAL_WINDOW;
    manager.ConvertAutoFillWindowType(autoFillRequest, isSmartAutoFill, autoFillWindowType);
    EXPECT_EQ(isSmartAutoFill, false);

    autoFillRequest.autoFillCommand = AbilityRuntime::AutoFill::AutoFillCommand::SAVE;
    autoFillRequest.autoFillType = AbilityBase::AutoFillType::PERSON_FULL_NAME;
    manager.ConvertAutoFillWindowType(autoFillRequest, isSmartAutoFill, autoFillWindowType);
    EXPECT_EQ(isSmartAutoFill, true);
    EXPECT_EQ(autoFillWindowType, AbilityRuntime::AutoFill::AutoFillWindowType::MODAL_WINDOW);
}

/*
 * Feature: AutoFillManager
 * Function: IsNeedToCreatePopupWindow
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: pull up the windowType and extension types.
 */
HWTEST_F(AutoFillManagerTest, IsNeedToCreatePopupWindow_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AutoFillManagerTest, IsNeedToCreatePopupWindow_0100, TestSize.Level1";
    auto &manager = AbilityRuntime::AutoFillManager::GetInstance();
    bool isPopupAutoFill = false;

    isPopupAutoFill = manager.IsNeedToCreatePopupWindow(AbilityBase::AutoFillType::PERSON_FULL_NAME);
    EXPECT_EQ(isPopupAutoFill, true);
}

/*
 * Feature: AutoFillManager
 * Function: CloseUIExtension
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test when extensionCallback is not nullptr.
 */
HWTEST_F(AutoFillManagerTest, CloseUIExtension_0100, TestSize.Level1)
{
    auto &manager = AbilityRuntime::AutoFillManager::GetInstance();
    EXPECT_EQ(manager.extensionCallbacks_.size(), 0);
    uint32_t autoFillSessionId = 0;
    auto extensionCallback = std::make_shared<AbilityRuntime::AutoFillExtensionCallback>();
    manager.extensionCallbacks_.emplace(autoFillSessionId, extensionCallback);
    manager.CloseUIExtension(autoFillSessionId);
    manager.extensionCallbacks_.clear();
}

/*
 * Feature: AutoFillManager
 * Function: CloseUIExtension
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test when extensionCallback is nullptr.
 */
HWTEST_F(AutoFillManagerTest, CloseUIExtension_0200, TestSize.Level1)
{
    auto &manager = AbilityRuntime::AutoFillManager::GetInstance();
    EXPECT_EQ(manager.extensionCallbacks_.size(), 0);
    uint32_t autoFillSessionId = 0;
    manager.CloseUIExtension(autoFillSessionId);
}

/*
 * Feature: AutoFillManager
 * Function: BindModalUIExtensionCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test BindModalUIExtensionCallback.
 */
HWTEST_F(AutoFillManagerTest, BindModalUIExtensionCallback_0100, TestSize.Level1)
{
    std::shared_ptr<AbilityRuntime::AutoFillExtensionCallback> extensionCallback;
    Ace::ModalUIExtensionCallbacks callback;
    auto &manager = AbilityRuntime::AutoFillManager::GetInstance();
    EXPECT_EQ(manager.extensionCallbacks_.size(), 0);
    manager.BindModalUIExtensionCallback(extensionCallback, callback);
}

/*
 * Feature: AutoFillManager
 * Function: RemoveTask、SetTimeOutEvent、RemoveEvent and RemoveAutoFillExtensionCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test RemoveTask、SetTimeOutEvent、RemoveEvent and RemoveAutoFillExtensionCallback.
 */
HWTEST_F(AutoFillManagerTest, AutoFillManager_RemoveTaskAndExtensionCallback_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "RemoveTaskAndSetTimeOutEvent_0100 start");

    auto& manager = AbilityRuntime::AutoFillManager::GetInstance();
    EXPECT_EQ(manager.extensionCallbacks_.size(), 0);
    uint32_t autoFillSessionId = 0;
    auto extensionCallback = std::make_shared<AbilityRuntime::AutoFillExtensionCallback>();
    ASSERT_NE(extensionCallback, nullptr);
    manager.extensionCallbacks_.emplace(autoFillSessionId, extensionCallback);
    uint32_t eventId = 0;
    manager.SetTimeOutEvent(eventId);
    EXPECT_EQ(manager.taskHandles_.size(), 1);
    manager.RemoveEvent(eventId);
    EXPECT_EQ(manager.taskHandles_.size(), 0);
    EXPECT_EQ(manager.extensionCallbacks_.size(), 1);
    manager.RemoveAutoFillExtensionCallback(eventId);
    EXPECT_EQ(manager.extensionCallbacks_.size(), 0);
    uint32_t taskId = 1;
    manager.taskHandles_.emplace(taskId, nullptr);
    EXPECT_EQ(manager.taskHandles_.size(), 1);
    manager.RemoveTask(taskId);
    EXPECT_EQ(manager.taskHandles_.size(), 0);

    TAG_LOGI(AAFwkTag::TEST, "AutoFillManager_RemoveTaskAndExtensionCallback_Test end");
}
} // namespace AppExecFwk
} // namespace OHOS