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
#include <singleton.h>
#include <cstdint>
#include <cstring>

#include "ability_manager_service.h"
#include "ability_record.h"
#include "wm_common.h"
#define private public
#define protected public
#include "modal_system_app_freeze_uiextension.h"
#undef private
#undef protected

using namespace OHOS::AAFwk;
using namespace OHOS::Rosen;

namespace OHOS {
namespace AppExecFwk {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AAFwk;

class ModalSystemAppFreezeUiextensionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    bool callbackCalled = false;
    void ResetCallbackFlag() { callbackCalled = false; }
    void CallbackFunction() { callbackCalled = true; }
};

void ModalSystemAppFreezeUiextensionTest::SetUpTestCase(void)
{}

void ModalSystemAppFreezeUiextensionTest::TearDownTestCase(void)
{}

void ModalSystemAppFreezeUiextensionTest::SetUp(void)
{
    ResetCallbackFlag();
}

void ModalSystemAppFreezeUiextensionTest::TearDown(void)
{}

/**
 * @tc.number: ProcessAppFreeze_001
 * @tc.name: ProcessAppFreeze with scene board bundle name
 * @tc.desc: Test ProcessAppFreeze when bundleName is scene board, callback should be called immediately.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(ModalSystemAppFreezeUiextensionTest, ProcessAppFreeze_001, TestSize.Level1)
{
    FaultData faultData;
    faultData.faultType = FaultDataType::APP_FREEZE;
    faultData.errorObject.name = AppFreezeType::THREAD_BLOCK_6S;
    faultData.waitSaveState = false;
    
    ModalSystemAppFreezeUIExtension::GetInstance().ProcessAppFreeze(true, faultData, "1234", "com.ohos.sceneboard",
        std::bind(&ModalSystemAppFreezeUiextensionTest::CallbackFunction, this));
    
    EXPECT_TRUE(callbackCalled);
}

/**
 * @tc.number: ProcessAppFreeze_002
 * @tc.name: ProcessAppFreeze with waitSaveState true
 * @tc.desc: Test ProcessAppFreeze when waitSaveState is true, callback should be called immediately.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(ModalSystemAppFreezeUiextensionTest, ProcessAppFreeze_002, TestSize.Level1)
{
    FaultData faultData;
    faultData.faultType = FaultDataType::APP_FREEZE;
    faultData.errorObject.name = AppFreezeType::THREAD_BLOCK_6S;
    faultData.waitSaveState = true;
    
    ModalSystemAppFreezeUIExtension::GetInstance().ProcessAppFreeze(true, faultData, "1234", "com.test.bundle",
        std::bind(&ModalSystemAppFreezeUiextensionTest::CallbackFunction, this));
    
    EXPECT_TRUE(callbackCalled);
}

/**
 * @tc.number: ProcessAppFreeze_003
 * @tc.name: ProcessAppFreeze with BUSSINESS_THREAD_BLOCK_6S
 * @tc.desc: Test ProcessAppFreeze when error name is BUSSINESS_THREAD_BLOCK_6S, function should return early.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(ModalSystemAppFreezeUiextensionTest, ProcessAppFreeze_003, TestSize.Level1)
{
    FaultData faultData;
    faultData.faultType = FaultDataType::APP_FREEZE;
    faultData.errorObject.name = AppFreezeType::BUSSINESS_THREAD_BLOCK_6S;
    faultData.waitSaveState = false;
    
    ModalSystemAppFreezeUIExtension::GetInstance().ProcessAppFreeze(true, faultData, "1234", "com.test.bundle",
        std::bind(&ModalSystemAppFreezeUiextensionTest::CallbackFunction, this));
    
    EXPECT_FALSE(callbackCalled);
}

/**
 * @tc.number: ProcessAppFreeze_004
 * @tc.name: ProcessAppFreeze with focus and THREAD_BLOCK_6S
 * @tc.desc: Test ProcessAppFreeze when focusFlag is true and error is THREAD_BLOCK_6S, should try to create dialog.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(ModalSystemAppFreezeUiextensionTest, ProcessAppFreeze_004, TestSize.Level1)
{
    FaultData faultData;
    faultData.faultType = FaultDataType::APP_FREEZE;
    faultData.errorObject.name = AppFreezeType::THREAD_BLOCK_6S;
    faultData.waitSaveState = false;
    faultData.appRunningUniqueId = "test_unique_id";
    
    ModalSystemAppFreezeUIExtension::GetInstance().ProcessAppFreeze(true, faultData, "1234", "com.test.bundle",
        std::bind(&ModalSystemAppFreezeUiextensionTest::CallbackFunction, this));
    
    EXPECT_FALSE(callbackCalled);
}

/**
 * @tc.number: ProcessAppFreeze_005
 * @tc.name: ProcessAppFreeze with focus and APP_INPUT_BLOCK
 * @tc.desc: Test ProcessAppFreeze when focusFlag is true and error is APP_INPUT_BLOCK, should try to create dialog.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(ModalSystemAppFreezeUiextensionTest, ProcessAppFreeze_005, TestSize.Level1)
{
    FaultData faultData;
    faultData.faultType = FaultDataType::APP_FREEZE;
    faultData.errorObject.name = AppFreezeType::APP_INPUT_BLOCK;
    faultData.waitSaveState = false;
    
    ModalSystemAppFreezeUIExtension::GetInstance().ProcessAppFreeze(true, faultData, "1234", "com.test.bundle",
        std::bind(&ModalSystemAppFreezeUiextensionTest::CallbackFunction, this));
    
    EXPECT_FALSE(callbackCalled);
}

/**
 * @tc.number: ProcessAppFreeze_006
 * @tc.name: ProcessAppFreeze with focus and BUSINESS_INPUT_BLOCK
 * @tc.desc: Test ProcessAppFreeze when focusFlag is true and error is
 * BUSINESS_INPUT_BLOCK, should try to create dialog.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(ModalSystemAppFreezeUiextensionTest, ProcessAppFreeze_006, TestSize.Level1)
{
    FaultData faultData;
    faultData.faultType = FaultDataType::APP_FREEZE;
    faultData.errorObject.name = AppFreezeType::BUSINESS_INPUT_BLOCK;
    faultData.waitSaveState = false;
    
    ModalSystemAppFreezeUIExtension::GetInstance().ProcessAppFreeze(true, faultData, "1234", "com.test.bundle",
        std::bind(&ModalSystemAppFreezeUiextensionTest::CallbackFunction, this));
    
    EXPECT_FALSE(callbackCalled);
}

/**
 * @tc.number: ProcessAppFreeze_007
 * @tc.name: ProcessAppFreeze with non-app-freeze fault type
 * @tc.desc: Test ProcessAppFreeze when faultType is not APP_FREEZE, callback should be called.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(ModalSystemAppFreezeUiextensionTest, ProcessAppFreeze_007, TestSize.Level1)
{
    FaultData faultData;
    faultData.faultType = FaultDataType::CPP_CRASH;
    faultData.errorObject.name = "SOME_OTHER_ERROR";
    faultData.waitSaveState = false;
    
    ModalSystemAppFreezeUIExtension::GetInstance().ProcessAppFreeze(true, faultData, "1234", "com.test.bundle",
        std::bind(&ModalSystemAppFreezeUiextensionTest::CallbackFunction, this));
    
    EXPECT_TRUE(callbackCalled);
}

/**
 * @tc.number: ProcessAppFreeze_008
 * @tc.name: ProcessAppFreeze with non-dialog error name
 * @tc.desc: Test ProcessAppFreeze when error name is not a dialog type, callback should be called.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(ModalSystemAppFreezeUiextensionTest, ProcessAppFreeze_008, TestSize.Level1)
{
    FaultData faultData;
    faultData.faultType = FaultDataType::APP_FREEZE;
    faultData.errorObject.name = "SOME_NON_DIALOG_ERROR";
    faultData.waitSaveState = false;
    
    ModalSystemAppFreezeUIExtension::GetInstance().ProcessAppFreeze(true, faultData, "1234", "com.test.bundle",
        std::bind(&ModalSystemAppFreezeUiextensionTest::CallbackFunction, this));
    
    EXPECT_TRUE(callbackCalled);
}

/**
 * @tc.number: ProcessAppFreeze_09
 * @tc.name: ProcessAppFreeze with null callback
 * @tc.desc: Test ProcessAppFreeze when callback is null, should not crash.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(ModalSystemAppFreezeUiextensionTest, ProcessAppFreeze_09, TestSize.Level1)
{
    FaultData faultData;
    faultData.faultType = FaultDataType::APP_FREEZE;
    faultData.errorObject.name = AppFreezeType::THREAD_BLOCK_6S;
    faultData.waitSaveState = false;
    
    ModalSystemAppFreezeUIExtension::GetInstance().ProcessAppFreeze(false, faultData, "1234", "com.test.bundle",
        nullptr);
    
    EXPECT_TRUE(true);
}

/**
 * @tc.number: ProcessAppFreeze_010
 * @tc.name: ProcessAppFreeze with invalid pid
 * @tc.desc: Test ProcessAppFreeze with invalid pid string.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(ModalSystemAppFreezeUiextensionTest, ProcessAppFreeze_010, TestSize.Level1)
{
    FaultData faultData;
    faultData.faultType = FaultDataType::APP_FREEZE;
    faultData.errorObject.name = AppFreezeType::THREAD_BLOCK_6S;
    faultData.waitSaveState = false;
    
    ModalSystemAppFreezeUIExtension::GetInstance().ProcessAppFreeze(true, faultData, "-1", "com.test.bundle",
        std::bind(&ModalSystemAppFreezeUiextensionTest::CallbackFunction, this));
    
    EXPECT_FALSE(callbackCalled);
}

/**
 * @tc.number: CreateModalUIExtension_001
 * @tc.name: DumpFfrt
 * @tc.desc: Test whether CreateModalUIExtension is called normally.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(ModalSystemAppFreezeUiextensionTest, CreateModalUIExtension_001, TestSize.Level1)
{
    std::string pid = "1";
    std::string bundleName = "Test";
    FaultData faultData;
    faultData.errorObject.name = "Test";
    faultData.appRunningUniqueId = "1";
    bool ret = ModalSystemAppFreezeUIExtension::GetInstance().CreateModalUIExtension(pid, bundleName, faultData);
    EXPECT_NE(ret, true);
}

/**
 * @tc.number: CreateSystemDialogWant_001
 * @tc.name: DumpFfrt
 * @tc.desc: Test whether CreateSystemDialogWant is called normally.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(ModalSystemAppFreezeUiextensionTest, CreateSystemDialogWant_001, TestSize.Level1)
{
    sptr<IRemoteObject> token;
    AAFwk::Want want;
    std::string pid = "1";
    std::string bundleName = "Test";
    FaultData faultData;
    faultData.errorObject.name = "Test";
    faultData.appRunningUniqueId = "1";
    bool ret = ModalSystemAppFreezeUIExtension::GetInstance().CreateSystemDialogWant(
        pid, bundleName, token, want, faultData);
    EXPECT_NE(ret, true);
}

}
}
