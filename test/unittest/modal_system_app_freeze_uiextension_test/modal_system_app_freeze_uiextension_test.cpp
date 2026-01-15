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
};

void ModalSystemAppFreezeUiextensionTest::SetUpTestCase(void)
{}

void ModalSystemAppFreezeUiextensionTest::TearDownTestCase(void)
{}

void ModalSystemAppFreezeUiextensionTest::SetUp(void)
{}

void ModalSystemAppFreezeUiextensionTest::TearDown(void)
{}

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
