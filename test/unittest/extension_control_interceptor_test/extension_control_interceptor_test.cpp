/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "extension_control_interceptor.h"
#undef private

#include "ability_record.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
class ExtensionControlInterceptorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    sptr<Token> GetAbilityToken();
};

void ExtensionControlInterceptorTest::SetUpTestCase(void)
{}
void ExtensionControlInterceptorTest::TearDownTestCase(void)
{}
void ExtensionControlInterceptorTest::SetUp(void)
{}
void ExtensionControlInterceptorTest::TearDown(void)
{}

sptr<Token> ExtensionControlInterceptorTest::GetAbilityToken()
{
    sptr<Token> token = nullptr;
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.fuzzTest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::DATA;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    if (abilityRecord) {
        token = abilityRecord->GetToken();
    }
    return token;
}

/*
 * Feature: ExtensionControlInterceptorTest
 * Function: DoProcess
 */
HWTEST_F(ExtensionControlInterceptorTest, DoProcess_001, TestSize.Level1)
{
    std::shared_ptr<ExtensionControlInterceptor> extensionControlInterceptor =
        std::make_shared<ExtensionControlInterceptor>();
    Want want;
    int requestCode = 1;
    int32_t userId = 100;
    bool isWithUI = false;
    sptr<IRemoteObject> token = GetAbilityToken();
    auto shouldBlockFunc = []() { return false; };
    AbilityInterceptorParam param = AbilityInterceptorParam(want, requestCode, userId, isWithUI, token,
        shouldBlockFunc);
    extensionControlInterceptor->DoProcess(param);
    AbilityInterceptorParam param2 = AbilityInterceptorParam(want, requestCode, userId, isWithUI, nullptr,
        shouldBlockFunc);
    EXPECT_EQ(extensionControlInterceptor->DoProcess(param2), ERR_OK);
}

}
}