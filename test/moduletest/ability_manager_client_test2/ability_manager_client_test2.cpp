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

#include "ability_manager_client.h"
#include "ability_manager_errors.h"
#include "ability_state_data.h"
#include "element_name.h"
#include "hilog_tag_wrapper.h"
#include "ipc_object_stub.h"
#include "start_options.h"
#include "status_bar_delegate_proxy.h"
#include "ui_extension/ui_extension_session_info.h"
#include "want.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {

class AbilityManagerClientTest2 : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AbilityManagerClientTest2::SetUpTestCase(void)
{}

void AbilityManagerClientTest2::TearDownTestCase(void)
{}

void AbilityManagerClientTest2::SetUp()
{}

void AbilityManagerClientTest2::TearDown()
{}

/**
 * @tc.name: ForceTimeoutForTest_0100
 * @tc.desc: OpenLink
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerClientTest2, ForceTimeoutForTest_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "StartSelfUIAbility_0100 start");
    std::string abilityName = "com.example.abilityName";
    std::string state = "com.example.state";
    auto result = AbilityManagerClient::GetInstance()->ForceTimeoutForTest(abilityName, state);
    EXPECT_NE(result, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "StartSelfUIAbility_0100 end");
}
}  // namespace AAFwk
}  // namespace OHOS