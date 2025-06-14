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

#define private public
#include "ability_record.h"
#include "app_utils.h"
#undef private
#include "hilog_tag_wrapper.h"
#include "multi_instance_utils.h"
#include "parameters.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class MultiInstanceUtilsSecondTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void MultiInstanceUtilsSecondTest::SetUpTestCase(void) {}
void MultiInstanceUtilsSecondTest::TearDownTestCase(void) {}
void MultiInstanceUtilsSecondTest::SetUp() {}
void MultiInstanceUtilsSecondTest::TearDown() {}

/**
 * @tc.name: MultiInstanceUtils_GetValidExtensionInstanceKey_0100
 * @tc.desc: GetValidExtensionInstanceKey
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(MultiInstanceUtilsSecondTest, MultiInstanceUtils_GetValidExtensionInstanceKey_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "MultiInstanceUtils_GetValidExtensionInstanceKey_0100 start");
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::WORK_SCHEDULER;
    std::string key = MultiInstanceUtils::GetValidExtensionInstanceKey(abilityRequest);
    EXPECT_EQ(key, "app_instance_0");
    TAG_LOGI(AAFwkTag::TEST, "MultiInstanceUtils_GetValidExtensionInstanceKey_0100 end");
}

/**
 * @tc.name: MultiInstanceUtils_IsMultiInstanceApp_0100
 * @tc.desc: IsMultiInstanceApp
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(MultiInstanceUtilsSecondTest, MultiInstanceUtils_IsMultiInstanceApp_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "MultiInstanceUtils_IsMultiInstanceApp_0100 start");
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.multiAppMode.multiAppModeType = AppExecFwk::MultiAppModeType::UNSPECIFIED;
    auto ret = MultiInstanceUtils::IsMultiInstanceApp(abilityRequest.appInfo);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "MultiInstanceUtils_IsMultiInstanceApp_0100 end");
}

/**
 * @tc.name: MultiInstanceUtils_IsInstanceKeyExist_0100
 * @tc.desc: IsInstanceKeyExist
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(MultiInstanceUtilsSecondTest, MultiInstanceUtils_IsInstanceKeyExist_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "MultiInstanceUtils_IsInstanceKeyExist_0100 start");
    std::string bundleName = "123";
    std::string key = "";
    bool ret = MultiInstanceUtils::IsInstanceKeyExist(bundleName, "");
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "MultiInstanceUtils_IsInstanceKeyExist_0100 end");
}

/**
 * @tc.name: MultiInstanceUtils_IsInstanceKeyExist_0200
 * @tc.desc: IsInstanceKeyExist
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(MultiInstanceUtilsSecondTest, MultiInstanceUtils_IsInstanceKeyExist_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "MultiInstanceUtils_IsInstanceKeyExist_0200 start");
    std::string bundleName = "123";
    std::string key = "bundleName";
    bool ret = MultiInstanceUtils::IsInstanceKeyExist(bundleName, "");
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "MultiInstanceUtils_IsInstanceKeyExist_0200 end");
}
}  // namespace AAFwk
}  // namespace OHOS
