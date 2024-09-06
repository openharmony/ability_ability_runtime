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
#include <memory>

#define private public
#define protected public
#include "extension_record.h"
#undef private
#undef protected

#include "ability_config.h"
#include "ability_manager_errors.h"
#include "ability_scheduler.h"
#include "ability_util.h"
#include "bundlemgr/mock_bundle_manager.h"
#include "hilog_tag_wrapper.h"
#include "mock_ability_connect_callback.h"
#include "mock_sa_call.h"
#include "mock_task_handler_wrap.h"
#include "sa_mgr_client.h"
#include "system_ability_definition.h"
#include <thread>
#include <chrono>

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using testing::_;
using testing::Return;

namespace {
    const int32_t SLEEP_TIME = 10000;
}
namespace OHOS {
namespace AAFwk {

class ExtensionRecordTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ExtensionRecordTest::SetUpTestCase(void)
{}
void ExtensionRecordTest::TearDownTestCase(void)
{}

void ExtensionRecordTest::SetUp()
{}
void ExtensionRecordTest::TearDown()
{}

/*
 * Feature: ExtensionRecordTest
 * Function: UnloadUIExtensionAbility
 * SubFunction: NA
 * FunctionPoints: UnloadUIExtensionAbility
 * EnvConditions:NA
 * CaseDescription: Verify the normal process of UnloadUIExtensionAbility
 */
HWTEST_F(ExtensionRecordTest, UnloadUIExtensionAbility_001, TestSize.Level1)
{
    TAG_LOGD(AAFwkTag::TEST, "UnloadUIExtensionAbility_001 called. start");
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.fuzzTest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::DATA;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    auto Info = std::make_shared<AbilityRuntime::ExtensionRecord>(abilityRecord);
    Info->hostBundleName_ = "ExtensionRecordTest";
    Info->UnloadUIExtensionAbility();
    EXPECT_EQ(Info->preLoadUIExtStateObserver_, nullptr);
    TAG_LOGD(AAFwkTag::TEST, "UnloadUIExtensionAbility_001 called. end");
}

}  // namespace AAFwk
}  // namespace OHOS
