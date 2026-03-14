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
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest);
    auto Info = std::make_shared<AbilityRuntime::ExtensionRecord>(abilityRecord);
    Info->hostBundleName_ = "ExtensionRecordTest";
    Info->UnloadUIExtensionAbility();
    EXPECT_EQ(Info->preLoadUIExtStateObserver_, nullptr);
    TAG_LOGD(AAFwkTag::TEST, "UnloadUIExtensionAbility_001 called. end");
}

/*
 * Feature: CreateBaseExtensionRecord
 * Function: CreateBaseExtensionRecord
 * SubFunction: APP_SERVICE with TYPE process mode
 * FunctionPoints: Process name setting for APP_SERVICE extension
 * EnvConditions: NA
 * CaseDescription: Verify that APP_SERVICE extension with TYPE process mode gets correct process name
 */
HWTEST_F(ExtensionRecordTest, CreateBaseExtensionRecord_AppService_TypeProcess_001, TestSize.Level1)
{
    TAG_LOGD(AAFwkTag::TEST, "CreateBaseExtensionRecord_AppService_TypeProcess_001 called. start");

    // 准备测试数据 - APP_SERVICE类型，TYPE进程模式
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.test";
    abilityRequest.appInfo.name = "TestApp";
    abilityRequest.abilityInfo.name = "AppServiceAbility";
    abilityRequest.abilityInfo.type = AbilityType::EXTENSION;
    abilityRequest.abilityInfo.bundleName = "com.example.test";
    abilityRequest.abilityInfo.process = "";
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::APP_SERVICE;
    abilityRequest.extensionProcessMode = AppExecFwk::ExtensionProcessMode::TYPE;

    // 调用被测方法
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest);

    // 验证结果
    ASSERT_NE(abilityRecord, nullptr);
    EXPECT_EQ(abilityRecord->GetProcessName(), "com.example.test:AppServiceAbility");

    TAG_LOGD(AAFwkTag::TEST, "CreateBaseExtensionRecord_AppService_TypeProcess_001 called. end");
}

/*
 * Feature: CreateBaseExtensionRecord
 * Function: CreateBaseExtensionRecord
 * SubFunction: Non-APP_SERVICE extension
 * FunctionPoints: No special process name setting
 * EnvConditions: NA
 * CaseDescription: Verify that non-APP_SERVICE extension doesn't get special process name
 */
HWTEST_F(ExtensionRecordTest, CreateBaseExtensionRecord_NonAppService_002, TestSize.Level1)
{
    TAG_LOGD(AAFwkTag::TEST, "CreateBaseExtensionRecord_NonAppService_002 called. start");

    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.test2";
    abilityRequest.appInfo.name = "TestApp2";
    abilityRequest.abilityInfo.name = "UIServiceAbility";
    abilityRequest.abilityInfo.type = AbilityType::EXTENSION;
    abilityRequest.abilityInfo.bundleName = "com.example.test2";
    abilityRequest.abilityInfo.process = "com.example.test2:process";
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SERVICE;
    abilityRequest.extensionProcessMode = AppExecFwk::ExtensionProcessMode::TYPE;

    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest);

    ASSERT_NE(abilityRecord, nullptr);
    EXPECT_EQ(abilityRecord->GetProcessName(), "com.example.test2:process");

    TAG_LOGD(AAFwkTag::TEST, "CreateBaseExtensionRecord_NonAppService_002 called. end");
}

/*
 * Feature: CreateBaseExtensionRecord
 * Function: CreateBaseExtensionRecord
 * SubFunction: APP_SERVICE with non-TYPE process mode
 * FunctionPoints: No special process name setting for non-TYPE modes
 * EnvConditions: NA
 * CaseDescription: Verify that APP_SERVICE extension with non-TYPE process mode doesn't get special process name
 */
HWTEST_F(ExtensionRecordTest, CreateBaseExtensionRecord_AppService_NonTypeProcess_003, TestSize.Level1)
{
    TAG_LOGD(AAFwkTag::TEST, "CreateBaseExtensionRecord_AppService_NonTypeProcess_003 called. start");

    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.test3";
    abilityRequest.appInfo.name = "TestApp3";
    abilityRequest.abilityInfo.name = "AppServiceAbility";
    abilityRequest.abilityInfo.type = AbilityType::EXTENSION;
    abilityRequest.abilityInfo.bundleName = "com.example.test3";
    abilityRequest.abilityInfo.process = "com.example.test3:shared";
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::APP_SERVICE;
    abilityRequest.extensionProcessMode = AppExecFwk::ExtensionProcessMode::BUNDLE;

    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest);

    ASSERT_NE(abilityRecord, nullptr);

    EXPECT_EQ(abilityRecord->GetProcessName(), "com.example.test3:shared");

    TAG_LOGD(AAFwkTag::TEST, "CreateBaseExtensionRecord_AppService_NonTypeProcess_003 called. end");
}

/*
 * Feature: CreateBaseExtensionRecord
 * Function: CreateBaseExtensionRecord
 * SubFunction: Process name format validation
 * FunctionPoints: Correct bundle:name format
 * EnvConditions: NA
 * CaseDescription: Verify the exact format of process name for APP_SERVICE TYPE mode
 */
HWTEST_F(ExtensionRecordTest, CreateBaseExtensionRecord_ProcessNameFormat_004, TestSize.Level1)
{
    TAG_LOGD(AAFwkTag::TEST, "CreateBaseExtensionRecord_ProcessNameFormat_004 called. start");

    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.company.myapp";
    abilityRequest.appInfo.name = "MyApplication";
    abilityRequest.abilityInfo.name = "MyAppService";
    abilityRequest.abilityInfo.type = AbilityType::EXTENSION;
    abilityRequest.abilityInfo.bundleName = "com.company.myapp";
    abilityRequest.abilityInfo.process = "";
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::APP_SERVICE;
    abilityRequest.extensionProcessMode = AppExecFwk::ExtensionProcessMode::TYPE;

    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest);

    ASSERT_NE(abilityRecord, nullptr);
    EXPECT_EQ(abilityRecord->GetProcessName(), "com.company.myapp:MyAppService");

    std::string processName = abilityRecord->GetProcessName();
    size_t colonPos = processName.find(':');
    ASSERT_NE(colonPos, std::string::npos);
    EXPECT_EQ(processName.substr(0, colonPos), "com.company.myapp");
    EXPECT_EQ(processName.substr(colonPos + 1), "MyAppService");

    TAG_LOGD(AAFwkTag::TEST, "CreateBaseExtensionRecord_ProcessNameFormat_004 called. end");
}

}  // namespace AAFwk
}  // namespace OHOS
