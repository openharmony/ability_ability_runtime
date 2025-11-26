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
#define protected public
#include "data_ability_record.h"
#undef private
#undef protected

#include "ability_scheduler_mock.h"
#include "app_process_data.h"
#include "hilog_tag_wrapper.h"

using namespace testing::ext;
using namespace testing;
using namespace std::chrono;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
class DataAbilityRecordTest : public testing::TestWithParam<OHOS::AAFwk::AbilityState> {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    sptr<AbilitySchedulerMock> abilitySchedulerMock_{ nullptr };
    AbilityRequest abilityRequest_;
    std::shared_ptr<AbilityRecord> abilityRecord_{ nullptr };
    OHOS::AAFwk::AbilityState abilityState_;
};

void DataAbilityRecordTest::SetUpTestCase(void)
{}
void DataAbilityRecordTest::TearDownTestCase(void)
{}

void DataAbilityRecordTest::SetUp(void)
{
    if (abilitySchedulerMock_ == nullptr) {
        abilitySchedulerMock_ = new AbilitySchedulerMock();
    }

    abilityRequest_.appInfo.bundleName = "com.data_ability.hiworld";
    abilityRequest_.appInfo.name = "com.data_ability.hiworld";
    abilityRequest_.abilityInfo.name = "DataAbilityHiworld";
    abilityRequest_.abilityInfo.type = AbilityType::DATA;

    if (abilityRecord_ == nullptr) {
        OHOS::AppExecFwk::AbilityInfo abilityInfo;
        OHOS::AppExecFwk::ApplicationInfo applicationInfo;
        const Want want;
        abilityRecord_ = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
        abilityRecord_->Init(AbilityRequest());
    }
    abilityState_ = INITIAL;
}

void DataAbilityRecordTest::TearDown(void)
{
    abilitySchedulerMock_.clear();
}

/*
 * Feature: AbilityManager
 * Function: DataAbility
 * SubFunction: GetDiedCallerPid
 * FunctionPoints: The parameter of function GetDiedCallerPid.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function GetDiedCallerPid
 */
HWTEST_F(DataAbilityRecordTest, AaFwk_DataAbilityRecord_GetDiedCallerPid_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AaFwk_DataAbilityRecord_GetDiedCallerPid_001 start.");

    auto dataAbilityRecord = std::make_shared<DataAbilityRecord>(abilityRequest_);
    int32_t result = dataAbilityRecord->GetDiedCallerPid(nullptr);
    EXPECT_EQ(result, 0);

    TAG_LOGI(AAFwkTag::TEST, "AaFwk_DataAbilityRecord_GetDiedCallerPid_001 end.");
}

/*
 * Feature: AbilityManager
 * Function: DataAbility
 * SubFunction: GetDiedCallerPid
 * FunctionPoints: The parameter of function GetDiedCallerPid.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function GetDiedCallerPid
 */
HWTEST_F(DataAbilityRecordTest, AaFwk_DataAbilityRecord_GetDiedCallerPid_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AaFwk_DataAbilityRecord_GetDiedCallerPid_002 start.");

    auto dataAbilityRecord = std::make_shared<DataAbilityRecord>(abilityRequest_);
    dataAbilityRecord->clients_.clear();
    int32_t result = dataAbilityRecord->GetDiedCallerPid(abilityRecord_->GetToken());
    EXPECT_EQ(result, 0);
    
    TAG_LOGI(AAFwkTag::TEST, "AaFwk_DataAbilityRecord_GetDiedCallerPid_002 end.");
}

/*
 * Feature: AbilityManager
 * Function: DataAbility
 * SubFunction: GetDiedCallerPid
 * FunctionPoints: The parameter of function GetDiedCallerPid.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function GetDiedCallerPid
 */
HWTEST_F(DataAbilityRecordTest, AaFwk_DataAbilityRecord_GetDiedCallerPid_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AaFwk_DataAbilityRecord_GetDiedCallerPid_003 start.");

    auto dataAbilityRecord = std::make_shared<DataAbilityRecord>(abilityRequest_);
    DataAbilityRecord::ClientInfo clientInfo;
    dataAbilityRecord->clients_.push_back(clientInfo);
    int32_t result = dataAbilityRecord->GetDiedCallerPid(abilityRecord_->GetToken());
    EXPECT_EQ(result, 0);
    
    TAG_LOGI(AAFwkTag::TEST, "AaFwk_DataAbilityRecord_GetDiedCallerPid_003 end.");
}

/*
 * Feature: AbilityManager
 * Function: DataAbility
 * SubFunction: GetDiedCallerPid
 * FunctionPoints: The parameter of function GetDiedCallerPid.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function GetDiedCallerPid
 */
HWTEST_F(DataAbilityRecordTest, AaFwk_DataAbilityRecord_GetDiedCallerPid_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AaFwk_DataAbilityRecord_GetDiedCallerPid_004 start.");

    auto dataAbilityRecord = std::make_shared<DataAbilityRecord>(abilityRequest_);
    DataAbilityRecord::ClientInfo clientInfo;
    clientInfo.client = abilityRecord_->GetToken();
    clientInfo.clientPid = 1;
    dataAbilityRecord->clients_.push_back(clientInfo);
    int32_t result = dataAbilityRecord->GetDiedCallerPid(abilityRecord_->GetToken());
    EXPECT_EQ(result, 1);
    
    TAG_LOGI(AAFwkTag::TEST, "AaFwk_DataAbilityRecord_GetDiedCallerPid_004 end.");
}

/*
 * Feature: AbilityManager
 * Function: DataAbility
 * SubFunction: GetDiedCallerPid
 * FunctionPoints: The parameter of function GetDiedCallerPid.
 * EnvConditions: Can run ohos test framework
 * CaseDescription: Verify function GetDiedCallerPid
 */
HWTEST_F(DataAbilityRecordTest, AaFwk_DataAbilityRecord_GetClientCount_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AaFwk_DataAbilityRecord_GetClientCount_001 start.");

    auto dataAbilityRecord = std::make_shared<DataAbilityRecord>(abilityRequest_);
    dataAbilityRecord->ability_ = abilityRecord_;
    dataAbilityRecord->scheduler_ = abilitySchedulerMock_;
    dataAbilityRecord->ability_->SetAbilityState(ACTIVE);
    size_t result = dataAbilityRecord->GetClientCount(nullptr);
    EXPECT_EQ(result, 0);
    
    TAG_LOGI(AAFwkTag::TEST, "AaFwk_DataAbilityRecord_GetClientCount_001 end.");
}
}  // namespace AAFwk
}  // namespace OHOS
