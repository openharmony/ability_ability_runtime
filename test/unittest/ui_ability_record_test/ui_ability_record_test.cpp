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

#include "ui_ability_record.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
class UIAbilityRecordTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void UIAbilityRecordTest::SetUpTestCase(void)
{}
void UIAbilityRecordTest::TearDownTestCase(void)
{}
void UIAbilityRecordTest::SetUp()
{}
void UIAbilityRecordTest::TearDown()
{}

/**
 * @tc.name: ScheduleCollaborate_0010
 * @tc.desc: lifecycleDeal null or not.
 * @tc.type: FUNC
 */
HWTEST_F(UIAbilityRecordTest, ScheduleCollaborate_0010, TestSize.Level2)
{
    AbilityRequest abilityRequest;
    auto abilityRecord = UIAbilityRecord::CreateAbilityRecord(abilityRequest);
    abilityRecord->lifecycleDeal_ = nullptr;
    abilityRecord->ScheduleCollaborate(abilityRequest.want);

    auto lifecycleDeal = std::make_shared<LifecycleDeal>();
    abilityRecord->lifecycleDeal_ = lifecycleDeal;
    EXPECT_CALL(*lifecycleDeal, ScheduleCollaborate).Times(1);
    abilityRecord->ScheduleCollaborate(abilityRequest.want);
}
}  // namespace AAFwk
}  // namespace OHOS
