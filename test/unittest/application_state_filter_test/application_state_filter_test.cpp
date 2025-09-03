/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "application_state_filter.h"
#include "hilog_tag_wrapper.h"
#include "ipc_types.h"
#include "mock_app_mgr_service.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t INVAID_ID = 120;
}  // namespace

class ApplicationStateFilterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void ApplicationStateFilterTest::SetUpTestCase(void)
{}

void ApplicationStateFilterTest::TearDownTestCase(void)
{}

void ApplicationStateFilterTest::SetUp()
{}

void ApplicationStateFilterTest::TearDown()
{}

/**
 * @tc.name: ApplicationStateFilter_GetFilterTypeFromApplicationState_001
 * @tc.desc: GetFilterTypeFromApplicationState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateFilterTest, ApplicationStateFilter_GetFilterTypeFromApplicationState_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromApplicationState_001 start";
    auto result = GetFilterTypeFromApplicationState(ApplicationState::APP_STATE_CREATE);
    EXPECT_EQ(result, FilterAppStateType::CREATE);
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromApplicationState_001 end";
}

/**
 * @tc.name: ApplicationStateFilter_GetFilterTypeFromApplicationState_002
 * @tc.desc: GetFilterTypeFromApplicationState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateFilterTest, ApplicationStateFilter_GetFilterTypeFromApplicationState_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromApplicationState_002 start";
    auto result = GetFilterTypeFromApplicationState(static_cast<ApplicationState>(INVAID_ID));
    EXPECT_EQ(result, FilterAppStateType::NONE);
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromApplicationState_002 end";
}

/**
 * @tc.name: ApplicationStateFilter_GetFilterTypeFromAppProcessState_001
 * @tc.desc: GetFilterTypeFromAppProcessState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateFilterTest, ApplicationStateFilter_GetFilterTypeFromAppProcessState_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromAppProcessState_001 start";
    auto result = GetFilterTypeFromAppProcessState(AppProcessState::APP_STATE_CREATE);
    EXPECT_EQ(result, FilterProcessStateType::CREATE);
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromAppProcessState_001 end";
}

/**
 * @tc.name: ApplicationStateFilter_GetFilterTypeFromAppProcessState_002
 * @tc.desc: GetFilterTypeFromAppProcessState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateFilterTest, ApplicationStateFilter_GetFilterTypeFromAppProcessState_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromAppProcessState_002 start";
    auto result = GetFilterTypeFromAppProcessState(static_cast<AppProcessState>(INVAID_ID));
    EXPECT_EQ(result, FilterProcessStateType::NONE);
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromAppProcessState_002 end";
}

/**
 * @tc.name: ApplicationStateFilter_GetFilterTypeFromAbilityState_001
 * @tc.desc: GetFilterTypeFromAbilityState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateFilterTest, ApplicationStateFilter_GetFilterTypeFromAbilityState_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromAbilityState_001 start";
    auto result = GetFilterTypeFromAbilityState(AbilityState::ABILITY_STATE_CREATE);
    EXPECT_EQ(result, FilterAbilityStateType::CREATE);
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromAbilityState_001 end";
}

/**
 * @tc.name: ApplicationStateFilter_GetFilterTypeFromAbilityState_002
 * @tc.desc: GetFilterTypeFromAbilityState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateFilterTest, ApplicationStateFilter_GetFilterTypeFromAbilityState_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromAbilityState_002 start";
    auto result = GetFilterTypeFromAbilityState(static_cast<AbilityState>(INVAID_ID));
    EXPECT_EQ(result, FilterAbilityStateType::NONE);
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromAbilityState_002 end";
}

/**
 * @tc.name: ApplicationStateFilter_GetFilterTypeFromBundleType_001
 * @tc.desc: GetFilterTypeFromBundleType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateFilterTest, ApplicationStateFilter_GetFilterTypeFromBundleType_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromBundleType_001 start";
    auto result = GetFilterTypeFromBundleType(BundleType::APP);
    EXPECT_EQ(result, FilterBundleType::APP);
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromBundleType_001 end";
}

/**
 * @tc.name: ApplicationStateFilter_GetFilterTypeFromBundleType_002
 * @tc.desc: GetFilterTypeFromBundleType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateFilterTest, ApplicationStateFilter_GetFilterTypeFromBundleType_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromBundleType_002 start";
    auto result = GetFilterTypeFromBundleType(static_cast<BundleType>(INVAID_ID));
    EXPECT_EQ(result, FilterBundleType::NONE);
    GTEST_LOG_(INFO) << "ApplicationStateFilter_GetFilterTypeFromBundleType_002 end";
}
} // namespace AppExecFwk
} // namespace OHOS
