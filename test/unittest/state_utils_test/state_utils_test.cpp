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

#include "state_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class StateUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void StateUtilsTest::SetUpTestCase(void)
{}

void StateUtilsTest::TearDownTestCase(void)
{}

void StateUtilsTest::SetUp()
{}

void StateUtilsTest::TearDown()
{}

/**
 * @tc.number: StateUtilsTest_StateToStrMap_0100
 * @tc.desc: StateToStrMap
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(StateUtilsTest, StateUtilsTest_StateToStrMap_0100, TestSize.Level0)
{
    EXPECT_EQ(StateUtils::StateToStrMap(FOREGROUNDING), std::string("FOREGROUNDING"));
    EXPECT_EQ(StateUtils::StateToStrMap(BACKGROUNDING), std::string("BACKGROUNDING"));
    EXPECT_EQ(StateUtils::StateToStrMap(FOREGROUND_WINDOW_FREEZED), std::string("FOREGROUND_WINDOW_FREEZED"));
    EXPECT_EQ(StateUtils::StateToStrMap(FOREGROUND_DO_NOTHING), std::string("FOREGROUND_DO_NOTHING"));
    EXPECT_EQ(StateUtils::StateToStrMap(BACKGROUND_FAILED), std::string("BACKGROUND_FAILED"));
    EXPECT_EQ(StateUtils::StateToStrMap(static_cast<AbilityState>(-1)), std::string("INVALIDSTATE"));
}

/**
 * @tc.number: StateUtilsTest_AppStateToStrMap_0100
 * @tc.desc: AppStateToStrMap
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(StateUtilsTest, StateUtilsTest_AppStateToStrMap_0100, TestSize.Level0)
{
    EXPECT_EQ(StateUtils::AppStateToStrMap(AppState::BACKGROUND), std::string("BACKGROUND"));
    EXPECT_EQ(StateUtils::AppStateToStrMap(AppState::SUSPENDED), std::string("SUSPENDED"));
    EXPECT_EQ(StateUtils::AppStateToStrMap(AppState::TERMINATED), std::string("TERMINATED"));
    EXPECT_EQ(StateUtils::AppStateToStrMap(AppState::END), std::string("END"));
    EXPECT_EQ(StateUtils::AppStateToStrMap(AppState::FOCUS), std::string("FOCUS"));
    EXPECT_EQ(StateUtils::AppStateToStrMap(static_cast<AppState>(-1)), std::string("INVALIDSTATE"));
}

/**
 * @tc.number: StateUtilsTest_ConvertStateMap_0100
 * @tc.desc: ConvertStateMap
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(StateUtilsTest, StateUtilsTest_ConvertStateMap_0100, TestSize.Level0)
{
    EXPECT_EQ(StateUtils::ConvertStateMap(ABILITY_STATE_FOREGROUND_NEW), FOREGROUND);
    EXPECT_EQ(StateUtils::ConvertStateMap(ABILITY_STATE_WINDOW_FREEZED), FOREGROUND_WINDOW_FREEZED);
    EXPECT_EQ(StateUtils::ConvertStateMap(ABILITY_STATE_DO_NOTHING), FOREGROUND_DO_NOTHING);
    EXPECT_EQ(StateUtils::ConvertStateMap(ABILITY_STATE_BACKGROUND_FAILED), BACKGROUND_FAILED);
}

}  // namespace AAFwk
}  // namespace OHOS
