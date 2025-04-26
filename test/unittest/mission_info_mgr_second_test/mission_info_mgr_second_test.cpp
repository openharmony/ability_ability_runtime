/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "ability_info.h"
#include "ability_manager_errors.h"
#include "mission_info_mgr.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
class MissionInfoMgrSecondTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MissionInfoMgrSecondTest::SetUpTestCase(void)
{}
void MissionInfoMgrSecondTest::TearDownTestCase(void)
{}
void MissionInfoMgrSecondTest::SetUp(void)
{}
void MissionInfoMgrSecondTest::TearDown(void)
{}

/*
 * Feature: MissionInfoMgr
 * Function: UpdateMissionContinueState
 * SubFunction: NA
 */
HWTEST_F(MissionInfoMgrSecondTest, UpdateMissionContinueState_001, TestSize.Level1)
{
    auto missionInfoMgr = std::make_shared<MissionInfoMgr>();
    int32_t missionId = -1;
    AAFwk::ContinueState state = AAFwk::ContinueState::CONTINUESTATE_UNKNOWN;
    auto ret = missionInfoMgr->UpdateMissionContinueState(missionId, state);
    EXPECT_EQ(ret, -1);
}

/*
 * Feature: MissionInfoMgr
 * Function: UpdateMissionContinueState
 * SubFunction: NA
 */
HWTEST_F(MissionInfoMgrSecondTest, UpdateMissionContinueState_002, TestSize.Level1)
{
    auto missionInfoMgr = std::make_shared<MissionInfoMgr>();
    int32_t missionId = 1;
    AAFwk::ContinueState state = AAFwk::ContinueState::CONTINUESTATE_UNKNOWN;
    missionInfoMgr->missionInfoList_.clear();
    auto ret = missionInfoMgr->UpdateMissionContinueState(missionId, state);
    EXPECT_EQ(ret, -1);
}

/*
 * Feature: MissionInfoMgr
 * Function: UpdateMissionContinueState
 * SubFunction: NA
 */
HWTEST_F(MissionInfoMgrSecondTest, UpdateMissionContinueState_003, TestSize.Level1)
{
    auto missionInfoMgr = std::make_shared<MissionInfoMgr>();
    InnerMissionInfo mission;
    mission.missionInfo.id = 1;
    int32_t missionId = 1;
    AAFwk::ContinueState state = AAFwk::ContinueState::CONTINUESTATE_UNKNOWN;
    missionInfoMgr->missionInfoList_.push_back(mission);
    auto ret = missionInfoMgr->UpdateMissionContinueState(missionId, state);
    EXPECT_EQ(ret, 0);
}
}  // namespace AAFwk
}  // namespace OHOS
