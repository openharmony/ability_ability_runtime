/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "ability_manager_client.h"
#include "ability_manager_stub_mock_second_test.h"
#include "ability_connect_manager.h"
#include "ability_manager_interface.h"
#undef private
#undef protected

#include "hilog_tag_wrapper.h"
#include "mock_ability_connect_callback.h"
#include "mock_ability_manager_collaborator.h"
#include "session/host/include/session.h"
#include "scene_board_judgement.h"
#include "status_bar_delegate_interface.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
namespace {
const int USER_ID = 100;
const size_t SIZE_ZERO = 0;
const std::string BUNDLE_NAME = "BUNDLE_NAME";
const std::string EMPTY_STRING = "";
}  // namespace

class AbilityManagerClientBranchSecondTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<AbilityManagerClient> client_{ nullptr };
    sptr<AbilityManagerStubTestMock> mock_{ nullptr };
    sptr<SessionInfo> MockSessionInfo(int32_t persistentId);
};

    sptr<SessionInfo> AbilityManagerClientBranchSecondTest::MockSessionInfo(int32_t persistentId)
{
    sptr<SessionInfo> sessionInfo = new (std::nothrow) SessionInfo();
    if (!sessionInfo) {
        TAG_LOGE(AAFwkTag::TEST, "sessionInfo is nullptr");
        return nullptr;
    }
    sessionInfo->persistentId = persistentId;
    return sessionInfo;
}

void AbilityManagerClientBranchSecondTest::SetUpTestCase(void)
{}
void AbilityManagerClientBranchSecondTest::TearDownTestCase(void)
{}
void AbilityManagerClientBranchSecondTest::TearDown()
{}

void AbilityManagerClientBranchSecondTest::SetUp()
{
    client_ = std::make_shared<AbilityManagerClient>();
    mock_ = new AbilityManagerStubTestMock();
    client_->proxy_ = mock_;
}

/**
 * @tc.name: AbilityManagerClient_AbilityWindowConfigTransitionDone_0100
 * @tc.desc: AbilityWindowConfigTransitionDone
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerClientBranchSecondTest, AbilityManagerClient_TransitionDone_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerClient_AbilityWindowConfigTransitionDone_0100 start";
    sptr<IRemoteObject> token = nullptr;
    WindowConfig windowConfig;
    ErrCode result = client_->AbilityWindowConfigTransitionDone(token, windowConfig);
    EXPECT_EQ(ERR_OK, result);
    GTEST_LOG_(INFO) << "AbilityManagerClient_AbilityWindowConfigTransitionDone_0100 end";
}

/**
 * @tc.name: AbilityManagerClient_CleanUIAbilityBySCB_0100
 * @tc.desc: CleanUIAbilityBySCB
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerClientBranchSecondTest, AbilityManagerClient_CleanUIAbilityBySCB_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerClient_CleanUIAbilityBySCB_0100 start";
    sptr<SessionInfo> sessionInfo = nullptr;
    ErrCode result = client_->CleanUIAbilityBySCB(sessionInfo);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "AbilityManagerClient_CleanUIAbilityBySCB_0100 end";
}

/**
 * @tc.name: AbilityManagerClient_TerminateMission_0100
 * @tc.desc: TerminateMission
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerClientBranchSecondTest, AbilityManagerClient_TerminateMission_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerClient_TerminateMission_0100 start";
    int32_t missionId = 1;
    ErrCode result = client_->TerminateMission(missionId);
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        EXPECT_EQ(result, ERR_OK);
    }
    EXPECT_NE(client_, nullptr);
    GTEST_LOG_(INFO) << "AbilityManagerClient_TerminateMission_0100 end";
}
}  // namespace AAFwk
}  // namespace OHOS