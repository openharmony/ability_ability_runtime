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
#include "ability_context_impl.h"
#include "ability_manager_client.h"
#include "hilog_tag_wrapper.h"
#include "mock_scene_board_judgement.h"
#include "scene_board_judgement.h"
#include "session/host/include/session.h"

namespace OHOS {
namespace Ace {
class UIContent;
}
namespace AppExecFwk {
using namespace testing::ext;
using namespace OHOS::AbilityRuntime;
using testing::Return;
namespace {
const std::string g_testLabel = "testLabel";
}

class AbilityContextImplSecondTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
public:
    std::unique_ptr<AbilityContextImpl> context_ = nullptr;
};

void AbilityContextImplSecondTest::SetUpTestCase(void)
{}

void AbilityContextImplSecondTest::TearDownTestCase(void)
{}

void AbilityContextImplSecondTest::SetUp(void)
{
    context_ = std::make_unique<AbilityContextImpl>();
}

void AbilityContextImplSecondTest::TearDown(void)
{}


/**
 * @tc.number: TerminateAbilityWithResult_0100
 * @tc.name: TerminateAbilityWithResult
 */
HWTEST_F(AbilityContextImplSecondTest, TerminateAbilityWithResult_0100, Function | MediumTest | Level1)
{
    Want want;
    int resultCode = 0;
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled()).Times(1).WillOnce(Return(false));
    ErrCode ret = context_->TerminateAbilityWithResult(want, resultCode);
    EXPECT_FALSE(ret == ERR_OK);

    Rosen::SessionInfo info;
    context_->sessionToken_ = wptr<IRemoteObject> (new Rosen::Session(info));
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled()).Times(1).WillOnce(Return(true));
    ret = context_->TerminateAbilityWithResult(want, resultCode);
    EXPECT_TRUE(ret == ERR_OK);

    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled()).Times(1).WillOnce(Return(true));
    ret = context_->TerminateAbilityWithResult(want, resultCode);
    EXPECT_FALSE(ret == ERR_OK);
}

/**
 * @tc.number: RequestDialogService_0100
 * @tc.name: SetAbilityInstanceInfo
 */
HWTEST_F(AbilityContextImplSecondTest, SetAbilityInstanceInfo_0100, Function | MediumTest | Level1)
{
    std::shared_ptr<OHOS::Media::PixelMap> icon = nullptr;
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled()).Times(1).WillOnce(Return(false));
    ErrCode ret = context_->SetAbilityInstanceInfo(g_testLabel, icon);
    EXPECT_TRUE(ret == ERR_CAPABILITY_NOT_SUPPORT);

    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled()).Times(1).WillOnce(Return(true));
    ret = context_->SetAbilityInstanceInfo(g_testLabel, icon);
    EXPECT_TRUE(ret == ERR_INVALID_VALUE);

    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled()).Times(1).WillOnce(Return(true));
    Rosen::SessionInfo info;
    context_->sessionToken_ = wptr<IRemoteObject> (new Rosen::Session(info));
    ret = context_->SetAbilityInstanceInfo(g_testLabel, icon);
    EXPECT_FALSE(ret == ERR_INVALID_VALUE);
}

} // namespace AppExecFwk
} // namespace OHOS