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
#include "app_utils.h"
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

/**
 * @tc.number: RestartAppWithWindow_0100
 * @tc.name: RestartAppWithWindow
 */
HWTEST_F(AbilityContextImplSecondTest, RestartAppWithWindow_0100, Function | MediumTest | Level1)
{
    Want want;
    context_->abilityInfo_ = nullptr;
    ErrCode ret = context_->RestartAppWithWindow(want);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    context_->abilityInfo_ = std::make_shared<AppExecFwk::AbilityInfo>();
    context_->abilityInfo_->bundleName.clear();
    ret = context_->RestartAppWithWindow(want);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    context_->abilityInfo_->bundleName = "testBundleName";
    context_->abilityInfo_->name.clear();
    ret = context_->RestartAppWithWindow(want);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    context_->abilityInfo_->name = "testAbilityName";
    ret = context_->RestartAppWithWindow(want);
    EXPECT_EQ(ret, AAFwk::ERR_RESTART_APP_INCORRECT_ABILITY);

    want.SetElementName("testBundleName2", "");
    ret = context_->RestartAppWithWindow(want);
    EXPECT_EQ(ret, AAFwk::ERR_RESTART_APP_INCORRECT_ABILITY);

    want.SetElementName("testBundleName", "");
    ret = context_->RestartAppWithWindow(want);
    EXPECT_EQ(ret, AAFwk::ERR_RESTART_APP_INCORRECT_ABILITY);

    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled).Times(1).WillOnce(Return(false));
    want.SetElementName("testBundleName", "testAbilityName");
    ret = context_->RestartAppWithWindow(want);
    EXPECT_EQ(ret, AAFwk::ERR_CAPABILITY_NOT_SUPPORT);

    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled)
        .Times(2).WillRepeatedly(Return(true));
    AAFwk::AppUtils::GetInstance().isSupportRestartAppWithWindow_.isLoaded = true;
    AAFwk::AppUtils::GetInstance().isSupportRestartAppWithWindow_.value = false;
    ret = context_->RestartAppWithWindow(want);
    EXPECT_EQ(ret, AAFwk::ERR_CAPABILITY_NOT_SUPPORT);

    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled).Times(1).WillOnce(Return(true));
    AAFwk::AppUtils::GetInstance().isSupportRestartAppWithWindow_.value = true;
    ret = context_->RestartAppWithWindow(want);
    EXPECT_EQ(ret, AAFwk::ERR_INVALID_VALUE);
}

#ifdef SUPPORT_SCREEN
/**
 * @tc.number: TransferRestartWSError_0100
 * @tc.name: TransferRestartWSError
 */
HWTEST_F(AbilityContextImplSecondTest, TransferRestartWSError_0100, Function | MediumTest | Level1)
{
    auto srcCode = Rosen::WSError::WS_OK;
    EXPECT_EQ(TransferRestartWSError(srcCode), ERR_OK);

    srcCode = Rosen::WSError::WS_ERROR_INVALID_OPERATION;
    EXPECT_EQ(TransferRestartWSError(srcCode), AAFwk::ERR_RESTART_APP_INCORRECT_ABILITY);

    srcCode = Rosen::WSError::WS_ERROR_SET_SESSION_LABEL_FAILED;
    EXPECT_EQ(TransferRestartWSError(srcCode), ERR_INVALID_VALUE);
}
#endif
} // namespace AppExecFwk
} // namespace OHOS