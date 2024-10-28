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

#include "gtest/gtest.h"

#define private public
#include "dialog_session_manager.h"
#undef private
#include "hilog_tag_wrapper.h"
#include "mock_ability_token.h"
#include "start_ability_utils.h"

using OHOS::AppExecFwk::AbilityType;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
namespace {
constexpr int32_t TEST_USER_ID = 10001;
constexpr int32_t TEST_ERMS_ISALLOW_RESULTCODE = 9;
const std::string TEST_BUNDLE_NAME = "com.test.demo";
const std::string TEST_DIALOG_SESSION_ID = "dialogSessionId";
}

class DialogSessionManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<AbilityRecord> MockAbilityRecord(AbilityType);
    sptr<Token> MockToken(AbilityType);
};

void DialogSessionManagerTest::SetUpTestCase(void)
{}

void DialogSessionManagerTest::TearDownTestCase(void)
{}

void DialogSessionManagerTest::SetUp()
{}

void DialogSessionManagerTest::TearDown()
{}

std::shared_ptr<AbilityRecord> DialogSessionManagerTest::MockAbilityRecord(AbilityType abilityType)
{
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = TEST_BUNDLE_NAME;
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = abilityType;
    return AbilityRecord::CreateAbilityRecord(abilityRequest);
}

sptr<Token> DialogSessionManagerTest::MockToken(AbilityType abilityType)
{
    std::shared_ptr<AbilityRecord> abilityRecord = MockAbilityRecord(abilityType);
    if (!abilityRecord) {
        return nullptr;
    }
    return abilityRecord->GetToken();
}

/**
 * @tc.name: GetStartupSessionInfoTest_0100
 * @tc.desc: Test GetStartupSessionInfo
 * @tc.type: FUNC
 */
HWTEST_F(DialogSessionManagerTest, GetStartupSessionInfoTest_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetStartupSessionInfoTest_0100 start";
    DialogSessionManager dialogSessionManager;
    std::shared_ptr<StartupSessionInfo> ret = dialogSessionManager.GetStartupSessionInfo(TEST_DIALOG_SESSION_ID);
    EXPECT_EQ(ret, nullptr);

    AbilityRequest abilityRequest;
    dialogSessionManager.SetStartupSessionInfo(TEST_DIALOG_SESSION_ID, abilityRequest);
    ret = dialogSessionManager.GetStartupSessionInfo(TEST_DIALOG_SESSION_ID);
    EXPECT_NE(ret, nullptr);
    GTEST_LOG_(INFO) << "GetStartupSessionInfoTest_0100 end";
}

/**
 * @tc.name: SendDialogResultTest_0100
 * @tc.desc: Test SendDialogResult
 * @tc.type: FUNC
 */
HWTEST_F(DialogSessionManagerTest, SendDialogResultTest_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendDialogResultTest_0100 start";
    AbilityRequest abilityRequest;
    DialogSessionManager dialogSessionManager;
    Want want;
    bool isAllowed = false;
    int32_t ret = dialogSessionManager.SendDialogResult(want, TEST_DIALOG_SESSION_ID, isAllowed);
    EXPECT_EQ(ret, ERR_OK);
    
    isAllowed = true;
    ret = dialogSessionManager.SendDialogResult(want, TEST_DIALOG_SESSION_ID, isAllowed);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    dialogSessionManager.SetStartupSessionInfo(TEST_DIALOG_SESSION_ID, abilityRequest);
    ret = dialogSessionManager.SendDialogResult(want, TEST_DIALOG_SESSION_ID, isAllowed);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "SendDialogResultTest_0100 end";
}

/**
 * @tc.name: SendDialogResultTest_0200
 * @tc.desc: Test SendDialogResult
 * @tc.type: FUNC
 */
HWTEST_F(DialogSessionManagerTest, SendDialogResultTest_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendDialogResultTest_0200 start";
    AbilityRequest abilityRequest;
    DialogSessionManager dialogSessionManager;
    Want want;
    bool isAllowed = true;
    sptr<DialogSessionInfo> dilogSessionInfo = nullptr;
    std::shared_ptr<DialogCallerInfo> dialogCallerInfo = std::make_shared<DialogCallerInfo>();

    dialogSessionManager.SetDialogSessionInfo(TEST_DIALOG_SESSION_ID, dilogSessionInfo, dialogCallerInfo);
    int32_t ret = dialogSessionManager.SendDialogResult(want, TEST_DIALOG_SESSION_ID, isAllowed);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    want.SetParam(Want::PARAM_APP_CLONE_INDEX_KEY, 0);
    ret = dialogSessionManager.SendDialogResult(want, TEST_DIALOG_SESSION_ID, isAllowed);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "SendDialogResultTest_0200 end";
}

/**
 * @tc.name: NotifySCBToRecoveryAfterInterceptionTest_0100
 * @tc.desc: Test NotifySCBToRecoveryAfterInterception
 * @tc.type: FUNC
 */
HWTEST_F(DialogSessionManagerTest, NotifySCBToRecoveryAfterInterceptionTest_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifySCBToRecoveryAfterInterceptionTest_0100 start";
    AbilityRequest abilityRequest;
    DialogSessionManager dialogSessionManager;

    int32_t ret = dialogSessionManager.NotifySCBToRecoveryAfterInterception(TEST_DIALOG_SESSION_ID, abilityRequest);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "NotifySCBToRecoveryAfterInterceptionTest_0100 end";
}

/**
 * @tc.name: CreateModalDialogCommonTest_0100
 * @tc.desc: Test CreateModalDialogCommon
 * @tc.type: FUNC
 */
HWTEST_F(DialogSessionManagerTest, CreateModalDialogCommonTest_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CreateModalDialogCommonTest_0100 start";
    Want replaceWant;
    sptr<IRemoteObject> callerToken = MockToken(AbilityType::PAGE);
    DialogSessionManager dialogSessionManager;

    int32_t ret = dialogSessionManager.CreateModalDialogCommon(replaceWant, callerToken, TEST_DIALOG_SESSION_ID);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    GTEST_LOG_(INFO) << "CreateModalDialogCommonTest_0100 end";
}

/**
 * @tc.name: IsCreateCloneSelectorDialogTest_0100
 * @tc.desc: Test IsCreateCloneSelectorDialog
 * @tc.type: FUNC
 */
HWTEST_F(DialogSessionManagerTest, IsCreateCloneSelectorDialogTest_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsCreateCloneSelectorDialogTest_0100 start";
    DialogSessionManager dialogSessionManager;

    StartAbilityUtils::isWantWithAppCloneIndex = true;
    bool ret = dialogSessionManager.IsCreateCloneSelectorDialog(TEST_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "IsCreateCloneSelectorDialogTest_0100 end";
}
}  // namespace AAFwk
}  // namespace OHOS
