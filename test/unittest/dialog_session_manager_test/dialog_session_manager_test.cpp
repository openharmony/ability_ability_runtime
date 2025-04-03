/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "ability_config.h"
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
    EXPECT_EQ(ret, ERR_NULL_INTERCEPTOR_EXECUTER);

    want.SetParam(Want::PARAM_APP_CLONE_INDEX_KEY, 0);
    ret = dialogSessionManager.SendDialogResult(want, TEST_DIALOG_SESSION_ID, isAllowed);
    EXPECT_EQ(ret, ERR_NULL_INTERCEPTOR_EXECUTER);
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

/**
 * @tc.name: UpdateExtensionWantWithDialogCallerInfo_0100
 * @tc.desc: callerToken is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DialogSessionManagerTest, UpdateExtensionWantWithDialogCallerInfo_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateExtensionWantWithDialogCallerInfo_0100 start";
    std::string dialogSessionId = "";
    AbilityRequest abilityRequest;
    bool isSCBCall = false;
    sptr<IRemoteObject> callerToken = nullptr;
    abilityRequest.want.SetParam(TEST_DIALOG_SESSION_ID, dialogSessionId);
    DialogSessionManager dialogSessionManager;
    auto ret = dialogSessionManager.UpdateExtensionWantWithDialogCallerInfo(abilityRequest, callerToken, isSCBCall);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "UpdateExtensionWantWithDialogCallerInfo_0100 end";
}

/**
 * @tc.name: UpdateExtensionWantWithDialogCallerInfo_0200
 * @tc.desc: dialogSessionId is empty
 * @tc.type: FUNC
 */
HWTEST_F(DialogSessionManagerTest, UpdateExtensionWantWithDialogCallerInfo_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateExtensionWantWithDialogCallerInfo_0200 start";
    std::string dialogSessionId = "";
    AbilityRequest abilityRequest;
    bool isSCBCall = false;
    sptr<IRemoteObject> callerToken = sptr<AppExecFwk::MockAbilityToken>::MakeSptr();
    abilityRequest.want.SetParam(TEST_DIALOG_SESSION_ID, dialogSessionId);
    DialogSessionManager dialogSessionManager;
    auto ret = dialogSessionManager.UpdateExtensionWantWithDialogCallerInfo(abilityRequest, callerToken, isSCBCall);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "UpdateExtensionWantWithDialogCallerInfo_0200 end";
}

/**
 * @tc.name: UpdateExtensionWantWithDialogCallerInfo_0300
 * @tc.desc: can not find dialogCallerInfo by dialogSessionId
 * @tc.type: FUNC
 */
HWTEST_F(DialogSessionManagerTest, UpdateExtensionWantWithDialogCallerInfo_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateExtensionWantWithDialogCallerInfo_0300 start";
    std::string dialogSessionId = "1000001";
    AbilityRequest abilityRequest;
    bool isSCBCall = false;
    sptr<IRemoteObject> callerToken = sptr<AppExecFwk::MockAbilityToken>::MakeSptr();
    abilityRequest.want.SetParam(TEST_DIALOG_SESSION_ID, dialogSessionId);
    DialogSessionManager dialogSessionManager;
    auto ret = dialogSessionManager.UpdateExtensionWantWithDialogCallerInfo(abilityRequest, callerToken, isSCBCall);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "UpdateExtensionWantWithDialogCallerInfo_0300 end";
}

/**
 * @tc.name: UpdateExtensionWantWithDialogCallerInfo_0400
 * @tc.desc: dialog callerInfo do not need grant uri permission
 * @tc.type: FUNC
 */
HWTEST_F(DialogSessionManagerTest, UpdateExtensionWantWithDialogCallerInfo_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateExtensionWantWithDialogCallerInfo_0400 start";
    std::string dialogSessionId = "1000001";
    AbilityRequest abilityRequest;
    bool isSCBCall = false;
    sptr<IRemoteObject> callerToken = sptr<AppExecFwk::MockAbilityToken>::MakeSptr();
    abilityRequest.want.SetParam(TEST_DIALOG_SESSION_ID, dialogSessionId);

    std::shared_ptr<DialogCallerInfo> dialogCallerInfo = std::make_shared<DialogCallerInfo>();
    dialogCallerInfo->needGrantUriPermission = false;
    DialogSessionManager dialogSessionManager;
    dialogSessionManager.dialogCallerInfoMap_[dialogSessionId] = dialogCallerInfo;
    auto ret = dialogSessionManager.UpdateExtensionWantWithDialogCallerInfo(abilityRequest, callerToken, isSCBCall);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "UpdateExtensionWantWithDialogCallerInfo_0400 end";
}

/**
 * @tc.name: UpdateExtensionWantWithDialogCallerInfo_0500
 * @tc.desc: do not have uri permission flag
 * @tc.type: FUNC
 */
HWTEST_F(DialogSessionManagerTest, UpdateExtensionWantWithDialogCallerInfo_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateExtensionWantWithDialogCallerInfo_0500 start";
    std::string dialogSessionId = "1000001";
    AbilityRequest abilityRequest;
    bool isSCBCall = false;
    sptr<IRemoteObject> callerToken = sptr<AppExecFwk::MockAbilityToken>::MakeSptr();
    abilityRequest.want.SetParam(TEST_DIALOG_SESSION_ID, dialogSessionId);

    std::shared_ptr<DialogCallerInfo> dialogCallerInfo = std::make_shared<DialogCallerInfo>();
    dialogCallerInfo->needGrantUriPermission = true;
    DialogSessionManager dialogSessionManager;
    dialogSessionManager.dialogCallerInfoMap_[dialogSessionId] = dialogCallerInfo;
    auto ret = dialogSessionManager.UpdateExtensionWantWithDialogCallerInfo(abilityRequest, callerToken, isSCBCall);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "UpdateExtensionWantWithDialogCallerInfo_0500 end";
}

/**
 * @tc.name: UpdateExtensionWantWithDialogCallerInfo_0600
 * @tc.desc: not scb call and have uri permission flag
 * @tc.type: FUNC
 */
HWTEST_F(DialogSessionManagerTest, UpdateExtensionWantWithDialogCallerInfo_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateExtensionWantWithDialogCallerInfo_0600 start";
    std::string dialogSessionId = "1000001";
    AbilityRequest abilityRequest;
    bool isSCBCall = false;
    sptr<IRemoteObject> callerToken = sptr<AppExecFwk::MockAbilityToken>::MakeSptr();
    abilityRequest.want.SetParam(TEST_DIALOG_SESSION_ID, dialogSessionId);

    std::shared_ptr<DialogCallerInfo> dialogCallerInfo = std::make_shared<DialogCallerInfo>();
    uint32_t flag = 1;
    dialogCallerInfo->targetWant.SetFlags(flag);
    dialogCallerInfo->needGrantUriPermission = true;

    DialogSessionManager dialogSessionManager;
    dialogSessionManager.dialogCallerInfoMap_[dialogSessionId] = dialogCallerInfo;
    auto ret = dialogSessionManager.UpdateExtensionWantWithDialogCallerInfo(abilityRequest, callerToken, isSCBCall);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "UpdateExtensionWantWithDialogCallerInfo_0600 end";
}

/**
 * @tc.name: UpdateExtensionWantWithDialogCallerInfo_0700
 * @tc.desc: scb call and have uri permission flag
 * @tc.type: FUNC
 */
HWTEST_F(DialogSessionManagerTest, UpdateExtensionWantWithDialogCallerInfo_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateExtensionWantWithDialogCallerInfo_0600 start";
    std::string dialogSessionId = "1000001";
    AbilityRequest abilityRequest;
    bool isSCBCall = true;
    sptr<IRemoteObject> callerToken = sptr<AppExecFwk::MockAbilityToken>::MakeSptr();
    abilityRequest.want.SetParam(TEST_DIALOG_SESSION_ID, dialogSessionId);

    std::shared_ptr<DialogCallerInfo> dialogCallerInfo = std::make_shared<DialogCallerInfo>();
    uint32_t flag = 1;
    std::string uri = "file://com.example.test/temp.txt";
    std::vector<std::string> uriVec = { uri };
    dialogCallerInfo->targetWant.SetFlags(flag);
    dialogCallerInfo->targetWant.SetUri(uri);
    dialogCallerInfo->targetWant.SetParam(AbilityConfig::PARAMS_STREAM, uriVec);
    dialogCallerInfo->needGrantUriPermission = true;

    DialogSessionManager dialogSessionManager;
    dialogSessionManager.dialogCallerInfoMap_[dialogSessionId] = dialogCallerInfo;
    auto ret = dialogSessionManager.UpdateExtensionWantWithDialogCallerInfo(abilityRequest, callerToken, isSCBCall);
    EXPECT_FALSE(ret);

    EXPECT_EQ(abilityRequest.want.GetFlags(), flag);
    EXPECT_EQ(abilityRequest.want.GetUriString(), uri);
    EXPECT_EQ(abilityRequest.want.GetStringArrayParam(AbilityConfig::PARAMS_STREAM).size(), 1);
    GTEST_LOG_(INFO) << "UpdateExtensionWantWithDialogCallerInfo_0700 end";
}
}  // namespace AAFwk
}  // namespace OHOS
