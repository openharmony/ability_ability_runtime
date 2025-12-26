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

#include <gtest/gtest.h>

#include "mock_permission_verification.h"
#define private public
#define protected public
#include "update_caller_info_util.h"
#include "ability_manager_service.h"
#include "dialog_session_manager.h"
#undef private
#undef protected
#include "ability_manager_errors.h"
#include "hilog_tag_wrapper.h"
#include "string_wrapper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::AppExecFwk::AbilityType;
using OHOS::AppExecFwk::ExtensionAbilityType;
namespace OHOS {
namespace AAFwk {

constexpr const char *CALLER_REQUEST_CODE = "ohos.extra.param.key.callerRequestCode";
constexpr const char *DMS_CALLER_BUNDLE_NAME = "ohos.dms.param.sourceCallerBundleName";

class UpdateCallerInfoUtilTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<AbilityRecord> MockAbilityRecord(AbilityType);
    sptr<Token> MockToken(AbilityType);
    sptr<SessionInfo> MockSessionInfo(int32_t persistentId);

public:
    AbilityRequest abilityRequest_{};
    Want want_{};
};

std::shared_ptr<AbilityRecord> UpdateCallerInfoUtilTest::MockAbilityRecord(AbilityType abilityType)
{
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.test.demo";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = abilityType;
    return AbilityRecord::CreateAbilityRecord(abilityRequest);
}

sptr<Token> UpdateCallerInfoUtilTest::MockToken(AbilityType abilityType)
{
    std::shared_ptr<AbilityRecord> abilityRecord = MockAbilityRecord(abilityType);
    if (!abilityRecord) {
        return nullptr;
    }
    return abilityRecord->GetToken();
}

sptr<SessionInfo> UpdateCallerInfoUtilTest::MockSessionInfo(int32_t persistentId)
{
    sptr<SessionInfo> sessionInfo = new (std::nothrow) SessionInfo();
    if (!sessionInfo) {
        TAG_LOGE(AAFwkTag::TEST, "sessionInfo is nullptr");
        return nullptr;
    }
    sessionInfo->persistentId = persistentId;
    return sessionInfo;
}

void UpdateCallerInfoUtilTest::SetUpTestCase() {}

void UpdateCallerInfoUtilTest::TearDownTestCase() {}

void UpdateCallerInfoUtilTest::SetUp() {}

void UpdateCallerInfoUtilTest::TearDown() {}

/**
 * @tc.name: UpdateCallerInfoUtilTest_UpdateAsCallerInfoFromCallerRecord_0001
 * @tc.desc: Test the state of QueryAllAutoStartupApplications
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, UpdateAsCallerInfoFromCallerRecord_0001, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    std::shared_ptr<AbilityRecord> abilityRecord = MockAbilityRecord(AbilityType::PAGE);
    callerToken = abilityRecord->GetToken();

    updateCallerUtil->UpdateAsCallerInfoFromCallerRecord(want, callerToken);
    EXPECT_NE(callerToken, nullptr);
}

/**
 * @tc.name: UpdateCallerInfoUtilTest_UpdateCallerInfoFromToken_0001
 * @tc.desc: Test the state of UpdateCallerInfoFromToken
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, UpdateCallerInfoFromToken_0001, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    std::shared_ptr<AbilityRecord> abilityRecord = MockAbilityRecord(AbilityType::PAGE);
    callerToken = abilityRecord->GetToken();

    updateCallerUtil->UpdateCallerInfoFromToken(want, callerToken);
    EXPECT_NE(abilityRecord, nullptr);

    abilityRecord = nullptr;
    updateCallerUtil->UpdateCallerInfoFromToken(want, callerToken);
    EXPECT_EQ(abilityRecord, nullptr);
}

/**
 * @tc.name: UpdateCallerInfoUtilTest_ClearProtectedWantParam_001
 * @tc.desc: The caller is not system app, remove udKey.
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, ClearProtectedWantParam_001, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    Want want;
    std::string key = "udmf://temp/key/aaa";
    want.SetParam(Want::PARAM_ABILITY_UNIFIED_DATA_KEY, key);
    updateCallerUtil->ClearProtectedWantParam(want);
    EXPECT_EQ(want.GetStringParam(Want::PARAM_ABILITY_UNIFIED_DATA_KEY), key);
}

/**
 * @tc.name: UpdateCallerInfoUtilTest_ClearProtectedWantParam_002
 * @tc.desc: The caller is system app, do not remove udKey.
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, ClearProtectedWantParam_002, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    Want want;
    std::string key = "udmf://temp/key/aaa";
    want.SetParam(Want::PARAM_ABILITY_UNIFIED_DATA_KEY, key);
    MyFlag::isSystemAppCallRet = false;
    updateCallerUtil->ClearProtectedWantParam(want);
    MyFlag::isSystemAppCallRet = true;
    EXPECT_EQ(want.GetStringParam(Want::PARAM_ABILITY_UNIFIED_DATA_KEY), "");
}

/**
 * @tc.name: UpdateCallerInfoUtilTest_ClearProtectedWantParam_003
 * @tc.desc: The caller is system app, do not remove udKey.
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, ClearProtectedWantParam_003, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    Want want;
    std::string key = "test";
    want.SetParam(Want::PARAM_RESV_CALLER_NATIVE_NAME, key);
    updateCallerUtil->ClearProtectedWantParam(want);
    EXPECT_EQ(want.GetStringParam(Want::PARAM_RESV_CALLER_NATIVE_NAME), "");
}

/**
 * @tc.name: UpdateCallerInfoUtilTest_UpdateAsCallerInfoFromCallerRecord_0002
 * @tc.desc: Test the state of QueryAllAutoStartupApplications
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, UpdateAsCallerInfoFromCallerRecord_0002, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    std::shared_ptr<AbilityRecord> abilityRecord = MockAbilityRecord(AbilityType::PAGE);
    callerToken = abilityRecord->GetToken();

    updateCallerUtil->UpdateAsCallerInfoFromCallerRecord(want, callerToken);
    EXPECT_NE(callerToken, nullptr);
}

/**
 * @tc.name: UpdateCallerInfoUtilTest_UpdateAsCallerInfoFromDialog_0001
 * @tc.desc: Test the state of QueryAllAutoStartupApplications
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, UpdateAsCallerInfoFromDialog_0001, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    DialogSessionManager dialogSessionManager;
    Want want;
    const std::string TEST_DIALOG_SESSION_ID = "dialogSessionId";
    want.SetParam(KEY_REQUEST_ID, std::string("1234567890"));
    sptr<DialogSessionInfo> dilogSessionInfo = nullptr;
    std::shared_ptr<DialogCallerInfo> dialogCallerInfo = std::make_shared<DialogCallerInfo>();
    EXPECT_NE(dialogCallerInfo, nullptr);
    dialogCallerInfo->targetWant = want;

    dialogSessionManager.SetDialogSessionInfo(TEST_DIALOG_SESSION_ID, dilogSessionInfo, dialogCallerInfo);
    auto callerInfo = dialogSessionManager.GetDialogCallerInfo(TEST_DIALOG_SESSION_ID);
    EXPECT_NE(dialogSessionManager.GetDialogCallerInfo(TEST_DIALOG_SESSION_ID), nullptr);

    bool ret = updateCallerUtil->UpdateAsCallerInfoFromDialog(want);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: UpdateCallerInfoUtilTest_UpdateAsCallerInfoFromDialog_0002
 * @tc.desc: Test the state of QueryAllAutoStartupApplications
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, UpdateAsCallerInfoFromDialog_0002, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    DialogSessionManager dialogSessionManager;
    Want want;
    bool ret = updateCallerUtil->UpdateAsCallerInfoFromDialog(want);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: UpdateCallerInfoUtilTest_UpdateAsCallerInfoFromDialog_0003
 * @tc.desc: Test UpdateAsCallerInfoFromDialog with BROKER_UID
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, UpdateAsCallerInfoFromDialog_0003, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    DialogSessionManager dialogSessionManager;
    Want want;
    const std::string TEST_DIALOG_SESSION_ID = "dialogSessionId";
    want.SetParam(Want::PARAM_RESV_CALLER_UID, 5557);
    sptr<DialogSessionInfo> dilogSessionInfo = nullptr;
    std::shared_ptr<DialogCallerInfo> dialogCallerInfo = std::make_shared<DialogCallerInfo>();
    EXPECT_NE(dialogCallerInfo, nullptr);
    dialogCallerInfo->targetWant = want;

    dialogSessionManager.SetDialogSessionInfo(TEST_DIALOG_SESSION_ID, dilogSessionInfo, dialogCallerInfo);
    auto callerInfo = dialogSessionManager.GetDialogCallerInfo(TEST_DIALOG_SESSION_ID);
    EXPECT_NE(callerInfo, nullptr);

    bool ret = updateCallerUtil->UpdateAsCallerInfoFromDialog(want);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: UpdateCallerInfoUtilTest_UpdateAsCallerInfoFromToken_0001
 * @tc.desc: Test the state of UpdateAsCallerInfoFromToken
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, UpdateAsCallerInfoFromToken_0001, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    ASSERT_NE(updateCallerUtil, nullptr);
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    updateCallerUtil->UpdateAsCallerInfoFromToken(want, callerToken);
    auto bundleName = want.GetStringParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME);
    EXPECT_TRUE(bundleName.empty());
}

/**
 * @tc.name: UpdateCallerInfoUtilTest_UpdateAsCallerInfoFromToken_0002
 * @tc.desc: Test the state of UpdateAsCallerInfoFromToken
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, UpdateAsCallerInfoFromToken_0002, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    ASSERT_NE(updateCallerUtil, nullptr);
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    std::shared_ptr<AbilityRecord> abilityRecord = MockAbilityRecord(AbilityType::PAGE);
    ASSERT_NE(abilityRecord, nullptr);
    callerToken = abilityRecord->GetToken();
    updateCallerUtil->UpdateAsCallerInfoFromToken(want, callerToken);
    EXPECT_TRUE(want.HasParameter(Want::PARAM_RESV_CALLER_TOKEN));
}

/**
 * @tc.name: UpdateCallerInfoUtilTest_UpdateBackToCallerFlag_0001
 * @tc.desc: Test the state of UpdateBackToCallerFlag
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, UpdateBackToCallerFlag_0001, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    ASSERT_NE(updateCallerUtil, nullptr);
    Want want;
    want.SetParam(OHOS::AAFwk::CALLER_REQUEST_CODE, 0);
    sptr<IRemoteObject> callerToken = nullptr;
    std::shared_ptr<AbilityRecord> abilityRecord = MockAbilityRecord(AbilityType::PAGE);
    ASSERT_NE(abilityRecord, nullptr);
    callerToken = abilityRecord->GetToken();
    int32_t requestCode = 0;
    bool backFlag = true;
    updateCallerUtil->UpdateBackToCallerFlag(callerToken, want, requestCode, backFlag);
    EXPECT_FALSE(want.HasParameter(OHOS::AAFwk::CALLER_REQUEST_CODE));
}

/**
 * @tc.name: UpdateCallerInfoUtilTest_UpdateBackToCallerFlag_0002
 * @tc.desc: Test the state of UpdateBackToCallerFlag
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, UpdateBackToCallerFlag_0002, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    ASSERT_NE(updateCallerUtil, nullptr);
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    std::shared_ptr<AbilityRecord> abilityRecord = MockAbilityRecord(AbilityType::PAGE);
    ASSERT_NE(abilityRecord, nullptr);
    callerToken = abilityRecord->GetToken();
    int32_t requestCode = 0;
    bool backFlag = true;
    updateCallerUtil->UpdateBackToCallerFlag(callerToken, want, requestCode, backFlag);
    EXPECT_FALSE(want.HasParameter(OHOS::AAFwk::CALLER_REQUEST_CODE));
}

/**
 * @tc.name: UpdateCallerInfoUtilTest_UpdateBackToCallerFlag_0003
 * @tc.desc: Test the state of UpdateBackToCallerFlag
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, UpdateBackToCallerFlag_0003, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    ASSERT_NE(updateCallerUtil, nullptr);
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    std::shared_ptr<AbilityRecord> abilityRecord = MockAbilityRecord(AbilityType::PAGE);
    ASSERT_NE(abilityRecord, nullptr);
    callerToken = abilityRecord->GetToken();
    int32_t requestCode = 1;
    bool backFlag = true;
    updateCallerUtil->UpdateBackToCallerFlag(callerToken, want, requestCode, backFlag);
    EXPECT_TRUE(want.HasParameter(OHOS::AAFwk::CALLER_REQUEST_CODE));
}

/**
 * @tc.name: UpdateCallerInfoUtilTest_UpdateDmsCallerInfo_0001
 * @tc.desc: Test the state of UpdateDmsCallerInfo
 * @tc.type: FUNC
 */
HWTEST_F(UpdateCallerInfoUtilTest, UpdateDmsCallerInfo_0001, TestSize.Level1)
{
    std::shared_ptr<UpdateCallerInfoUtil> updateCallerUtil = std::make_shared<UpdateCallerInfoUtil>();
    ASSERT_NE(updateCallerUtil, nullptr);
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    std::shared_ptr<AbilityRecord> abilityRecord = MockAbilityRecord(AbilityType::PAGE);
    ASSERT_NE(abilityRecord, nullptr);
    callerToken = abilityRecord->GetToken();
    updateCallerUtil->UpdateDmsCallerInfo(want, callerToken);
    EXPECT_TRUE(want.HasParameter(OHOS::AAFwk::DMS_CALLER_BUNDLE_NAME));
}
} // namespace AAFwk
} // namespace OHOS
