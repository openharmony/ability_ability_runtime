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

#include <gtest/gtest.h>

#define private public
#define protected public
#include "ability_record.h"
#include "app_utils.h"
#undef private
#undef protected

#include "ability_util.h"
#include "uri_utils.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
namespace {
const std::string TEST_NATIVE_DEBUG = "nativeDebug";
const std::string TEST_PERF_CMD = "perfCmd";
const std::string TEST_MULTI_THREAD = "multiThread";
const std::string TEST_ERROR_INFO_ENHANCE = "errorInfoEnhance";
const std::string TEST_PARAMS_STREAM = "ability.params.stream";
}

class AbilityRecordFirstTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<AbilityRecord> GetAbilityRecord();

    std::shared_ptr<AbilityRecord> abilityRecord_{ nullptr };
};

void AbilityRecordFirstTest::SetUpTestCase(void)
{}

void AbilityRecordFirstTest::TearDownTestCase(void)
{}

void AbilityRecordFirstTest::SetUp(void)
{
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    Want want;
    abilityRecord_ = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    abilityRecord_->Init();
}

void AbilityRecordFirstTest::TearDown(void)
{
    abilityRecord_.reset();
}

std::shared_ptr<AbilityRecord> AbilityRecordFirstTest::GetAbilityRecord()
{
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    return std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
}

class MockWMSHandler : public IWindowManagerServiceHandler {
public:
    virtual void NotifyWindowTransition(sptr<AbilityTransitionInfo> fromInfo, sptr<AbilityTransitionInfo> toInfo,
        bool& animaEnabled)
    {}

    virtual int32_t GetFocusWindow(sptr<IRemoteObject>& abilityToken)
    {
        return 0;
    }

    virtual void StartingWindow(sptr<AbilityTransitionInfo> info,
        std::shared_ptr<Media::PixelMap> pixelMap, uint32_t bgColor) {}

    virtual void StartingWindow(sptr<AbilityTransitionInfo> info, std::shared_ptr<Media::PixelMap> pixelMap) {}

    virtual void CancelStartingWindow(sptr<IRemoteObject> abilityToken)
    {}

    virtual void NotifyAnimationAbilityDied(sptr<AbilityTransitionInfo> info)
    {}

    virtual int32_t MoveMissionsToForeground(const std::vector<int32_t>& missionIds, int32_t topMissionId)
    {
        return 0;
    }

    virtual int32_t MoveMissionsToBackground(const std::vector<int32_t>& missionIds, std::vector<int32_t>& result)
    {
        return 0;
    }

    virtual sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    }
};

/*
 * Feature: AbilityRecord
 * Function: SetWant
 * SubFunction: NA
 */
HWTEST_F(AbilityRecordFirstTest, AbilityRecord_SetWant_001, TestSize.Level1)
{
    Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo applicationInfo;
    Want nativeDebugWant;
    nativeDebugWant.SetParam(TEST_NATIVE_DEBUG, false);
    want.SetParam(TEST_NATIVE_DEBUG, true);
    AbilityRecord nativeDebugAbilityRecord(nativeDebugWant, abilityInfo, applicationInfo, 0);
    EXPECT_FALSE(nativeDebugAbilityRecord.GetWant().GetBoolParam(TEST_NATIVE_DEBUG, false));
    nativeDebugAbilityRecord.SetWant(want);
    EXPECT_FALSE(nativeDebugAbilityRecord.GetWant().GetBoolParam(TEST_NATIVE_DEBUG, false));
    Want perfCmdWant;
    std::string perfCmd = "perfCmd";
    std::string perfCmd1 = "perfCmd1";
    perfCmdWant.SetParam(TEST_PERF_CMD, perfCmd);
    perfCmdWant.SetParam(TEST_MULTI_THREAD, true);
    perfCmdWant.SetParam(TEST_ERROR_INFO_ENHANCE, true);
    AbilityRecord perfCmdWantAbilityRecord(perfCmdWant, abilityInfo, applicationInfo, 0);
    Want want1;
    want1.SetParam(TEST_PERF_CMD, perfCmd1);
    want1.SetParam(TEST_MULTI_THREAD, false);
    want1.SetParam(TEST_ERROR_INFO_ENHANCE, false);
    perfCmdWantAbilityRecord.SetWant(want1);
    EXPECT_STREQ(perfCmdWantAbilityRecord.GetWant().GetStringParam(TEST_PERF_CMD).c_str(), perfCmd.c_str());
    EXPECT_TRUE(perfCmdWantAbilityRecord.GetWant().GetBoolParam(TEST_MULTI_THREAD, true));
    EXPECT_TRUE(perfCmdWantAbilityRecord.GetWant().GetBoolParam(TEST_ERROR_INFO_ENHANCE, true));
}

/*
 * Feature: AbilityRecord
 * Function: CovertAppExitReasonToLastReason
 * SubFunction: NA
 */
HWTEST_F(AbilityRecordFirstTest, AbilityRecord_CovertAppExitReasonToLastReason_001, TestSize.Level1)
{
    EXPECT_EQ(abilityRecord_->CovertAppExitReasonToLastReason(AAFwk::Reason::REASON_NORMAL),
        AAFwk::LastExitReason::LASTEXITREASON_NORMAL);
    EXPECT_EQ(abilityRecord_->CovertAppExitReasonToLastReason(AAFwk::Reason::REASON_CPP_CRASH),
        AAFwk::LastExitReason::LASTEXITREASON_CPP_CRASH);
    EXPECT_EQ(abilityRecord_->CovertAppExitReasonToLastReason(AAFwk::Reason::REASON_JS_ERROR),
        AAFwk::LastExitReason::LASTEXITREASON_JS_ERROR);
    EXPECT_EQ(abilityRecord_->CovertAppExitReasonToLastReason(AAFwk::Reason::REASON_APP_FREEZE),
        AAFwk::LastExitReason::LASTEXITREASON_APP_FREEZE);
    EXPECT_EQ(abilityRecord_->CovertAppExitReasonToLastReason(AAFwk::Reason::REASON_PERFORMANCE_CONTROL),
        AAFwk::LastExitReason::LASTEXITREASON_PERFORMANCE_CONTROL);
    EXPECT_EQ(abilityRecord_->CovertAppExitReasonToLastReason(AAFwk::Reason::REASON_RESOURCE_CONTROL),
        AAFwk::LastExitReason::LASTEXITREASON_RESOURCE_CONTROL);
    EXPECT_EQ(abilityRecord_->CovertAppExitReasonToLastReason(AAFwk::Reason::REASON_UPGRADE),
        AAFwk::LastExitReason::LASTEXITREASON_UPGRADE);
    EXPECT_EQ(abilityRecord_->CovertAppExitReasonToLastReason(AAFwk::Reason::REASON_UNKNOWN),
        AAFwk::LastExitReason::LASTEXITREASON_UNKNOWN);
}

/*
 * Feature: AbilityRecord
 * Function: GrantPermissionToShell
 * SubFunction: NA
 */
HWTEST_F(AbilityRecordFirstTest, AbilityRecord_GrantPermissionToShell_001, TestSize.Level1)
{
    uint32_t flag = 0;
    Want want;
    want.SetUri("file://com.example.test/test.txt");
    std::vector<std::string> oriUriVec(50, "file://com.example.test/test.txt");
    want.SetParam(TEST_PARAMS_STREAM, oriUriVec);
    std::vector<std::string> uriVec;
    UriUtils::GetInstance().GetUriListFromWant(want, uriVec);
    std::string targetPkg = "";
    bool ret = abilityRecord_->GrantPermissionToShell(uriVec, flag, targetPkg);
    EXPECT_FALSE(ret);
}

/*
 * Feature: AbilityRecord
 * Function: GrantPermissionToShell
 * SubFunction: NA
 */
HWTEST_F(AbilityRecordFirstTest, AbilityRecord_GrantPermissionToShell_002, TestSize.Level1)
{
    uint32_t flag = 0;
    Want want;
    want.SetUri("content://com.example.app1001/data/storage/el2/base/haps/entry/files/test_1.txt");
    std::string str = "content://com.example.app1001/data/storage/el2/base/haps/entry/files/test_1.txt";
    std::vector<std::string> oriUriVec(50, str);
    want.SetParam(TEST_PARAMS_STREAM, oriUriVec);
    std::vector<std::string> uriVec;
    UriUtils::GetInstance().GetUriListFromWant(want, uriVec);
    std::string targetPkg = "";
    bool ret = abilityRecord_->GrantPermissionToShell(uriVec, flag, targetPkg);
    EXPECT_TRUE(ret);
}

/*
 * Feature: AbilityRecord
 * Function: SetWindowModeAndDisplayId
 * SubFunction: SetWindowModeAndDisplayId
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord SetWindowModeAndDisplayId
 */
HWTEST_F(AbilityRecordFirstTest, AaFwk_AbilityMS_SetWindowModeAndDisplayId_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AaFwk_AbilityMS_SetWindowModeAndDisplayId_002 start");
    std::shared_ptr<AbilityRecord> abilityRecord = GetAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    sptr<AbilityTransitionInfo> info = new AbilityTransitionInfo();
    std::shared_ptr<Want> want = std::make_shared<Want>();
    want->SetParam(Want::PARAM_RESV_WINDOW_MODE, 1);
    want->SetParam(Want::PARAM_RESV_DISPLAY_ID, 1);
    abilityRecord->SetWindowModeAndDisplayId(info, want);
    int32_t mode = want->GetIntParam(Want::PARAM_RESV_WINDOW_MODE, -1);
    int32_t displayId = want->GetIntParam(Want::PARAM_RESV_DISPLAY_ID, -1);
    EXPECT_EQ(mode, 1);
    EXPECT_EQ(displayId, 1);
    TAG_LOGI(AAFwkTag::TEST, "AaFwk_AbilityMS_SetWindowModeAndDisplayId_002 end");
}

/*
 * Feature: AbilityRecord
 * Function: SetWindowModeAndDisplayId
 * SubFunction: SetWindowModeAndDisplayId
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AbilityRecord SetWindowModeAndDisplayId
 */
HWTEST_F(AbilityRecordFirstTest, AaFwk_AbilityMS_SetWindowModeAndDisplayId_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AaFwk_AbilityMS_SetWindowModeAndDisplayId_003 start");
    std::shared_ptr<AbilityRecord> abilityRecord = GetAbilityRecord();
    EXPECT_NE(abilityRecord, nullptr);
    sptr<AbilityTransitionInfo> info = sptr<AbilityTransitionInfo>::MakeSptr();
    std::shared_ptr<Want> want = std::make_shared<Want>();
    want->SetParam(Want::PARAM_RESV_WINDOW_MODE, -1);
    want->SetParam(Want::PARAM_RESV_DISPLAY_ID, -1);
    abilityRecord->SetWindowModeAndDisplayId(info, want);
    int32_t mode = want->GetIntParam(Want::PARAM_RESV_WINDOW_MODE, -1);
    int32_t displayId = want->GetIntParam(Want::PARAM_RESV_DISPLAY_ID, -1);
    EXPECT_EQ(mode, -1);
    EXPECT_EQ(displayId, -1);
    TAG_LOGI(AAFwkTag::TEST, "AaFwk_AbilityMS_SetWindowModeAndDisplayId_003 end");
}
}  // namespace AAFwk
}  // namespace OHOS
