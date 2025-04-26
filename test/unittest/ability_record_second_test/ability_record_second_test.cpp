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

#include "ability_record.h"
#include "app_utils.h"
#include "uri_utils.h"
#include "hilog_tag_wrapper.h"
#include "connection_record.h"
#include "mock_ability_connect_callback.h"
#include "mock_scene_board_judgement.h"

#include "ability_util.h"

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
constexpr int32_t INVALID_USER_ID = 100;
}

class AbilityRecordSecondTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<AbilityRecord> GetAbilityRecord();
    std::shared_ptr<AbilityRecord> abilityRecord_{ nullptr };
};

void AbilityRecordSecondTest::SetUpTestCase(void)
{}

void AbilityRecordSecondTest::TearDownTestCase(void)
{}

void AbilityRecordSecondTest::SetUp(void)
{
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    Want want;
    abilityRecord_ = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    abilityRecord_->Init();
}

void AbilityRecordSecondTest::TearDown(void)
{
    abilityRecord_.reset();
}

std::shared_ptr<AbilityRecord> AbilityRecordSecondTest::GetAbilityRecord()
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
* Function: IsSystemAbilityCall
* SubFunction: NA
*/
HWTEST_F(AbilityRecordSecondTest, AbilityRecord_IsSystemAbilityCall_001, TestSize.Level1)
{
    TAG_LOGE(AAFwkTag::TEST, "AbilityRecord_IsSystemAbilityCall_001 start.");
    std::shared_ptr<AbilityRecord> abilityRecord = GetAbilityRecord();
    sptr<IRemoteObject> callerToken = nullptr;
    uint32_t callingTokenId = 0;
    auto instanceKey = abilityRecord->IsSystemAbilityCall(callerToken, callingTokenId);
    EXPECT_EQ(instanceKey, false);
    std::shared_ptr<AbilityRecord> callerAbilityRecord = GetAbilityRecord();
    callerAbilityRecord->Init();
    callerToken = callerAbilityRecord->GetToken();
    instanceKey = abilityRecord->IsSystemAbilityCall(callerToken, callingTokenId);
    EXPECT_EQ(instanceKey, false);
    callerAbilityRecord = nullptr;
    callerToken = new Token(callerAbilityRecord);
    instanceKey = abilityRecord->IsSystemAbilityCall(callerToken, callingTokenId);
    EXPECT_EQ(instanceKey, false);
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled())
        .WillRepeatedly(testing::Return(true));
    instanceKey = abilityRecord->IsSystemAbilityCall(callerToken, callingTokenId);
    EXPECT_EQ(instanceKey, false);
    TAG_LOGE(AAFwkTag::TEST, "AbilityRecord_IsSystemAbilityCall_001 end.");
}

/*
* Feature: AbilityRecord
* Function: GetInProgressRecordCount
* SubFunction: NA
*/
HWTEST_F(AbilityRecordSecondTest, AbilityRecord_GetInProgressRecordCount_001, TestSize.Level1)
{
    TAG_LOGE(AAFwkTag::TEST, "AbilityRecord_GetInProgressRecordCount_001 start.");
    std::shared_ptr<AbilityRecord> abilityRecord = GetAbilityRecord();
    std::shared_ptr<ConnectionRecord> connections = nullptr;
    abilityRecord->connRecordList_.push_back(connections);
    auto res = abilityRecord->GetInProgressRecordCount();
    EXPECT_EQ(res, 0);
    abilityRecord->connRecordList_.clear();
    OHOS::sptr<IAbilityConnection> callback = new AbilityConnectCallback();
    std::shared_ptr<ConnectionRecord> connection1 =
        std::make_shared<ConnectionRecord>(abilityRecord->GetToken(), abilityRecord, callback, nullptr);
        connection1->SetConnectState(ConnectionState::CONNECTING);
    std::shared_ptr<ConnectionRecord> connection2 =
        std::make_shared<ConnectionRecord>(abilityRecord->GetToken(), abilityRecord, callback, nullptr);
        connection2->SetConnectState(ConnectionState::CONNECTED);
    std::shared_ptr<ConnectionRecord> connection3 =
        std::make_shared<ConnectionRecord>(abilityRecord->GetToken(), abilityRecord, callback, nullptr);
        connection3->SetConnectState(ConnectionState::DISCONNECTING);
    abilityRecord->connRecordList_.push_back(connection1);
    abilityRecord->connRecordList_.push_back(connection2);
    abilityRecord->connRecordList_.push_back(connection3);
    res = abilityRecord->GetInProgressRecordCount();
    EXPECT_EQ(res, 2);
    TAG_LOGE(AAFwkTag::TEST, "AbilityRecord_GetInProgressRecordCount_001 end.");
}

/*
* Feature: AbilityRecord
* Function: CovertAppExitReasonToLastReason
* SubFunction: NA
*/
HWTEST_F(AbilityRecordSecondTest, AbilityRecord_CovertAppExitReasonToLastReason_001, TestSize.Level1)
{
    TAG_LOGE(AAFwkTag::TEST, "AbilityRecord_CovertAppExitReasonToLastReason_001 start.");
    std::shared_ptr<AbilityRecord> abilityRecord = GetAbilityRecord();
    Reason exitReason;
    exitReason = REASON_NORMAL;
    auto res = abilityRecord->CovertAppExitReasonToLastReason(exitReason);
    EXPECT_EQ(res, LASTEXITREASON_NORMAL);
    exitReason = REASON_CPP_CRASH;
    res = abilityRecord->CovertAppExitReasonToLastReason(exitReason);
    EXPECT_EQ(res, LASTEXITREASON_CPP_CRASH);
    exitReason = REASON_JS_ERROR;
    res = abilityRecord->CovertAppExitReasonToLastReason(exitReason);
    EXPECT_EQ(res, LASTEXITREASON_JS_ERROR);
    exitReason = REASON_APP_FREEZE;
    res = abilityRecord->CovertAppExitReasonToLastReason(exitReason);
    EXPECT_EQ(res, LASTEXITREASON_APP_FREEZE);
    exitReason = REASON_PERFORMANCE_CONTROL;
    res = abilityRecord->CovertAppExitReasonToLastReason(exitReason);
    EXPECT_EQ(res, LASTEXITREASON_PERFORMANCE_CONTROL);
    exitReason = REASON_RESOURCE_CONTROL;
    res = abilityRecord->CovertAppExitReasonToLastReason(exitReason);
    EXPECT_EQ(res, LASTEXITREASON_RESOURCE_CONTROL);
    exitReason = REASON_UPGRADE;
    res = abilityRecord->CovertAppExitReasonToLastReason(exitReason);
    EXPECT_EQ(res, LASTEXITREASON_UPGRADE);
    exitReason = REASON_USER_REQUEST;
    res = abilityRecord->CovertAppExitReasonToLastReason(exitReason);
    EXPECT_EQ(res, LASTEXITREASON_USER_REQUEST);
    exitReason = REASON_SIGNAL;
    res = abilityRecord->CovertAppExitReasonToLastReason(exitReason);
    EXPECT_EQ(res, LASTEXITREASON_SIGNAL);
    exitReason = REASON_UNKNOWN;
    res = abilityRecord->CovertAppExitReasonToLastReason(exitReason);
    EXPECT_EQ(res, LASTEXITREASON_UNKNOWN);
    TAG_LOGE(AAFwkTag::TEST, "AbilityRecord_CovertAppExitReasonToLastReason_001 end.");
}

/*
* Feature: AbilityRecord
* Function: CallRequestDone
* SubFunction: NA
*/
HWTEST_F(AbilityRecordSecondTest, AbilityRecord_CallRequestDone_001, TestSize.Level1)
{
    TAG_LOGE(AAFwkTag::TEST, "AbilityRecord_CallRequestDone_001 start.");
    std::shared_ptr<AbilityRecord> abilityRecord = GetAbilityRecord();
    sptr<IRemoteObject> callStub = abilityRecord->GetToken();
    abilityRecord->callContainer_ = std::make_shared<CallContainer>();
    auto res = abilityRecord->CallRequestDone(callStub);
    EXPECT_EQ(res, false);
    callStub = nullptr;
    res = abilityRecord->CallRequestDone(callStub);
    EXPECT_EQ(res, false);
    abilityRecord->Init();
    sptr<IRemoteObject> callStubs = abilityRecord->GetToken();
    res = abilityRecord->CallRequestDone(callStubs);
    EXPECT_EQ(res, true);
    TAG_LOGE(AAFwkTag::TEST, "AbilityRecord_CallRequestDone_001 end.");
}

/*
* Feature: AbilityRecord
* Function: IsNeedToCallRequest
* SubFunction: NA
*/
HWTEST_F(AbilityRecordSecondTest, AbilityRecord_IsNeedToCallRequeste_001, TestSize.Level1)
{
    TAG_LOGE(AAFwkTag::TEST, "AbilityRecord_IsNeedToCallRequest_001 start.");
    std::shared_ptr<AbilityRecord> abilityRecord = GetAbilityRecord();
    abilityRecord->callContainer_ = std::make_shared<CallContainer>();
    auto res = abilityRecord->IsNeedToCallRequest();
    EXPECT_EQ(res, false);
    abilityRecord->callContainer_ = nullptr;
    res = abilityRecord->IsNeedToCallRequest();
    EXPECT_EQ(res, false);
    TAG_LOGE(AAFwkTag::TEST, "AbilityRecord_IsNeedToCallRequest_001 end.");
}

/*
* Feature: AbilityRecord
* Function: GetCurrentAccountId
* SubFunction: NA
*/
HWTEST_F(AbilityRecordSecondTest, AbilityRecord_GetCurrentAccountId_001, TestSize.Level1)
{
    TAG_LOGE(AAFwkTag::TEST, "AbilityRecord_GetCurrentAccountId_001 start.");
    std::shared_ptr<AbilityRecord> abilityRecord = GetAbilityRecord();
    auto res = abilityRecord->GetCurrentAccountId();
    EXPECT_EQ(res, INVALID_USER_ID);
    TAG_LOGE(AAFwkTag::TEST, "AbilityRecord_GetCurrentAccountId_001 end.");
}
}  // namespace AAFwk
}  // namespace OHOS