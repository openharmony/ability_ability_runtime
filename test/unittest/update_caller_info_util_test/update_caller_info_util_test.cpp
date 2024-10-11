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
#include "update_caller_info_util.h"
#include "ability_manager_service.h"
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
} // namespace AAFwk
} // namespace OHOS
