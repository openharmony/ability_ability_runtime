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
#include "ui_extension_record.h"
#undef private

#include "session/host/include/session.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class UIExtensionRecordTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void UIExtensionRecordTest::SetUpTestCase()
{}

void UIExtensionRecordTest::TearDownTestCase()
{}

void UIExtensionRecordTest::SetUp()
{}

void UIExtensionRecordTest::TearDown()
{}

/**
 * @tc.number: Update_0100
 * @tc.name: Update
 * @tc.desc: Test whether Update and are called normally.
 */
HWTEST_F(UIExtensionRecordTest, Update_0100, TestSize.Level0)
{
    std::shared_ptr<AAFwk::AbilityRecord> abilityRecord = nullptr;
    auto extRecord = std::make_shared<AbilityRuntime::UIExtensionRecord>(abilityRecord);
    AAFwk::AbilityRequest abilityRequest;
    extRecord->Update(abilityRequest);
    EXPECT_EQ(abilityRecord, nullptr);
}

/**
 * @tc.number: Update_0200
 * @tc.name: Update
 * @tc.desc: Test whether Update and are called normally.
 */
HWTEST_F(UIExtensionRecordTest, Update_0200, TestSize.Level0)
{
    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;

    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    auto extRecord = std::make_shared<AbilityRuntime::UIExtensionRecord>(abilityRecord);
    extRecord->Update(abilityRequest);
    EXPECT_NE(abilityRecord, nullptr);
}

/**
 * @tc.number: HandleNotifyUIExtensionTimeout_0300
 * @tc.name: HandleNotifyUIExtensionTimeout
 * @tc.desc: Test whether HandleNotifyUIExtensionTimeout and are called normally.
 */
HWTEST_F(UIExtensionRecordTest, HandleNotifyUIExtensionTimeout_0300, TestSize.Level1)
{
    std::shared_ptr<AAFwk::AbilityRecord> abilityRecord = nullptr;
    auto extRecord = std::make_shared<AbilityRuntime::UIExtensionRecord>(abilityRecord);
    extRecord->HandleNotifyUIExtensionTimeout(AbilityRuntime::UIExtensionRecord::TERMINATE_TIMEOUT);
    EXPECT_EQ(abilityRecord, nullptr);

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;

    abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    extRecord = std::make_shared<AbilityRuntime::UIExtensionRecord>(abilityRecord);
    extRecord->HandleNotifyUIExtensionTimeout(AbilityRuntime::UIExtensionRecord::TERMINATE_TIMEOUT);
    EXPECT_NE(extRecord->abilityRecord_, nullptr);

    sptr<AAFwk::SessionInfo> sessionInfo(new AAFwk::SessionInfo());
    sessionInfo->uiExtensionComponentId = 10;
    sessionInfo->sessionToken = nullptr;
    abilityRequest.sessionInfo = sessionInfo;
    abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    extRecord = std::make_shared<AbilityRuntime::UIExtensionRecord>(abilityRecord);
    extRecord->HandleNotifyUIExtensionTimeout(AbilityRuntime::UIExtensionRecord::TERMINATE_TIMEOUT);
    EXPECT_NE(extRecord->abilityRecord_->GetSessionInfo(), nullptr);

    Rosen::SessionInfo info;
    sessionInfo->sessionToken = new Rosen::Session(info);
    abilityRequest.sessionInfo = sessionInfo;
    abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    extRecord = std::make_shared<AbilityRuntime::UIExtensionRecord>(abilityRecord);
    extRecord->HandleNotifyUIExtensionTimeout(AbilityRuntime::UIExtensionRecord::TERMINATE_TIMEOUT);
    EXPECT_NE(sessionInfo->sessionToken, nullptr);
}
}  // namespace OHOS
