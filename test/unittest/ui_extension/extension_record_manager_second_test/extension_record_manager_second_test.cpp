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

#include "hilog_tag_wrapper.h"
#include "ability_manager_client.h"

#define private public
#define protected public
#define inline
#include "extension_record.h" 
#include "extension_record_manager.h"
#define inline
#undef protected
#undef private

#include "mock_ability_token.h"
#include "mock_native_token.h"
#include "scene_board_judgement.h"
#include "session_info.h"
#include "bool_wrapper.h"
#include "mock_my_flag.h"
#include "mock_permission_verification.h"
#include "mock_sa_call.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class ExtensionRecordManagerSecondTest : public testing::Test {
public:

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void ExtensionRecordManagerSecondTest::SetUpTestCase(void)
{}

void ExtensionRecordManagerSecondTest::TearDownTestCase(void)
{}

void ExtensionRecordManagerSecondTest::SetUp()
{}

void ExtensionRecordManagerSecondTest::TearDown()
{}

/**
 * @tc.name: RemovePreloadUIExtensionRecord_0100
 * @tc.desc: Test RemovePreloadUIExtensionRecord.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerSecondTest, RemovePreloadUIExtensionRecord_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    ExtensionRecordManager::PreLoadUIExtensionMapKey extensionRecordMapKey;
    EXPECT_FALSE(extRecordMgr->RemovePreloadUIExtensionRecord(extensionRecordMapKey));

    std::vector<std::shared_ptr<ExtensionRecord>> v_ExtensionRecord;
    extRecordMgr->preloadUIExtensionMap_[extensionRecordMapKey] = v_ExtensionRecord;
    EXPECT_TRUE(extRecordMgr->RemovePreloadUIExtensionRecord(extensionRecordMapKey));

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);
    auto extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    v_ExtensionRecord.push_back(extRecord);
    extRecordMgr->preloadUIExtensionMap_[extensionRecordMapKey] = v_ExtensionRecord;
    EXPECT_TRUE(extRecordMgr->RemovePreloadUIExtensionRecord(extensionRecordMapKey));
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GetRootCallerTokenLocked_0100
 * @tc.desc: Test GetRootCallerTokenLocked.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerSecondTest, GetRootCallerTokenLocked_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    int32_t extensionRecordId = 0;
    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    EXPECT_EQ(extRecordMgr->GetRootCallerTokenLocked(extensionRecordId, abilityRecord), nullptr);

    std::shared_ptr<ExtensionRecord> extRecord = nullptr;
    extRecordMgr->extensionRecords_[extensionRecordId] = extRecord;
    EXPECT_EQ(extRecordMgr->GetRootCallerTokenLocked(extensionRecordId, abilityRecord), nullptr);

    extRecordMgr->extensionRecords_.clear();
    extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    sptr<IRemoteObject> rootCallerToken = nullptr;
    extRecord->SetRootCallerToken(rootCallerToken);
    extRecordMgr->extensionRecords_[extensionRecordId] = extRecord;
    EXPECT_EQ(extRecordMgr->GetRootCallerTokenLocked(extensionRecordId, abilityRecord), nullptr);

    rootCallerToken = sptr<AppExecFwk::MockAbilityToken>::MakeSptr();
    extRecord->SetRootCallerToken(rootCallerToken);
    extRecordMgr->extensionRecords_.clear();
    extRecordMgr->extensionRecords_[extensionRecordId] = extRecord;
    EXPECT_NE(extRecordMgr->GetRootCallerTokenLocked(extensionRecordId, abilityRecord), nullptr);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GetUIExtensionSessionInfo_0100
 * @tc.desc: Test GetUIExtensionSessionInfo.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerSecondTest, GetUIExtensionSessionInfo_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    sptr<IRemoteObject> token = nullptr;
    UIExtensionSessionInfo uiExtensionSessionInfo;
    EXPECT_EQ(extRecordMgr->GetUIExtensionSessionInfo(token, uiExtensionSessionInfo), ERR_NULL_OBJECT);

    token = sptr<AppExecFwk::MockAbilityToken>::MakeSptr();
    EXPECT_EQ(extRecordMgr->GetUIExtensionSessionInfo(token, uiExtensionSessionInfo), ERR_NULL_OBJECT);

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    token = abilityRecord->GetToken();
    EXPECT_EQ(extRecordMgr->GetUIExtensionSessionInfo(token, uiExtensionSessionInfo), ERR_INVALID_VALUE);

    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SHARE;
    EXPECT_EQ(extRecordMgr->GetUIExtensionSessionInfo(token, uiExtensionSessionInfo), ERR_NULL_OBJECT);

    abilityRecord->sessionInfo_ = sptr<AAFwk::SessionInfo>::MakeSptr();
    EXPECT_EQ(extRecordMgr->GetUIExtensionSessionInfo(token, uiExtensionSessionInfo), ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CreateExtensionRecord_0100
 * @tc.desc: Test CreateExtensionRecord.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerSecondTest, CreateExtensionRecord_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    AAFwk::AbilityRequest abilityRequest;
    std::string hostBundleName("hostBundleName");
    std::shared_ptr<ExtensionRecord> extensionRecord;
    int32_t extensionRecordId = 0;
    EXPECT_EQ(extRecordMgr->CreateExtensionRecord(
        abilityRequest, hostBundleName, extensionRecord, extensionRecordId), ERR_INVALID_VALUE);

    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SHARE;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    extensionRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    EXPECT_EQ(extRecordMgr->CreateExtensionRecord(
        abilityRequest, hostBundleName, extensionRecord, extensionRecordId), ERR_OK);

    abilityRequest.extensionType = AppExecFwk::ExtensionAbilityType::EMBEDDED_UI;
    EXPECT_EQ(extRecordMgr->CreateExtensionRecord(
        abilityRequest, hostBundleName, extensionRecord, extensionRecordId), ERR_INVALID_VALUE);

    abilityRequest.extensionType = AppExecFwk::ExtensionAbilityType::SHARE;
    std::string key("ability.want.params.is_preload_uiextension_ability");
    AAFwk::WantParams wantParams;
    wantParams.SetParam(key, AAFwk::Boolean::Box(true));
    AAFwk::Want want;
    want.SetParams(wantParams);
    abilityRequest.want = want;
    EXPECT_EQ(extRecordMgr->CreateExtensionRecord(
        abilityRequest, hostBundleName, extensionRecord, extensionRecordId), ERR_INVALID_VALUE);

    AAFwk::IsMockSaCall::IsMockSaCallWithPermission();
    AAFwk::MyFlag::flag_ = AAFwk::MyFlag::IS_SA_CALL;
    EXPECT_EQ(extRecordMgr->CreateExtensionRecord(
        abilityRequest, hostBundleName, extensionRecord, extensionRecordId), ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: RemovePreloadUIExtensionRecordById_0100
 * @tc.desc: Test RemovePreloadUIExtensionRecordById.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerSecondTest, RemovePreloadUIExtensionRecordById_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    std::tuple<std::string, std::string, std::string, std::string> extensionRecordMapKey;
    int32_t extensionRecordId = 0;
    EXPECT_FALSE(extRecordMgr->RemovePreloadUIExtensionRecordById(extensionRecordMapKey, extensionRecordId));

    std::vector<std::shared_ptr<ExtensionRecord>> v_ExtensionRecord;
    extRecordMgr->preloadUIExtensionMap_[extensionRecordMapKey] = v_ExtensionRecord;
    EXPECT_FALSE(extRecordMgr->RemovePreloadUIExtensionRecordById(extensionRecordMapKey, extensionRecordId));

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);
    auto extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    extRecord->extensionRecordId_ = 0;
    v_ExtensionRecord.push_back(extRecord);
    extRecordMgr->preloadUIExtensionMap_[extensionRecordMapKey] = v_ExtensionRecord;
    EXPECT_TRUE(extRecordMgr->RemovePreloadUIExtensionRecordById(extensionRecordMapKey, extensionRecordId));

    extRecord->extensionRecordId_ = 1;
    v_ExtensionRecord.clear();
    v_ExtensionRecord.push_back(extRecord);
    extRecordMgr->preloadUIExtensionMap_[extensionRecordMapKey] = v_ExtensionRecord;
    EXPECT_FALSE(extRecordMgr->RemovePreloadUIExtensionRecordById(extensionRecordMapKey, extensionRecordId));
    TAG_LOGI(AAFwkTag::TEST, "end.");
}
} // namespace AbilityRuntime
} // namespace OHOS
