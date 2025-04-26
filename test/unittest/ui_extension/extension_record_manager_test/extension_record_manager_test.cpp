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

#include "hilog_tag_wrapper.h"
#include "ability_manager_client.h"
#include "ability_record.h"
#include "extension_record.h"
#include "extension_record_factory.h"
#define private public
#include "extension_record_manager.h"
#undef private
#include "mock_ability_token.h"
#include "mock_native_token.h"
#include "scene_board_judgement.h"
#include "session_info.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
namespace {
    constexpr int32_t EXTENSION_RECORD_KEY_0 = 0;
    constexpr int32_t EXTENSION_RECORD_KEY_1 = 1;
    constexpr int32_t EXTENSION_RECORD_KEY_2 = 2;
    constexpr const char *SEPARATOR = ":";
} // namespace
class ExtensionRecordManagerTest : public testing::Test {
public:

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void ExtensionRecordManagerTest::SetUpTestCase(void)
{}

void ExtensionRecordManagerTest::TearDownTestCase(void)
{}

void ExtensionRecordManagerTest::SetUp()
{}

void ExtensionRecordManagerTest::TearDown()
{}

/**
 * @tc.name: IsFocused_0100
 * @tc.desc: check is focused.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, IsFocused_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    ASSERT_NE(extRecordMgr, nullptr);

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);
    auto extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    int32_t extensionRecordId = 1;
    extRecordMgr->AddExtensionRecord(extensionRecordId, extRecord);

    sptr<IRemoteObject> token = sptr<AppExecFwk::MockAbilityToken>::MakeSptr();
    ASSERT_NE(token, nullptr);
    extRecordMgr->SetCachedFocusedCallerToken(extensionRecordId, token);

    bool isFocused = extRecordMgr->IsFocused(extensionRecordId, token, token);
    EXPECT_EQ(isFocused, true);

    auto focusedToken = extRecordMgr->GetCachedFocusedCallerToken(extensionRecordId);
    EXPECT_EQ(focusedToken, token);

    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GetCallerTokenList_0100
 * @tc.desc: get caller token list.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, GetCallerTokenList_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);
    auto extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    ASSERT_NE(extRecord, nullptr);

    sptr<AAFwk::SessionInfo> sessionInfo = sptr<AAFwk::SessionInfo>::MakeSptr();
    ASSERT_NE(sessionInfo, nullptr);
    sptr<IRemoteObject> callerToken = sptr<AppExecFwk::MockAbilityToken>::MakeSptr();
    EXPECT_NE(callerToken, nullptr);
    sessionInfo->callerToken = callerToken;
    extRecord->abilityRecord_->SetSessionInfo(sessionInfo);
    extRecord->SetFocusedCallerToken(callerToken);
    extRecord->GetFocusedCallerToken();

    int32_t extensionRecordId = 1;
    extRecordMgr->AddExtensionRecord(extensionRecordId, extRecord);

    std::list<sptr<IRemoteObject>> callerList;
    extRecordMgr->GetCallerTokenList(abilityRecord, callerList);
    ASSERT_NE(extRecordMgr, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GenerateExtensionRecordId_0100
 * @tc.desc: generate extension record id.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, GenerateExtensionRecordId_0100, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    ASSERT_NE(extRecordMgr, nullptr);
    int32_t extensionRecordId = 2;
    EXPECT_EQ(extRecordMgr->GenerateExtensionRecordId(INVALID_EXTENSION_RECORD_ID), 1);
    EXPECT_EQ(extRecordMgr->GenerateExtensionRecordId(extensionRecordId), 2);
    EXPECT_EQ(extRecordMgr->GenerateExtensionRecordId(extensionRecordId), 3);
}

/**
 * @tc.name: AddExtensionRecord_0100
 * @tc.desc: AddExtensionRecord RemoveExtensionRecord
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, AddExtensionRecord_0100, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    ASSERT_NE(extRecordMgr, nullptr);

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);
    auto extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    int32_t extensionRecordId = 5;
    extRecordMgr->AddExtensionRecord(extensionRecordId, extRecord);
    extRecordMgr->AddExtensionRecordToTerminatedList(extensionRecordId);
    extRecordMgr->RemoveExtensionRecord(extensionRecordId);
    extRecordMgr->AddExtensionRecordToTerminatedList(extensionRecordId);

    int32_t extensionRecordId2 = 6;
    extRecordMgr->AddExtensionRecord(extensionRecordId2, extRecord);
    bool  bIsload = false;
    auto extRecord2 = std::make_shared<ExtensionRecord>(abilityRecord);
    auto result = extRecordMgr->GetExtensionRecord(extensionRecordId2, "com.example.unittest", extRecord2, bIsload);

    auto result2 = extRecordMgr->GetExtensionRecord(extensionRecordId2, "aa", extRecord2, bIsload);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
}

/**
 * @tc.name: GetActiveUIExtensionList_0100
 * @tc.desc: GetActiveUIExtensionList
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, GetActiveUIExtensionList_0100, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    ASSERT_NE(extRecordMgr, nullptr);

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);
    auto extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    int32_t extensionRecordId = 5;
    extRecordMgr->AddExtensionRecord(extensionRecordId, extRecord);
    int32_t pId = abilityRecord->GetPid();
    std::vector<std::string> extensionList;
    extRecordMgr->GetActiveUIExtensionList(pId, extensionList);
    extRecordMgr->GetActiveUIExtensionList("com.example.unittest", extensionList);
    extRecordMgr->GetActiveUIExtensionList("aa", extensionList);
}

/**
 * @tc.name: GetAbilityRecordBySessionInfo_0100
 * @tc.desc: GetAbilityRecordBySessionInfo
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, GetAbilityRecordBySessionInfo_0100, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    ASSERT_NE(extRecordMgr, nullptr);

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    sptr<AAFwk::SessionInfo> sessionInfo(new AAFwk::SessionInfo());
    sessionInfo->uiExtensionComponentId = 10;
    abilityRequest.sessionInfo = sessionInfo;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);
    auto extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    int32_t extensionRecordId = 5;
    extRecordMgr->AddExtensionRecord(extensionRecordId, extRecord);

    sptr<AAFwk::SessionInfo> sessionParam(new AAFwk::SessionInfo());
    sessionParam->uiExtensionComponentId = INVALID_EXTENSION_RECORD_ID;
    EXPECT_EQ(extRecordMgr->GetAbilityRecordBySessionInfo(sessionParam), nullptr);

    sessionParam->uiExtensionComponentId = 10;
    EXPECT_EQ(extRecordMgr->GetAbilityRecordBySessionInfo(sessionParam), abilityRecord);
    sessionParam->uiExtensionComponentId = 9;
    EXPECT_EQ(extRecordMgr->GetAbilityRecordBySessionInfo(sessionParam), nullptr);

    auto extRecord2 = std::make_shared<ExtensionRecord>(nullptr);
    int32_t extensionRecordId2 = 6;
    extRecordMgr->AddExtensionRecord(extensionRecordId2, extRecord2);
    extRecordMgr->GetAbilityRecordBySessionInfo(sessionParam);

    AAFwk::AbilityRequest abilityRequest2;
    auto abilityRecord2 = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    bool bLoaded = false;
    std::string  bundleName = "";
    extRecordMgr->GetOrCreateExtensionRecord(abilityRequest, bundleName, abilityRecord2, bLoaded);
    extRecordMgr->GetOrCreateExtensionRecord(abilityRequest2, bundleName, abilityRecord2, bLoaded);
    bundleName = "";
    extRecordMgr->GetHostBundleNameForExtensionId(extensionRecordId, bundleName);
}

/**
 * @tc.name: AddPreloadUIExtensionRecord_0100
 * @tc.desc: AddPreloadUIExtensionRecord
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, AddPreloadUIExtensionRecord_0100, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    ASSERT_NE(extRecordMgr, nullptr);

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;

    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);


    extRecordMgr->AddPreloadUIExtensionRecord(abilityRecord);
    int32_t extId = 12;
    abilityRecord->SetUIExtensionAbilityId(extId);
    auto extRecord = std::make_shared<ExtensionRecord>(abilityRecord);

    extRecordMgr->AddExtensionRecord(extId, extRecord);
    extRecordMgr->AddPreloadUIExtensionRecord(abilityRecord);
    extRecordMgr->StartAbility(abilityRequest);
    extRecordMgr->GetCachedFocusedCallerToken(extId);
}

/**
 * @tc.name: CreateExtensionRecord_0100
 * @tc.desc: CreateExtensionRecord
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, CreateExtensionRecord_0100, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    ASSERT_NE(extRecordMgr, nullptr);
    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UNSPECIFIED;

    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);

    std::string bundleName = "com.example.unittest";
    int32_t extRecordId = 9;
    std::shared_ptr<ExtensionRecord> extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    auto result = extRecordMgr->CreateExtensionRecord(abilityRequest, bundleName, extRecord, extRecordId);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::PHOTO_EDITOR;
}

/**
 * @tc.name: IsHostSpecifiedProcessValid_0100
 * @tc.desc: IsHostSpecifiedProcessValid
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, IsHostSpecifiedProcessValid_0100, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    AAFwk::AbilityRequest abilityRequest;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    std::shared_ptr<ExtensionRecord> extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    std::string process = "testProcess";

    bool result = extRecordMgr->IsHostSpecifiedProcessValid(abilityRequest, extRecord, process);
    EXPECT_FALSE(result);

    std::shared_ptr<ExtensionRecord> nullExtRecord = std::make_shared<ExtensionRecord>(nullptr);
    extRecordMgr->extensionRecords_.insert({EXTENSION_RECORD_KEY_0, nullptr});
    extRecordMgr->extensionRecords_.insert({EXTENSION_RECORD_KEY_1, nullExtRecord});
    extRecordMgr->extensionRecords_.insert({EXTENSION_RECORD_KEY_2, extRecord});
    result = extRecordMgr->IsHostSpecifiedProcessValid(abilityRequest, extRecord, process);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsHostSpecifiedProcessValid_0200
 * @tc.desc: IsHostSpecifiedProcessValid
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, IsHostSpecifiedProcessValid_0200, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    std::shared_ptr<ExtensionRecord> extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    std::string process = "testProcess";

    bool result = extRecordMgr->IsHostSpecifiedProcessValid(abilityRequest, extRecord, process);
    EXPECT_FALSE(result);

    extRecord->abilityRecord_->SetProcessName(process);
    extRecordMgr->extensionRecords_.insert({EXTENSION_RECORD_KEY_0, extRecord});
    result = extRecordMgr->IsHostSpecifiedProcessValid(abilityRequest, extRecord, process);
    EXPECT_TRUE(result);

    abilityRequest.abilityInfo.name = "ability";
    result = extRecordMgr->IsHostSpecifiedProcessValid(abilityRequest, extRecord, process);
    EXPECT_FALSE(result);

    abilityRequest.abilityInfo.bundleName = "testBundleName";
    result = extRecordMgr->IsHostSpecifiedProcessValid(abilityRequest, extRecord, process);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: UpdateProcessName_0100
 * @tc.desc: UpdateProcessName
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, UpdateProcessName_0100, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.bundleName = "testBundleName";
    abilityRequest.abilityInfo.name = "testInfoName";
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    std::shared_ptr<ExtensionRecord> extRecord = std::make_shared<ExtensionRecord>(abilityRecord);

    int32_t result = extRecordMgr->UpdateProcessName(abilityRequest, extRecord);
    EXPECT_EQ(result, ERR_OK);

    extRecord->processMode_ = PROCESS_MODE_INSTANCE;
    std::string process = abilityRequest.abilityInfo.bundleName + SEPARATOR + abilityRequest.abilityInfo.name
        + SEPARATOR + std::to_string(abilityRecord->GetUIExtensionAbilityId());
    result = extRecordMgr->UpdateProcessName(abilityRequest, extRecord);
    EXPECT_EQ(abilityRecord->GetProcessName(), process);
    EXPECT_EQ(result, ERR_OK);

    extRecord->processMode_ = PROCESS_MODE_TYPE;
    process = abilityRequest.abilityInfo.bundleName + SEPARATOR + abilityRequest.abilityInfo.name;
    result = extRecordMgr->UpdateProcessName(abilityRequest, extRecord);
    EXPECT_EQ(abilityRecord->GetProcessName(), process);
    EXPECT_EQ(result, ERR_OK);

    extRecord->processMode_ = PROCESS_MODE_CUSTOM;
    process = abilityRequest.abilityInfo.bundleName + abilityRequest.customProcess;
    result = extRecordMgr->UpdateProcessName(abilityRequest, extRecord);
    EXPECT_EQ(abilityRecord->GetProcessName(), process);
    EXPECT_EQ(result, ERR_OK);

    extRecord->processMode_ = PROCESS_MODE_HOST_SPECIFIED;
    process = abilityRequest.want.GetStringParam(PROCESS_MODE_HOST_SPECIFIED_KEY);
    result = extRecordMgr->UpdateProcessName(abilityRequest, extRecord);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    extRecord->abilityRecord_->SetProcessName(process);
    extRecordMgr->extensionRecords_.insert({EXTENSION_RECORD_KEY_0, extRecord});
    result = extRecordMgr->UpdateProcessName(abilityRequest, extRecord);
    EXPECT_EQ(abilityRecord->GetProcessName(), process);
    EXPECT_EQ(result, ERR_OK);

    extRecord->processMode_ = PROCESS_MODE_RUN_WITH_MAIN_PROCESS;
    process = abilityRequest.abilityInfo.bundleName;
    result = extRecordMgr->UpdateProcessName(abilityRequest, extRecord);
    EXPECT_EQ(abilityRecord->GetProcessName(), process);
    EXPECT_EQ(result, ERR_OK);

    abilityRequest.appInfo.process = "testProcess";
    process = abilityRequest.appInfo.process;
    result = extRecordMgr->UpdateProcessName(abilityRequest, extRecord);
    EXPECT_EQ(abilityRecord->GetProcessName(), process);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: IsPreloadExtensionRecord_0100
 * @tc.desc: IsPreloadExtensionRecord
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, IsPreloadExtensionRecord_0100, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    AAFwk::AbilityRequest abilityRequest;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    std::shared_ptr<ExtensionRecord> extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    std::string hostBundleName = "testHostBundleName";
    bool isLoaded = false;

    bool result = extRecordMgr->IsPreloadExtensionRecord(abilityRequest, hostBundleName, extRecord, isLoaded);
    EXPECT_FALSE(result);

    std::string deviceId = "testDeviceId";
    std::string bundleName = "testBundleName";
    std::string abilityName = "testAbilityName";
    std::string moduleName = "testModuleName";
    abilityRequest.want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    auto extensionRecordMapKey = std::make_tuple(abilityName, bundleName, moduleName, hostBundleName);
    std::vector<std::shared_ptr<ExtensionRecord>> nullExtensions;
    std::vector<std::shared_ptr<ExtensionRecord>> extensions;

    extensions.push_back(extRecord);
    extRecordMgr->preloadUIExtensionMap_.insert({extensionRecordMapKey, extensions});
    result = extRecordMgr->IsPreloadExtensionRecord(abilityRequest, hostBundleName, extRecord, isLoaded);
    EXPECT_TRUE(isLoaded);
    EXPECT_TRUE(result);

    extRecordMgr->preloadUIExtensionMap_[extensionRecordMapKey] = nullExtensions;
    result = extRecordMgr->IsPreloadExtensionRecord(abilityRequest, hostBundleName, extRecord, isLoaded);
    EXPECT_FALSE(result);

    nullExtensions.push_back(nullptr);
    extRecordMgr->preloadUIExtensionMap_[extensionRecordMapKey] = nullExtensions;
    result = extRecordMgr->IsPreloadExtensionRecord(abilityRequest, hostBundleName, extRecord, isLoaded);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsBelongToManager_0100
 * @tc.desc: IsBelongToManager
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, IsBelongToManager_0100, TestSize.Level1)
{
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.extensionAbilityType =  AppExecFwk::ExtensionAbilityType::SYSDIALOG_COMMON;
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    EXPECT_TRUE(extRecordMgr->IsBelongToManager(abilityInfo));
}

/**
 * @tc.name: GetOrCreateExtensionRecord_0100
 * @tc.desc: GetOrCreateExtensionRecord
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, GetOrCreateExtensionRecord_0100, TestSize.Level1)
{
    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.sessionInfo = sptr<AAFwk::SessionInfo>::MakeSptr();
    abilityRequest.sessionInfo->uiExtensionComponentId = 0;

    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    std::shared_ptr<ExtensionRecord> extRecord =
        std::make_shared<ExtensionRecord>(abilityRecord);
    extRecord->abilityRecord_ = abilityRecord;
    std::string hostBundleName = "testHostBundleName";
    bool isLoaded = false;

    std::string deviceId = "testDeviceId";
    std::string bundleName = "testBundleName";
    std::string abilityName = "testAbilityName";
    std::string moduleName = "testModuleName";
    abilityRequest.want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    auto extensionRecordMapKey = std::make_tuple(abilityName,
        bundleName, moduleName, hostBundleName);
    std::vector<std::shared_ptr<ExtensionRecord>> nullExtensions;
    std::vector<std::shared_ptr<ExtensionRecord>> extensions;

    extensions.push_back(extRecord);
    extRecordMgr->preloadUIExtensionMap_.insert({extensionRecordMapKey, extensions});
    auto ret = extRecordMgr->GetOrCreateExtensionRecord(abilityRequest,
        hostBundleName, abilityRecord, isLoaded);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: GetOrCreateExtensionRecord_0200
 * @tc.desc: GetOrCreateExtensionRecord
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, GetOrCreateExtensionRecord_0200, TestSize.Level1)
{
    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.sessionInfo = sptr<AAFwk::SessionInfo>::MakeSptr();
    abilityRequest.sessionInfo->uiExtensionComponentId = 0;
    std::string hostBundleName = "testHostBundleName";
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    bool isLoaded = false;
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    auto ret = extRecordMgr->GetOrCreateExtensionRecord(abilityRequest,
        hostBundleName, abilityRecord, isLoaded);
    EXPECT_NE(ret, ERR_OK);
}
} // namespace AbilityRuntime
} // namespace OHOS
