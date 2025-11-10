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
    int32_t hostPid = 0;
    extRecordMgr->GetHostPidForExtensionId(extensionRecordId, hostPid);
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
    int32_t hostPid = 0;

    bool result = extRecordMgr->IsPreloadExtensionRecord(abilityRequest, hostPid, extRecord, isLoaded);
    EXPECT_FALSE(result);

    std::string deviceId = "testDeviceId";
    std::string bundleName = "testBundleName";
    std::string abilityName = "testAbilityName";
    std::string moduleName = "testModuleName";
    abilityRequest.want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    auto extensionRecordMapKey = std::make_tuple(abilityName, bundleName, moduleName, hostPid);
    std::vector<std::shared_ptr<ExtensionRecord>> nullExtensions;
    std::vector<std::shared_ptr<ExtensionRecord>> extensions;

    extensions.push_back(extRecord);
    extRecordMgr->preloadUIExtensionMap_.insert({extensionRecordMapKey, extensions});
    result = extRecordMgr->IsPreloadExtensionRecord(abilityRequest, hostPid, extRecord, isLoaded);
    EXPECT_TRUE(isLoaded);
    EXPECT_TRUE(result);

    extRecordMgr->preloadUIExtensionMap_[extensionRecordMapKey] = nullExtensions;
    result = extRecordMgr->IsPreloadExtensionRecord(abilityRequest, hostPid, extRecord, isLoaded);
    EXPECT_FALSE(result);

    nullExtensions.push_back(nullptr);
    extRecordMgr->preloadUIExtensionMap_[extensionRecordMapKey] = nullExtensions;
    result = extRecordMgr->IsPreloadExtensionRecord(abilityRequest, hostPid, extRecord, isLoaded);
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
    int32_t hostPid = 0;
    std::string hostBundleName = "testHostBundleName";
    bool isLoaded = false;

    std::string deviceId = "testDeviceId";
    std::string bundleName = "testBundleName";
    std::string abilityName = "testAbilityName";
    std::string moduleName = "testModuleName";
    abilityRequest.want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    auto extensionRecordMapKey = std::make_tuple(abilityName,
        bundleName, moduleName, hostPid);
    std::vector<std::shared_ptr<ExtensionRecord>> nullExtensions;
    std::vector<std::shared_ptr<ExtensionRecord>> extensions;

    extensions.push_back(extRecord);
    extRecordMgr->preloadUIExtensionMap_.insert({extensionRecordMapKey, extensions});
    auto ret = extRecordMgr->GetOrCreateExtensionRecord(abilityRequest,
        hostBundleName, abilityRecord, isLoaded);
    EXPECT_NE(ret, ERR_OK);
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

/**
 * @tc.name: GetUIExtensionSessionInfo_0100
 * @tc.desc: GetUIExtensionSessionInfo
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, GetUIExtensionSessionInfo_0100, TestSize.Level1)
{
    sptr<IRemoteObject> token;
    UIExtensionSessionInfo uiExtensionSessionInfo;
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    auto ret = extRecordMgr->GetUIExtensionSessionInfo(token, uiExtensionSessionInfo);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
}

/**
 * @tc.name: GetUIExtensionSessionInfo_0200
 * @tc.desc: GetUIExtensionSessionInfo
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, GetUIExtensionSessionInfo_0200, TestSize.Level1)
{
    sptr<IRemoteObject> token = sptr<AppExecFwk::MockAbilityToken>::MakeSptr();
    ASSERT_NE(token, nullptr);
    UIExtensionSessionInfo uiExtensionSessionInfo;
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    auto ret = extRecordMgr->GetUIExtensionSessionInfo(token, uiExtensionSessionInfo);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
}

/**
 * @tc.name: GetUIExtensionSessionInfo_0300
 * @tc.desc: GetUIExtensionSessionInfo
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, GetUIExtensionSessionInfo_0300, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    ASSERT_NE(extRecordMgr, nullptr);

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    abilityRequest.abilityInfo.extensionAbilityType =  AppExecFwk::ExtensionAbilityType::UNSPECIFIED;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);
    auto extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    int32_t extensionRecordId = 1;
    extRecordMgr->AddExtensionRecord(extensionRecordId, extRecord);

    auto token = abilityRecord->GetToken();
    ASSERT_NE(token, nullptr);

    UIExtensionSessionInfo uiExtensionSessionInfo;
    auto ret = extRecordMgr->GetUIExtensionSessionInfo(token, uiExtensionSessionInfo);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: GetUIExtensionSessionInfo_0400
 * @tc.desc: GetUIExtensionSessionInfo
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, GetUIExtensionSessionInfo_0400, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    ASSERT_NE(extRecordMgr, nullptr);

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    abilityRequest.abilityInfo.extensionAbilityType =  AppExecFwk::ExtensionAbilityType::SYSDIALOG_COMMON;
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);
    auto extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    int32_t extensionRecordId = 1;
    extRecordMgr->AddExtensionRecord(extensionRecordId, extRecord);

    auto token = abilityRecord->GetToken();
    ASSERT_NE(token, nullptr);

    UIExtensionSessionInfo uiExtensionSessionInfo;
    auto ret = extRecordMgr->GetUIExtensionSessionInfo(token, uiExtensionSessionInfo);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
}

/**
 * @tc.name: GetUIExtensionSessionInfo_0500
 * @tc.desc: GetUIExtensionSessionInfo
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, GetUIExtensionSessionInfo_0500, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    ASSERT_NE(extRecordMgr, nullptr);

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    abilityRequest.abilityInfo.extensionAbilityType =  AppExecFwk::ExtensionAbilityType::SYSDIALOG_COMMON;
    std::string deviceId = "testDeviceId";
    std::string bundleName = "testBundleName";
    std::string abilityName = "testAbilityName";
    std::string moduleName = "testModuleName";
    abilityRequest.want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);
    auto extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    int32_t extensionRecordId = 1;
    extRecordMgr->AddExtensionRecord(extensionRecordId, extRecord);

    auto token = abilityRecord->GetToken();
    ASSERT_NE(token, nullptr);

    sptr<AAFwk::SessionInfo> sessionInfo = sptr<AAFwk::SessionInfo>::MakeSptr();
    sessionInfo->persistentId  = 1;
    sessionInfo->hostWindowId  = 1;
    sessionInfo->uiExtensionUsage  = AAFwk::UIExtensionUsage::MODAL;
    ASSERT_NE(sessionInfo, nullptr);
    extRecord->abilityRecord_->SetSessionInfo(sessionInfo);

    UIExtensionSessionInfo uiExtensionSessionInfo;
    auto ret = extRecordMgr->GetUIExtensionSessionInfo(token, uiExtensionSessionInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: GetUIExtensionSessionInfo_0600
 * @tc.desc: GetUIExtensionSessionInfo
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ExtensionRecordManagerTest, GetUIExtensionSessionInfo_0600, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    ASSERT_NE(extRecordMgr, nullptr);

    AAFwk::AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    abilityRequest.abilityInfo.extensionAbilityType =  AppExecFwk::ExtensionAbilityType::SYSDIALOG_COMMON;
    std::string deviceId = "testDeviceId";
    std::string bundleName = "testBundleName";
    std::string abilityName = "testAbilityName";
    std::string moduleName = "testModuleName";
    abilityRequest.want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);
    auto extRecord = std::make_shared<ExtensionRecord>(abilityRecord);
    int32_t extensionRecordId = 1;
    extRecordMgr->AddExtensionRecord(extensionRecordId, extRecord);

    auto token = abilityRecord->GetToken();

    AAFwk::AbilityRequest callerAbilityRequest;
    callerAbilityRequest.appInfo.bundleName = "com.example.unittest";
    callerAbilityRequest.abilityInfo.name = "MainAbility";
    callerAbilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    callerAbilityRequest.abilityInfo.extensionAbilityType =  AppExecFwk::ExtensionAbilityType::SYSDIALOG_COMMON;
    std::string callerDeviceId = "testDeviceId";
    std::string callerBundleName = "testBundleName";
    std::string callerAbilityName = "testAbilityName";
    std::string callerModuleName = "testModuleName";
    callerAbilityRequest.want.SetElementName(callerDeviceId, callerBundleName, callerAbilityName, callerModuleName);
    auto callerAbilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(callerAbilityRequest);
    ASSERT_NE(callerAbilityRecord, nullptr);
    auto callerExtRecord = std::make_shared<ExtensionRecord>(callerAbilityRecord);
    int32_t callerExtensionRecordId = 2;
    extRecordMgr->AddExtensionRecord(callerExtensionRecordId, callerExtRecord);
    sptr<IRemoteObject> callerToken = callerAbilityRecord->GetToken();
    ASSERT_NE(callerToken, nullptr);

    sptr<AAFwk::SessionInfo> sessionInfo = sptr<AAFwk::SessionInfo>::MakeSptr();
    sessionInfo->persistentId  = 1;
    sessionInfo->hostWindowId  = 1;
    sessionInfo->uiExtensionUsage  = AAFwk::UIExtensionUsage::MODAL;
    sessionInfo->callerToken = callerToken;
    ASSERT_NE(sessionInfo, nullptr);
    extRecord->abilityRecord_->SetSessionInfo(sessionInfo);

    UIExtensionSessionInfo uiExtensionSessionInfo;
    auto ret = extRecordMgr->GetUIExtensionSessionInfo(token, uiExtensionSessionInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: ClearPreloadedUIExtensionAbility_0100
 * @tc.desc: Test clear with invalid extensionRecordId (not found in extensionRecords_)
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, ClearPreloadedUIExtensionAbility_0100, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    int32_t invalidId = 9999;
    EXPECT_EQ(extRecordMgr->ClearPreloadedUIExtensionAbility(invalidId), AAFwk::ERR_CODE_INVALID_ID);
}

/**
 * @tc.name: ClearPreloadedUIExtensionAbility_0200
 * @tc.desc: Test clear when record exists but is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, ClearPreloadedUIExtensionAbility_0200, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    int32_t id = 1001;
    extRecordMgr->extensionRecords_[id] = nullptr;
    EXPECT_EQ(extRecordMgr->ClearPreloadedUIExtensionAbility(id), ERR_INVALID_VALUE);
}

/**
 * @tc.name: ClearPreloadedUIExtensionAbility_0300
 * @tc.desc: Test clear when callingPid != hostPid
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, ClearPreloadedUIExtensionAbility_0300, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    AAFwk::AbilityRequest req;
    req.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    auto abilityRec = AAFwk::AbilityRecord::CreateAbilityRecord(req);
    auto extRec = std::make_shared<ExtensionRecord>(abilityRec);
    extRec->hostPid_ = 12345;
    int id = 1001;
    extRecordMgr->extensionRecords_[id] = extRec;
    EXPECT_EQ(extRecordMgr->ClearPreloadedUIExtensionAbility(id), AAFwk::ERR_CODE_INVALID_ID);
}

/**
 * @tc.name: ClearPreloadedUIExtensionAbility_0400
 * @tc.desc: Test clear when abilityRecord inside ExtensionRecord is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, ClearPreloadedUIExtensionAbility_0400, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    int32_t id = 1001;
    auto extRec = std::make_shared<ExtensionRecord>(nullptr);
    extRec->hostPid_ = IPCSkeleton::GetCallingPid();
    extRecordMgr->extensionRecords_[id] = extRec;
    EXPECT_EQ(extRecordMgr->ClearPreloadedUIExtensionAbility(id), ERR_INVALID_VALUE);
}

/**
 * @tc.name: ClearPreloadedUIExtensionAbility_0500
 * @tc.desc: Test clear when RemovePreloadUIExtensionRecordById returns false
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, ClearPreloadedUIExtensionAbility_0500, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    AAFwk::AbilityRequest req;
    req.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    req.abilityInfo.name = "TestAbility";
    req.abilityInfo.bundleName = "com.test.bundle";
    req.abilityInfo.moduleName = "entry";
    auto abilityRec = AAFwk::AbilityRecord::CreateAbilityRecord(req);
    auto extRec = std::make_shared<ExtensionRecord>(abilityRec);
    extRec->hostPid_ = IPCSkeleton::GetCallingPid();
    extRec->hostBundleName_ = "com.test.host";
    
    int32_t id = 1001;
    extRecordMgr->extensionRecords_[id] = extRec;
    // preloadUIExtensionMap_ is empty, so RemovePreloadUIExtensionRecordById will return false
    
    EXPECT_EQ(extRecordMgr->ClearPreloadedUIExtensionAbility(id), ERR_INVALID_VALUE);
}

/**
 * @tc.name: ClearPreloadedUIExtensionAbility_0600
 * @tc.desc: Test clear success path
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, ClearPreloadedUIExtensionAbility_0600, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    AAFwk::AbilityRequest req;
    req.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    req.abilityInfo.name = "TestAbility";
    req.abilityInfo.bundleName = "com.test.bundle";
    req.abilityInfo.moduleName = "entry";
    auto abilityRec = AAFwk::AbilityRecord::CreateAbilityRecord(req);
    
    int32_t id = 1001;
    
    auto uiExtRec = std::make_shared<ExtensionRecord>(abilityRec);
    uiExtRec->hostPid_ = IPCSkeleton::GetCallingPid();
    uiExtRec->hostBundleName_ = "com.test.host";
    uiExtRec->extensionRecordId_ = id;
    
    extRecordMgr->extensionRecords_[id] = uiExtRec;
    
    auto key = std::make_tuple("TestAbility", "com.test.bundle", "entry", "com.test.host");
    extRecordMgr->preloadUIExtensionMap_[key].push_back(uiExtRec);
    
    EXPECT_EQ(extRecordMgr->preloadUIExtensionMap_[key].size(), 1);
    
    int32_t result = extRecordMgr->ClearPreloadedUIExtensionAbility(id);
    
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(extRecordMgr->preloadUIExtensionMap_.find(key) == extRecordMgr->preloadUIExtensionMap_.end() ||
                extRecordMgr->preloadUIExtensionMap_[key].empty());
}

/**
 * @tc.name: ClearAllPreloadUIExtensionRecordForHost_0100
 * @tc.desc: Empty preloadUIExtensionMap_
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, ClearAllPreloadUIExtensionRecordForHost_0100, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    EXPECT_EQ(extRecordMgr->ClearAllPreloadUIExtensionRecordForHost("any.host"), ERR_OK);
}

/**
 * @tc.name: ClearAllPreloadUIExtensionRecordForHost_0200
 * @tc.desc: Map contains entry for different bundleName, should not unload
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, ClearAllPreloadUIExtensionRecordForHost_0200, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    auto rec = std::make_shared<ExtensionRecord>(nullptr);
    rec->hostBundleName_ = "com.example.host";
    rec->hostPid_ = IPCSkeleton::GetCallingPid();

    auto key = std::make_tuple("AbilityA", "bundleA", "moduleA", "com.example.host");
    extRecordMgr->preloadUIExtensionMap_[key].push_back(rec);

    EXPECT_EQ(extRecordMgr->ClearAllPreloadUIExtensionRecordForHost("other.host"), ERR_OK);
}

/**
 * @tc.name: ClearAllPreloadUIExtensionRecordForHost_0300
 * @tc.desc: Map contains matching bundleName but different pid, should not unload
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, ClearAllPreloadUIExtensionRecordForHost_0300, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    auto rec = std::make_shared<ExtensionRecord>(nullptr);
    rec->hostBundleName_ = "com.example.host";
    rec->hostPid_ = 99999;
    
    auto key = std::make_tuple("AbilityA", "bundleA", "moduleA", "com.example.host");
    extRecordMgr->preloadUIExtensionMap_[key].push_back(rec);
    
    EXPECT_EQ(extRecordMgr->ClearAllPreloadUIExtensionRecordForHost("com.example.host"), ERR_OK);
    EXPECT_EQ(extRecordMgr->preloadUIExtensionMap_[key].size(), 1);
}

/**
 * @tc.name: ClearAllPreloadUIExtensionRecordForHost_0400
 * @tc.desc: Map contains matching bundleName and pid, should unload
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, ClearAllPreloadUIExtensionRecordForHost_0400, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    auto rec = std::make_shared<ExtensionRecord>(nullptr);
    rec->hostBundleName_ = "com.example.host";
    rec->hostPid_ = IPCSkeleton::GetCallingPid();
    
    auto key = std::make_tuple("AbilityA", "bundleA", "moduleA", "com.example.host");
    extRecordMgr->preloadUIExtensionMap_[key].push_back(rec);
    
    EXPECT_EQ(extRecordMgr->ClearAllPreloadUIExtensionRecordForHost("com.example.host"), ERR_OK);
    EXPECT_TRUE(extRecordMgr->preloadUIExtensionMap_.find(key) == extRecordMgr->preloadUIExtensionMap_.end());
}

/**
 * @tc.name: ClearAllPreloadUIExtensionRecordForHost_0500
 * @tc.desc: Map contains multiple records, only matching ones should be unloaded
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, ClearAllPreloadUIExtensionRecordForHost_0500, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    
    auto rec1 = std::make_shared<ExtensionRecord>(nullptr);
    rec1->hostBundleName_ = "com.example.host";
    rec1->hostPid_ = IPCSkeleton::GetCallingPid();
    
    auto rec2 = std::make_shared<ExtensionRecord>(nullptr);
    rec2->hostBundleName_ = "com.example.host";
    rec2->hostPid_ = 99999;
    
    auto key = std::make_tuple("AbilityA", "bundleA", "moduleA", "com.example.host");
    extRecordMgr->preloadUIExtensionMap_[key].push_back(rec1);
    extRecordMgr->preloadUIExtensionMap_[key].push_back(rec2);
    
    EXPECT_EQ(extRecordMgr->ClearAllPreloadUIExtensionRecordForHost("com.example.host"), ERR_OK);
    EXPECT_EQ(extRecordMgr->preloadUIExtensionMap_[key].size(), 1);
    EXPECT_EQ(extRecordMgr->preloadUIExtensionMap_[key][0], rec2);
}

/**
 * @tc.name: UnloadExtensionRecordsByPid_0100
 * @tc.desc: Test with empty records vector
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, UnloadExtensionRecordsByPid_0100, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    std::vector<std::shared_ptr<ExtensionRecord>> records;
    std::vector<std::shared_ptr<ExtensionRecord>> recordsToUnload;
    int32_t callingPid = IPCSkeleton::GetCallingPid();
    
    extRecordMgr->UnloadExtensionRecordsByPid(records, callingPid, recordsToUnload);
    EXPECT_TRUE(records.empty());
    EXPECT_TRUE(recordsToUnload.empty());
}

/**
 * @tc.name: UnloadExtensionRecordsByPid_0200
 * @tc.desc: Test with nullptr record in vector
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, UnloadExtensionRecordsByPid_0200, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    std::vector<std::shared_ptr<ExtensionRecord>> records;
    records.push_back(nullptr);
    std::vector<std::shared_ptr<ExtensionRecord>> recordsToUnload;
    int32_t callingPid = IPCSkeleton::GetCallingPid();
    
    extRecordMgr->UnloadExtensionRecordsByPid(records, callingPid, recordsToUnload);
    EXPECT_EQ(records.size(), 1);
    EXPECT_TRUE(recordsToUnload.empty());
}

/**
 * @tc.name: UnloadExtensionRecordsByPid_0300
 * @tc.desc: Test with record that has different pid
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, UnloadExtensionRecordsByPid_0300, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    std::vector<std::shared_ptr<ExtensionRecord>> records;
    auto rec = std::make_shared<ExtensionRecord>(nullptr);
    rec->hostPid_ = 99999;
    records.push_back(rec);
    
    std::vector<std::shared_ptr<ExtensionRecord>> recordsToUnload;
    int32_t callingPid = IPCSkeleton::GetCallingPid();
    
    extRecordMgr->UnloadExtensionRecordsByPid(records, callingPid, recordsToUnload);
    EXPECT_EQ(records.size(), 1);
    EXPECT_TRUE(recordsToUnload.empty());
}

/**
 * @tc.name: UnloadExtensionRecordsByPid_0400
 * @tc.desc: Test with record that has matching pid
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, UnloadExtensionRecordsByPid_0400, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    std::vector<std::shared_ptr<ExtensionRecord>> records;
    auto rec = std::make_shared<ExtensionRecord>(nullptr);
    rec->hostPid_ = IPCSkeleton::GetCallingPid();
    records.push_back(rec);
    
    std::vector<std::shared_ptr<ExtensionRecord>> recordsToUnload;
    int32_t callingPid = IPCSkeleton::GetCallingPid();
    
    extRecordMgr->UnloadExtensionRecordsByPid(records, callingPid, recordsToUnload);
    EXPECT_TRUE(records.empty());
    EXPECT_EQ(recordsToUnload.size(), 1);
    EXPECT_EQ(recordsToUnload[0], rec);
}

/**
 * @tc.name: RegisterPreloadUIExtensionHostClient_0100
 * @tc.desc: Test register with nullptr callerToken
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, RegisterPreloadUIExtensionHostClient_0100, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    int32_t hostPid = IPCSkeleton::GetCallingPid();
    extRecordMgr->RegisterPreloadUIExtensionHostClient(nullptr);
    EXPECT_TRUE(extRecordMgr->preloadUIExtensionHostClientCallerTokens_.find(hostPid) ==
                extRecordMgr->preloadUIExtensionHostClientCallerTokens_.end() ||
                extRecordMgr->preloadUIExtensionHostClientCallerTokens_[hostPid] == nullptr);
}

/**
 * @tc.name: UnRegisterPreloadUIExtensionHostClient_0100
 * @tc.desc: Test unregister when token is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionRecordManagerTest, UnRegisterPreloadUIExtensionHostClient_0100, TestSize.Level1)
{
    auto extRecordMgr = std::make_shared<ExtensionRecordManager>(0);
    int32_t hostPid = IPCSkeleton::GetCallingPid();
    extRecordMgr->preloadUIExtensionHostClientCallerTokens_.clear();
    extRecordMgr->UnRegisterPreloadUIExtensionHostClient(hostPid);
    EXPECT_TRUE(extRecordMgr->preloadUIExtensionHostClientCallerTokens_.empty() ||
                extRecordMgr->preloadUIExtensionHostClientCallerTokens_.find(hostPid) ==
                extRecordMgr->preloadUIExtensionHostClientCallerTokens_.end());
}
} // namespace AbilityRuntime
} // namespace OHOS
