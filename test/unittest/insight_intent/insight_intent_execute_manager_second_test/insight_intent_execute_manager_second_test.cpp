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

#include "hilog_tag_wrapper.h"
#include "insight_intent_execute_manager.h"
#include "insight_intent_execute_param.h"
#include "mock_ability_token.h"
#include "want.h"

using namespace testing;
using namespace testing::ext;

namespace {
constexpr uint64_t NON_EXIST_ID = 12345;
};
namespace OHOS {
namespace AAFwk {
class InsightIntentExecuteManagerSecondTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void InsightIntentExecuteManagerSecondTest::SetUpTestCase(void)
{}

void InsightIntentExecuteManagerSecondTest::TearDownTestCase(void)
{}

void InsightIntentExecuteManagerSecondTest::SetUp()
{}

void InsightIntentExecuteManagerSecondTest::TearDown()
{}

/**
 * @tc.name: CheckAndUpdateParam_0100
 * @tc.desc: CheckAndUpdateParam_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckAndUpdateParam_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = std::make_shared<WantParams>();
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    sptr<IRemoteObject> callerToken = new AppExecFwk::MockAbilityToken();
    uint64_t key = 1;
    std::string callerBundleName = "com.bundlename.test";
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->CheckAndUpdateParam(
        key, callerToken, paramPtr, callerBundleName);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckAndUpdateParam_0200
 * @tc.desc: CheckAndUpdateParam_0200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckAndUpdateParam_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = std::make_shared<WantParams>();
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    sptr<IRemoteObject> callerToken;
    uint64_t key = 1;
    std::string callerBundleName = "com.bundlename.test";
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->CheckAndUpdateParam(
        key, callerToken, paramPtr, callerBundleName);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckAndUpdateParam_0300
 * @tc.desc: CheckAndUpdateParam_0300
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckAndUpdateParam_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    std::shared_ptr<AppExecFwk::InsightIntentExecuteParam> paramPtr = nullptr;
    sptr<IRemoteObject> callerToken = new AppExecFwk::MockAbilityToken();
    uint64_t key = 1;
    std::string callerBundleName = "com.bundlename.test";
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->CheckAndUpdateParam(
        key, callerToken, paramPtr, callerBundleName);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckAndUpdateParam_0400
 * @tc.desc: CheckAndUpdateParam_0400
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckAndUpdateParam_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = std::make_shared<WantParams>();
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    sptr<IRemoteObject> callerToken = new AppExecFwk::MockAbilityToken();
    uint64_t key = 1;
    std::string callerBundleName = "com.bundlename.test";
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->CheckAndUpdateParam(
        key, callerToken, paramPtr, callerBundleName);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckAndUpdateWant_0100
 * @tc.desc: CheckAndUpdateWant_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckAndUpdateWant_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Want want;
    auto executeMode = AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND;
    std::string callerBundleName = "test";
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->CheckAndUpdateWant(
        want, executeMode, callerBundleName);
    EXPECT_NE(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckAndUpdateWant_0200
 * @tc.desc: CheckAndUpdateWant_0200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckAndUpdateWant_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Want want;
    want.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("com.example.test"));
    auto executeMode = AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND;
    std::string callerBundleName = "test";
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->CheckAndUpdateWant(
        want, executeMode, callerBundleName);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckAndUpdateWant_0300
 * @tc.desc: CheckAndUpdateWant_0300
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckAndUpdateWant_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Want want;
    want.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("com.example.test"));
    auto executeMode = AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND;
    std::string callerBundleName = "test";
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->CheckAndUpdateWant(
        want, executeMode, callerBundleName);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: ExecuteIntentDone_0100
 * @tc.desc: ExecuteIntentDone_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, ExecuteIntentDone_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    uint64_t intentId = 0;
    int32_t resultCode = 0;
    AppExecFwk::InsightIntentExecuteResult result;
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->ExecuteIntentDone(
        intentId, resultCode, result);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: ExecuteIntentDone_0200
 * @tc.desc: ExecuteIntentDone_0200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, ExecuteIntentDone_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    uint64_t intentId = 0;
    int32_t resultCode = 0;
    AppExecFwk::InsightIntentExecuteResult result;
    std::string bundle = "com.bundle.test";
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = std::make_shared<WantParams>();
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    sptr<IRemoteObject> callerToken = new AppExecFwk::MockAbilityToken();
    uint64_t key = 1;
    std::string callerBundleName = "com.bundlename.test";
    DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->AddRecord(
        key, callerToken, param.bundleName_, intentId, callerBundleName);
    intentId = 1;
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->ExecuteIntentDone(
        intentId, resultCode, result);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: ExecuteIntentDone_0300
 * @tc.desc: ExecuteIntentDone_0300
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, ExecuteIntentDone_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    uint64_t intentId = 0;
    int32_t resultCode = 0;
    AppExecFwk::InsightIntentExecuteResult result;
    DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->records_[intentId] = nullptr;
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->ExecuteIntentDone(
        intentId, resultCode, result);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: ExecuteIntentDone_0400
 * @tc.desc: ExecuteIntentDone_0400
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, ExecuteIntentDone_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    uint64_t intentId = 0;
    int32_t resultCode = 0;
    AppExecFwk::InsightIntentExecuteResult result;
    auto record = std::make_shared<InsightIntentExecuteRecord>();
    record->state = InsightIntentExecuteState::UNKNOWN;
    DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->records_[intentId] = record;
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->ExecuteIntentDone(
        intentId, resultCode, result);
    EXPECT_EQ(ret, ERR_INVALID_OPERATION);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GetCallerBundleName_0100
 * @tc.desc: GetCallerBundleName_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, GetCallerBundleName_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    uint64_t intentId = 0;
    std::string callerBundleName = "com.bundlename.test";
    DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->records_.clear();
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->GetCallerBundleName(
        intentId, callerBundleName);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GetCallerBundleName_0200
 * @tc.desc: GetCallerBundleName_0200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, GetCallerBundleName_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    uint64_t intentId = 0;
    std::string callerBundleName = "com.bundlename.test";
    auto record = std::make_shared<InsightIntentExecuteRecord>();
    record->state = InsightIntentExecuteState::UNKNOWN;
    DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->records_[intentId] = record;
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->GetCallerBundleName(
        intentId, callerBundleName);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GetCallerBundleName_0300
 * @tc.desc: GetCallerBundleName_0300
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, GetCallerBundleName_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    uint64_t intentId = 0;
    std::string callerBundleName = "com.bundlename.test";
    DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->records_[intentId] = nullptr;
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->GetCallerBundleName(
        intentId, callerBundleName);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: AddWantUirsAndFlagsFromParam_001
 * @tc.desc: basic function test of display id.
 * @tc.type: FUNC
 * @tc.require: issueI8ZRAG
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, AddWantUirsAndFlagsFromParam_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Want want;
    std::shared_ptr<AppExecFwk::InsightIntentExecuteParam> paramPtr = nullptr;
    auto ret = InsightIntentExecuteManager::AddWantUirsAndFlagsFromParam(paramPtr, want);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: AddWantUirsAndFlagsFromParam_002
 * @tc.desc: basic function test of display id.
 * @tc.type: FUNC
 * @tc.require: issueI8ZRAG
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, AddWantUirsAndFlagsFromParam_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Want want;
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = std::make_shared<WantParams>();
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    paramPtr->uris_.emplace_back("testUri1");
    paramPtr->uris_.emplace_back("testUri2");
    auto ret = InsightIntentExecuteManager::AddWantUirsAndFlagsFromParam(paramPtr, want);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: RemoteDied_0100
 * @tc.desc: RemoteDied_0100
 * @tc.type: FUNC
 * @tc.require: issueI8ZRAG
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, RemoteDied_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    std::shared_ptr<InsightIntentExecuteManager> manager = std::make_shared<InsightIntentExecuteManager>();
    EXPECT_NE(manager, nullptr);
    uint64_t nonExistentIntentId = NON_EXIST_ID;
    int32_t result = manager->RemoteDied(nonExistentIntentId);

    EXPECT_EQ(result, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: RemoteDied_0200
 * @tc.desc: RemoteDied_0200
 * @tc.type: FUNC
 * @tc.require: issueI8ZRAG
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, RemoteDied_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    std::shared_ptr<InsightIntentExecuteManager> manager = std::make_shared<InsightIntentExecuteManager>();
    EXPECT_NE(manager, nullptr);
    uint64_t key = 1;
    sptr<IRemoteObject> callToken = new AppExecFwk::MockAbilityToken();
    EXPECT_NE(callToken, nullptr);
    std::string bundleName = "test.bundleName";
    std::string callerBundleName = "test.callerBundleName";
    uint64_t intentId = 1;
    manager->AddRecord(key, callToken, bundleName, intentId, callerBundleName);

    int32_t result = manager->RemoteDied(intentId);
    EXPECT_EQ(result, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GetBundleName_0100
 * @tc.desc: GetBundleName_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, GetBundleName_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    std::shared_ptr<InsightIntentExecuteManager> manager = std::make_shared<InsightIntentExecuteManager>();
    EXPECT_NE(manager, nullptr);
    uint64_t nonExistentIntentId = NON_EXIST_ID;
    std::string bundleName;

    int32_t result = manager->GetBundleName(nonExistentIntentId, bundleName);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GetBundleName_0200
 * @tc.desc: GetBundleName_0200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, GetBundleName_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    std::shared_ptr<InsightIntentExecuteManager> manager = std::make_shared<InsightIntentExecuteManager>();
    EXPECT_NE(manager, nullptr);
    uint64_t key = 1;
    sptr<IRemoteObject> callToken = new AppExecFwk::MockAbilityToken();
    EXPECT_NE(callToken, nullptr);
    std::string bundleName = "test.bundleName";
    std::string callerBundleName = "test.callerBundleName";
    uint64_t intentId = 1;
    manager->AddRecord(key, callToken, bundleName, intentId, callerBundleName);

    std::string retBundleName;
    int32_t result = manager->GetBundleName(intentId, retBundleName);
    EXPECT_EQ(result, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GenerateWant_0300
 * @tc.desc: GenerateWant_0300
 * @tc.type: FUNC
 * @tc.require: issueI8ZRAG
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, GenerateWant_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AbilityRuntime::ExtractInsightIntentGenericInfo decoratorInfo;
    Want want;
    auto ret = InsightIntentExecuteManager::GenerateWant(nullptr, decoratorInfo, want);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GenerateWant_0400
 * @tc.desc: GenerateWant_0400
 * @tc.type: FUNC
 * @tc.require: issueI8ZRAG
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, GenerateWant_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "";
    param.insightIntentParam_ = nullptr;
    param.displayId_ = 2;
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND;
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    Want want;
    std::string startTime = want.GetStringParam(Want::PARAM_RESV_START_TIME);
    EXPECT_TRUE(startTime.empty());
    AbilityRuntime::ExtractInsightIntentGenericInfo decoratorInfo;
    InsightIntentExecuteManager::GenerateWant(paramPtr, decoratorInfo, want);
    startTime = want.GetStringParam(Want::PARAM_RESV_START_TIME);
    EXPECT_FALSE(startTime.empty());
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GenerateWant_0500
 * @tc.desc: GenerateWant_0500
 * @tc.type: FUNC
 * @tc.require: issueI8ZRAG
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, GenerateWant_0500, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "test.IntentName";
    param.insightIntentParam_ = nullptr;
    param.displayId_ = 2;
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND;
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    AbilityRuntime::ExtractInsightIntentGenericInfo decoratorInfo;
    Want want;
    int32_t result = InsightIntentExecuteManager::GenerateWant(paramPtr, decoratorInfo, want);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckIntentIsExemption_0100
 * @tc.desc: CheckIntentIsExemption_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckIntentIsExemption_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    std::shared_ptr<InsightIntentExecuteManager> manager = std::make_shared<InsightIntentExecuteManager>();
    EXPECT_NE(manager, nullptr);
    int32_t uid = NON_EXIST_ID;

    bool result = manager->CheckIntentIsExemption(uid);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckIntentIsExemption_0200
 * @tc.desc: CheckIntentIsExemption_0200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckIntentIsExemption_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    std::shared_ptr<InsightIntentExecuteManager> manager = std::make_shared<InsightIntentExecuteManager>();
    EXPECT_NE(manager, nullptr);
    int32_t uid = 1;
    manager->SetIntentExemptionInfo(uid);

    bool result = manager->CheckIntentIsExemption(uid);
    EXPECT_TRUE(result);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GetAllIntentExemptionInfo_0100
 * @tc.desc: GetAllIntentExemptionInfo_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, GetAllIntentExemptionInfo_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    std::shared_ptr<InsightIntentExecuteManager> manager = std::make_shared<InsightIntentExecuteManager>();
    EXPECT_NE(manager, nullptr);
    int32_t uid1 = 1;
    int32_t uid2 = 2;
    manager->SetIntentExemptionInfo(uid1);
    manager->SetIntentExemptionInfo(uid2);

    auto result = manager->GetAllIntentExemptionInfo();
    EXPECT_EQ(result.size(), 2);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: UpdateFuncDecoratorParams_0100
 * @tc.desc: UpdateFuncDecoratorParams_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, UpdateFuncDecoratorParams_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = nullptr;
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND;
    // other member has default value.
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    AbilityRuntime::ExtractInsightIntentInfo ententInfo;
    Want want;
    auto ret = InsightIntentExecuteManager::UpdateFuncDecoratorParams(paramPtr, ententInfo, want);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: UpdateFuncDecoratorParams_0200
 * @tc.desc: UpdateFuncDecoratorParams_0200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, UpdateFuncDecoratorParams_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = nullptr;
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND;
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    AbilityRuntime::ExtractInsightIntentInfo ententInfo;;
    Want want;
    auto ret = InsightIntentExecuteManager::UpdateFuncDecoratorParams(paramPtr, ententInfo, want);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: UpdateFuncDecoratorParams_0300
 * @tc.desc: UpdateFuncDecoratorParams_0300
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, UpdateFuncDecoratorParams_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = nullptr;
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND;
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    AbilityRuntime::ExtractInsightIntentInfo ententInfo;
    ententInfo.decoratorClass = "testClass";
    ententInfo.genericInfo.get<AbilityRuntime::InsightIntentFunctionInfo>().functionName = "";
    Want want;
    auto ret = InsightIntentExecuteManager::UpdateFuncDecoratorParams(paramPtr, ententInfo, want);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: UpdateFuncDecoratorParams_0400
 * @tc.desc: UpdateFuncDecoratorParams_0400
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, UpdateFuncDecoratorParams_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = nullptr;
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND;
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    AbilityRuntime::ExtractInsightIntentInfo ententInfo;
    ententInfo.decoratorClass = "";
    ententInfo.genericInfo.get<AbilityRuntime::InsightIntentFunctionInfo>().functionName = "testFunctionName";
    Want want;
    auto ret = InsightIntentExecuteManager::UpdateFuncDecoratorParams(paramPtr, ententInfo, want);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: UpdateFuncDecoratorParams_0500
 * @tc.desc: UpdateFuncDecoratorParams_0500
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, UpdateFuncDecoratorParams_0500, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = nullptr;
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND;
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    AbilityRuntime::ExtractInsightIntentInfo ententInfo;
    ententInfo.decoratorClass = "testClass";
    ententInfo.genericInfo.get<AbilityRuntime::InsightIntentFunctionInfo>().functionName = "testFunctionName";
    Want want;
    auto ret = InsightIntentExecuteManager::UpdateFuncDecoratorParams(paramPtr, ententInfo, want);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GetMainElementName_0100
 * @tc.desc: GetMainElementName_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, GetMainElementName_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "";
    param.insightIntentParam_ = nullptr;
    param.displayId_ = 2;
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND;
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    paramPtr->moduleName_ = "test.entry";
    std::string retString = InsightIntentExecuteManager::GetMainElementName(paramPtr);
    EXPECT_EQ(retString, "");
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: UpdatePageDecoratorParams_0100
 * @tc.desc: UpdatePageDecoratorParams_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, UpdatePageDecoratorParams_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = nullptr;
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND;
    // other member has default value.
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    AbilityRuntime::ExtractInsightIntentInfo intentInfo;
    Want want;
    auto ret = InsightIntentExecuteManager::UpdatePageDecoratorParams(paramPtr, intentInfo, want);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: UpdatePageDecoratorParams_0200
 * @tc.desc: UpdatePageDecoratorParams_0200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, UpdatePageDecoratorParams_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = nullptr;
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND;
    // other member has default value.
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    AbilityRuntime::ExtractInsightIntentInfo intentInfo;
    Want want;
    auto ret = InsightIntentExecuteManager::UpdatePageDecoratorParams(paramPtr, intentInfo, want);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: UpdatePageDecoratorParams_0300
 * @tc.desc: UpdatePageDecoratorParams_0300
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, UpdatePageDecoratorParams_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = nullptr;
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND;
    // other member has default value.
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    AbilityRuntime::ExtractInsightIntentInfo intentInfo;
    intentInfo.genericInfo.get<AbilityRuntime::InsightIntentPageInfo>().pagePath = "testPagePath";
    Want want;
    auto ret = InsightIntentExecuteManager::UpdatePageDecoratorParams(paramPtr, intentInfo, want);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: UpdatePageDecoratorParams_0400
 * @tc.desc: UpdatePageDecoratorParams_0400
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, UpdatePageDecoratorParams_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = nullptr;
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND;
    // other member has default value.
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    AbilityRuntime::ExtractInsightIntentInfo intentInfo;
    intentInfo.genericInfo.get<AbilityRuntime::InsightIntentPageInfo>().pagePath = "test.abilityName";
    intentInfo.genericInfo.get<AbilityRuntime::InsightIntentPageInfo>().uiAbility = "";
    Want want;
    auto ret = InsightIntentExecuteManager::UpdatePageDecoratorParams(paramPtr, intentInfo, want);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: UpdatePageDecoratorParams_0500
 * @tc.desc: UpdatePageDecoratorParams_0500
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, UpdatePageDecoratorParams_0500, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = nullptr;
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND;
    // other member has default value.
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    AbilityRuntime::ExtractInsightIntentInfo intentInfo;
    intentInfo.genericInfo.get<AbilityRuntime::InsightIntentPageInfo>().pagePath = "test.abilityName";
    intentInfo.genericInfo.get<AbilityRuntime::InsightIntentPageInfo>().uiAbility = "test.abilityName";
    Want want;
    auto ret = InsightIntentExecuteManager::UpdatePageDecoratorParams(paramPtr, intentInfo, want);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: UpdateEntryDecoratorParams_0100
 * @tc.desc: UpdateEntryDecoratorParams_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, UpdateEntryDecoratorParams_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Want want;
    auto mode = AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND;
    auto ret = InsightIntentExecuteManager::UpdateEntryDecoratorParams(want, mode);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

} // namespace AAFwk
} // namespace OHOS
