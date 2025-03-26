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

#define private public
#define protected public
#include "ability.h"
#include "data_ability_operation.h"
#undef protected
#undef private
#include "ability_context_impl.h"
#include "ability_handler.h"
#include "ability_recovery.h"
#include "data_ability_predicates.h"
#include "data_ability_result.h"
#include "hilog_tag_wrapper.h"
#include "ohos_application.h"
#include "runtime.h"
#include "values_bucket.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int TEST_NUMBER_100 = 100;
constexpr double TEST_DOUBLE_PI = 3.1415926;
const std::string MODULE_NAME_EMPTY = "";
const std::string MODULE_NAME = "testModuleName";
const std::string URI = "dataability://ohos.demo.TestDataAbilityOperation";
const std::string TEST_PHONE_NUMBER = "phone_number";
const std::string TEST_VALUE = "12345";
}
class AbilitySecondTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AbilitySecondTest::SetUpTestCase(void)
{}

void AbilitySecondTest::TearDownTestCase(void)
{}

void AbilitySecondTest::SetUp(void)
{}

void AbilitySecondTest::TearDown(void)
{}

enum class Flagtype {
    TYPE_INT,
    TYPE_DOUBLE,
    TYPE_STRING,
    TYPE_BLOB,
    TYPE_BOOL,
    TYPE_NULL,
};

std::shared_ptr<DataAbilityOperation> CreateOperation(
    std::vector<std::shared_ptr<DataAbilityResult>> &results,
    std::shared_ptr<OHOS::NativeRdb::DataAbilityPredicates> &executePredicates,
    std::shared_ptr<Uri> &uri, Flagtype type)
{
    auto values = std::make_shared<OHOS::NativeRdb::ValuesBucket>();
    std::vector<uint8_t> value = {0x1, 0x2};

    switch(type){
        case Flagtype::TYPE_INT:
            values->PutInt(TEST_PHONE_NUMBER, TEST_NUMBER_100);
            break;
        case Flagtype::TYPE_DOUBLE:
            values->PutDouble(TEST_PHONE_NUMBER, TEST_DOUBLE_PI);
            break;
        case Flagtype::TYPE_STRING:
            values->PutString(TEST_PHONE_NUMBER, TEST_VALUE);
            break;
        case Flagtype::TYPE_BLOB:
            values->PutBlob(TEST_PHONE_NUMBER, value);
            break;
        case Flagtype::TYPE_BOOL:
            values->PutBool(TEST_PHONE_NUMBER, false);
            break;
        case Flagtype::TYPE_NULL:
            values->PutNull(TEST_PHONE_NUMBER);
            break;
        default:
            break;
    }

    std::shared_ptr<DataAbilityOperation> operation =
        DataAbilityOperation::NewUpdateBuilder(uri)
        ->WithValuesBucket(values)
        ->WithValueBackReferences(values)
        ->WithPredicatesBackReference(0, 0)
        ->WithPredicates(executePredicates)
        ->WithInterruptionAllowed(true)
        ->Build();

    auto dataAbilityResult = std::make_shared<DataAbilityResult>(TEST_NUMBER_100);
    results.push_back(dataAbilityResult);
    return operation;
}

/**
 * @tc.number: Ability_IsRestoredInContinuation_0100
 * @tc.name: IsRestoredInContinuation
 * @tc.desc: NA
 */
HWTEST_F(AbilitySecondTest, Ability_IsRestoredInContinuation_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Ability_IsRestoredInContinuation_0100 start";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    ASSERT_NE(ability, nullptr);

    auto ret = ability->IsRestoredInContinuation();
    EXPECT_FALSE(ret);

    auto abilityContext = std::make_shared<AbilityRuntime::AbilityContextImpl>();
    ability->AttachAbilityContext(abilityContext);
    AAFwk::LaunchParam launchParam;
    launchParam.launchReason = LaunchReason::LAUNCHREASON_START_ABILITY;
    ability->SetLaunchParam(launchParam);
    ret = ability->IsRestoredInContinuation();
    EXPECT_FALSE(ret);

    launchParam.launchReason = LaunchReason::LAUNCHREASON_CONTINUATION;
    ability->SetLaunchParam(launchParam);
    ret = ability->IsRestoredInContinuation();
    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "Ability_IsRestoredInContinuation_0100 end";
}

/**
 * @tc.number: Ability_ShouldRecoverState_0100
 * @tc.name: ShouldRecoverState
 * @tc.desc: NA
 */
HWTEST_F(AbilitySecondTest, Ability_ShouldRecoverState_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Ability_ShouldRecoverState_0100 start";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    ASSERT_NE(ability, nullptr);

    Want want;
    bool ret = ability->ShouldRecoverState(want);
    EXPECT_FALSE(ret);
    ability->HandleCreateAsRecovery(want);

    auto abilityRecovery = std::make_shared<AbilityRecovery>();
    ability->EnableAbilityRecovery(abilityRecovery);

    want.SetParam(Want::PARAM_ABILITY_RECOVERY_RESTART, true);
    ability->HandleCreateAsRecovery(want);
    ret = ability->ShouldRecoverState(want);
    EXPECT_FALSE(ret);

    auto abilityContext = std::make_shared<AbilityRuntime::AbilityContextImpl>();
    ability->AttachAbilityContext(abilityContext);

    ret = ability->ShouldRecoverState(want);
    EXPECT_FALSE(ret);

    GTEST_LOG_(INFO) << "Ability_ShouldRecoverState_0100 end";
}

/**
 * @tc.number: Ability_StartAbility_0100
 * @tc.name: StartAbility
 * @tc.desc: NA
 */
HWTEST_F(AbilitySecondTest, Ability_StartAbility_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Ability_StartAbility_0100 start";
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    ASSERT_NE(ability, nullptr);

    Want want;
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    want.SetElementName(bundleName, abilityName);
    AbilityStartSetting abilityStartSetting;

    std::shared_ptr<AbilityInfo> abilityInfo = nullptr;
    ability->abilityInfo_ = abilityInfo;
    auto ret = ability->StartAbility(want, abilityStartSetting);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);

    abilityInfo = std::make_shared<AbilityInfo>();
    abilityInfo->type = AppExecFwk::AbilityType::DATA;
    ability->abilityInfo_ = abilityInfo;
    ret = ability->StartAbility(want, abilityStartSetting);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    abilityInfo->type = AppExecFwk::AbilityType::PAGE;
    ability->abilityInfo_ = abilityInfo;
    ret = ability->StartAbility(want, abilityStartSetting);
    EXPECT_NE(ret, ERR_OK);

    abilityInfo->type = AppExecFwk::AbilityType::SERVICE;
    ability->abilityInfo_ = abilityInfo;
    ret = ability->StartAbility(want, abilityStartSetting);
    EXPECT_NE(ret, ERR_OK);

    GTEST_LOG_(INFO) << "Ability_StartAbility_0100 end";
}

/**
 * @tc.number: Ability_GetModuleName_0100
 * @tc.name: GetModuleName
 * @tc.desc: NA
 */
HWTEST_F(AbilitySecondTest, Ability_GetModuleName_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Ability_GetModuleName_0100 start";

    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    ASSERT_NE(ability, nullptr);

    ability->abilityInfo_ = nullptr;
    EXPECT_STREQ(ability->GetModuleName().c_str(), MODULE_NAME_EMPTY.c_str());

    std::shared_ptr<AbilityInfo> abilityInfo = std::make_shared<AbilityInfo>();
    ASSERT_NE(abilityInfo, nullptr);

    abilityInfo->moduleName = MODULE_NAME;
    ability->abilityInfo_ = abilityInfo;
    EXPECT_STREQ(ability->GetModuleName().c_str(), MODULE_NAME.c_str());

    GTEST_LOG_(INFO) << "Ability_GetModuleName_0100 end";
}

/**
 * @tc.number: Ability_ExecuteBatch_0100
 * @tc.name: ExecuteBatch
 * @tc.desc: NA
 */
HWTEST_F(AbilitySecondTest, Ability_ExecuteBatch_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Ability_ExecuteBatch_0100 start";

    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    ASSERT_NE(ability, nullptr);

    auto uri = std::make_shared<Uri>(URI);
    std::shared_ptr<DataAbilityOperation> operation = DataAbilityOperation::NewUpdateBuilder(uri)->Build();
    std::vector<std::shared_ptr<DataAbilityOperation>> executeBatchOperations;
    executeBatchOperations.push_back(operation);

    auto result = ability->ExecuteBatch(executeBatchOperations);
    EXPECT_EQ(result.size(), 0);

    auto abilityInfo = std::make_shared<AbilityInfo>();
    EXPECT_NE(abilityInfo, nullptr);
    abilityInfo->name = "test_ExecuteOperation";
    abilityInfo->type = AbilityType::PAGE;
    auto application = std::make_shared<OHOSApplication>();
    EXPECT_NE(application, nullptr);
    auto eventRunner = EventRunner::Create(abilityInfo->name);
    auto handler = std::make_shared<AbilityHandler>(eventRunner);
    sptr<IRemoteObject> token = nullptr;
    ability->Init(abilityInfo, application, handler, token);
    result = ability->ExecuteBatch(executeBatchOperations);
    EXPECT_EQ(result.size(), 0);

    GTEST_LOG_(INFO) << "Ability_ExecuteBatch_0100 end";
}

/**
 * @tc.number: Ability_ExecuteBatch_0200
 * @tc.name: ExecuteBatch
 * @tc.desc: NA
 */
HWTEST_F(AbilitySecondTest, Ability_ExecuteBatch_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Ability_ExecuteBatch_0200 start";

    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    ASSERT_NE(ability, nullptr);
    std::shared_ptr<AbilityInfo> abilityInfo = std::make_shared<AbilityInfo>();
    abilityInfo->type = AbilityType::DATA;
    std::shared_ptr<EventRunner> eventRunner = EventRunner::Create(abilityInfo->name);
    std::shared_ptr<AbilityHandler> handler = std::make_shared<AbilityHandler>(eventRunner);
    abilityInfo->isNativeAbility = true;
    ability->Init(abilityInfo, nullptr, handler, nullptr);

    OHOS::NativeRdb::DataAbilityPredicates predicates;
    predicates.GreaterThan("id", "0");
    std::shared_ptr<OHOS::NativeRdb::DataAbilityPredicates> executePredicates =
        std::make_shared<OHOS::NativeRdb::DataAbilityPredicates>(predicates);

    std::vector<std::shared_ptr<DataAbilityResult>> results;
    auto uri = std::make_shared<Uri>(URI);
    auto operation = CreateOperation(results, executePredicates, uri, Flagtype::TYPE_STRING);
    ASSERT_NE(operation, nullptr);
    std::vector<std::shared_ptr<DataAbilityOperation>> executeBatchOperations;
    std::shared_ptr<DataAbilityOperation> operation2 = nullptr;
    executeBatchOperations.push_back(operation);
    executeBatchOperations.push_back(operation2);

    std::vector<std::shared_ptr<DataAbilityResult>> ret = ability->ExecuteBatch(executeBatchOperations);
    EXPECT_STREQ(ret.at(0)->GetUri().ToString().c_str(), uri->ToString().c_str());

    GTEST_LOG_(INFO) << "Ability_ExecuteBatch_0200 end";
}

/**
 * @tc.number: Ability_ParsePredictionArgsReference_0100
 * @tc.name: ParsePredictionArgsReference
 * @tc.desc: NA
 */
HWTEST_F(AbilitySecondTest, Ability_ParsePredictionArgsReference_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Ability_ParsePredictionArgsReference_0100 start";

    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    ASSERT_NE(ability, nullptr);

    std::vector<std::shared_ptr<DataAbilityResult>> results;
    std::shared_ptr<DataAbilityOperation> operation = nullptr;
    int numRefs = TEST_NUMBER_100;
    auto ret = ability->ParsePredictionArgsReference(results, operation, numRefs);
    EXPECT_EQ(ret, nullptr);

    operation = std::make_shared<DataAbilityOperation>();
    ASSERT_NE(operation, nullptr);
    ret = ability->ParsePredictionArgsReference(results, operation, numRefs);
    EXPECT_NE(ret, nullptr);

    auto uri = std::make_shared<Uri>(URI);
    std::shared_ptr<OHOS::NativeRdb::DataAbilityPredicates> executePredicates = nullptr;
    operation = CreateOperation(results, executePredicates, uri, Flagtype::TYPE_STRING);
    ASSERT_NE(operation, nullptr);
    ret = ability->ParsePredictionArgsReference(results, operation, numRefs);
    EXPECT_EQ(ret, nullptr);

    GTEST_LOG_(INFO) << "Ability_ParsePredictionArgsReference_0100 end";
}

/**
 * @tc.number: Ability_ParseValuesBucketReference_0100
 * @tc.name: ParseValuesBucketReference
 * @tc.desc: NA
 */
HWTEST_F(AbilitySecondTest, Ability_ParseValuesBucketReference_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Ability_ParseValuesBucketReference_0100 start";

    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    ASSERT_NE(ability, nullptr);

    int numRefs = TEST_NUMBER_100;
    std::vector<std::shared_ptr<DataAbilityResult>> results;
    std::shared_ptr<DataAbilityOperation> operation = nullptr;
    auto ret = ability->ParseValuesBucketReference(results, operation, numRefs);
    EXPECT_EQ(ret, nullptr);

    auto uri = std::make_shared<Uri>(URI);
    std::shared_ptr<OHOS::NativeRdb::DataAbilityPredicates> executePredicates = nullptr;
    operation = CreateOperation(results, executePredicates, uri, Flagtype::TYPE_INT);
    ASSERT_NE(operation, nullptr);
    ret = ability->ParseValuesBucketReference(results, operation, numRefs);
    EXPECT_NE(ret, nullptr);

    operation = CreateOperation(results, executePredicates, uri, Flagtype::TYPE_DOUBLE);
    ASSERT_NE(operation, nullptr);
    ret = ability->ParseValuesBucketReference(results, operation, numRefs);
    EXPECT_NE(ret, nullptr);

    operation = CreateOperation(results, executePredicates, uri, Flagtype::TYPE_STRING);
    ASSERT_NE(operation, nullptr);
    ret = ability->ParseValuesBucketReference(results, operation, numRefs);
    EXPECT_NE(ret, nullptr);

    operation = CreateOperation(results, executePredicates, uri, Flagtype::TYPE_BLOB);
    ASSERT_NE(operation, nullptr);
    ret = ability->ParseValuesBucketReference(results, operation, numRefs);
    EXPECT_NE(ret, nullptr);

    operation = CreateOperation(results, executePredicates, uri, Flagtype::TYPE_BOOL);
    ASSERT_NE(operation, nullptr);
    ret = ability->ParseValuesBucketReference(results, operation, numRefs);
    EXPECT_NE(ret, nullptr);

    operation = CreateOperation(results, executePredicates, uri, Flagtype::TYPE_NULL);
    ASSERT_NE(operation, nullptr);
    ret = ability->ParseValuesBucketReference(results, operation, numRefs);
    EXPECT_NE(ret, nullptr);

    GTEST_LOG_(INFO) << "Ability_ParseValuesBucketReference_0100 end";
}
}  // namespace AppExecFwk
}  // namespace OHOS
