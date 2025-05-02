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
#include "ecological_rule/ability_ecological_rule_mgr_service_param.h"
#include "interceptor/ecological_rule_interceptor.h"
#include "start_ability_utils.h"
#include "parameters.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using ErmsCallerInfo = OHOS::EcologicalRuleMgrService::AbilityCallerInfo;

namespace OHOS {
namespace AAFwk {
constexpr const char* ABILITY_SUPPORT_ECOLOGICAL_RULEMGRSERVICE =
    "persist.sys.abilityms.support.ecologicalrulemgrservice";
class EcologicalRuleInterceptorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void EcologicalRuleInterceptorTest::SetUpTestCase()
{}

void EcologicalRuleInterceptorTest::TearDownTestCase()
{}

void EcologicalRuleInterceptorTest::SetUp()
{}

void EcologicalRuleInterceptorTest::TearDown()
{}

/**
 * @tc.name: EcologicalRuleInterceptorTest_GetAppTypeByBundleType_001
 * @tc.desc: GetAppTypeByBundleType
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, EcologicalRuleInterceptorTest_GetAppTypeByBundleType_001, TestSize.Level1)
{
    int32_t bundleType = static_cast<int32_t>(AppExecFwk::BundleType::ATOMIC_SERVICE);
    auto result = EcologicalRuleInterceptor::GetAppTypeByBundleType(bundleType);
    EXPECT_EQ(result, ErmsCallerInfo::TYPE_ATOM_SERVICE);
}

/**
 * @tc.name: EcologicalRuleInterceptorTest_GetAppTypeByBundleType_002
 * @tc.desc: GetAppTypeByBundleType
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, EcologicalRuleInterceptorTest_GetAppTypeByBundleType_002, TestSize.Level1)
{
    int32_t bundleType = static_cast<int32_t>(AppExecFwk::BundleType::APP);
    auto result = EcologicalRuleInterceptor::GetAppTypeByBundleType(bundleType);
    EXPECT_EQ(result, ErmsCallerInfo::TYPE_HARMONY_APP);
}

/**
 * @tc.name: EcologicalRuleInterceptorTest_GetAppTypeByBundleType_003
 * @tc.desc: GetAppTypeByBundleType
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, EcologicalRuleInterceptorTest_GetAppTypeByBundleType_003, TestSize.Level1)
{
    int32_t bundleType = static_cast<int32_t>(AppExecFwk::BundleType::APP_SERVICE_FWK);
    auto result = EcologicalRuleInterceptor::GetAppTypeByBundleType(bundleType);
    EXPECT_EQ(result, ErmsCallerInfo::TYPE_APP_SERVICE);
}

/**
 * @tc.name: EcologicalRuleInterceptorTest_GetAppTypeByBundleType_004
 * @tc.desc: GetAppTypeByBundleType
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, EcologicalRuleInterceptorTest_GetAppTypeByBundleType_004, TestSize.Level1)
{
    int32_t bundleType = static_cast<int32_t>(-1);
    auto result = EcologicalRuleInterceptor::GetAppTypeByBundleType(bundleType);
    EXPECT_EQ(result, ErmsCallerInfo::TYPE_INVALID);
}
/**
 * @tc.name: QueryAtomicServiceStartupRule_001
 * @tc.desc: Tests the first branch in QueryAtomicServiceStartupRule where caller and target bundle names are the same
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, QueryAtomicServiceStartupRule_001, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    std::string bundleName = "com.example.test";
    ElementName element("", bundleName, "MainAbility");
    want.SetElement(element);
    want.SetParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME, bundleName);
    sptr<IRemoteObject> callerToken = nullptr;
    int userId = 100;
    AtomicServiceStartupRule rule;
    sptr<Want> replaceWant = nullptr;
    ErrCode result = interceptor->QueryAtomicServiceStartupRule(want, callerToken, userId, rule, replaceWant);
    EXPECT_EQ(result, ERR_INVALID_CALLER);
}

/**
 * @tc.name: QueryAtomicServiceStartupRule_002
 * @tc.desc: Tests the second branch in QueryAtomicServiceStartupRule where ERMS is not supported
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, QueryAtomicServiceStartupRule_002, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    std::string targetBundleName = "com.example.target";
    std::string callerBundleName = "com.example.caller";
    ElementName element("", targetBundleName, "MainAbility");
    want.SetElement(element);
    want.SetParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME, callerBundleName);
    sptr<IRemoteObject> callerToken = nullptr;
    int userId = 100;
    AtomicServiceStartupRule rule;
    sptr<Want> replaceWant = nullptr;
    OHOS::system::SetParameter(ABILITY_SUPPORT_ECOLOGICAL_RULEMGRSERVICE, "false");
    ErrCode result = interceptor->QueryAtomicServiceStartupRule(want, callerToken, userId, rule, replaceWant);
    EXPECT_EQ(result, ERR_CAPABILITY_NOT_SUPPORT);
}

/**
 * @tc.name: GetEcologicalTargetInfo_001
 * @tc.desc: Tests GetEcologicalTargetInfo with non-null StartAbilityInfo matching the want
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, GetEcologicalTargetInfo_001, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    std::string bundleName = "com.example.test";
    std::string abilityName = "MainAbility";
    ElementName element("", bundleName, abilityName);
    want.SetElement(element);
    std::string testFeature= "testFeature";
    int testType = 123;
    want.SetParam("send_to_erms_targetLinkFeature", testFeature);
    want.SetParam("send_to_erms_targetLinkType", testType);
    StartAbilityUtils::startAbilityInfo = std::make_shared<StartAbilityInfo>();
    StartAbilityUtils::startAbilityInfo->abilityInfo.bundleName = bundleName;
    StartAbilityUtils::startAbilityInfo->abilityInfo.name = abilityName;
    StartAbilityUtils::startAbilityInfo->abilityInfo.applicationInfo.appDistributionType = "test_dist_type";
    StartAbilityUtils::startAbilityInfo->abilityInfo.applicationInfo.appProvisionType = "test_provision_type";
    StartAbilityUtils::startAbilityInfo->abilityInfo.applicationInfo.bundleType =
        static_cast<AppExecFwk::BundleType>(AppExecFwk::BundleType::APP);
    StartAbilityUtils::startAbilityInfo->abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    StartAbilityUtils::startAbilityInfo->abilityInfo.extensionAbilityType = ExtensionAbilityType::SERVICE;
    StartAbilityUtils::startAbilityInfo->abilityInfo.applicationInfo.applicationReservedFlag =
        static_cast<AppExecFwk::ApplicationFlag>(123);
    ErmsCallerInfo callerInfo;
    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    interceptor->GetEcologicalTargetInfo(want, abilityInfo, callerInfo);
    EXPECT_EQ(callerInfo.targetLinkFeature, "testFeature");
    EXPECT_EQ(callerInfo.targetLinkType, 123);
    EXPECT_EQ(callerInfo.targetAppDistType, "test_dist_type");
    EXPECT_EQ(callerInfo.targetAppProvisionType, "test_provision_type");
    EXPECT_EQ(callerInfo.targetAppType, ErmsCallerInfo::TYPE_HARMONY_APP);
    EXPECT_EQ(callerInfo.targetAbilityType, AppExecFwk::AbilityType::PAGE);
    StartAbilityUtils::startAbilityInfo = nullptr;
}

/**
 * @tc.name: GetEcologicalTargetInfo_002
 * @tc.desc: Tests GetEcologicalTargetInfo with non-null abilityInfo when StartAbilityInfo doesn't match
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, GetEcologicalTargetInfo_002, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    std::string bundleName = "com.example.test";
    std::string abilityName = "MainAbility";
    ElementName element("", bundleName, abilityName);
    want.SetElement(element);
    std::string testFeature = "testFeature";
    int testType = 123;
    want.SetParam("send_to_erms_targetLinkFeature", testFeature);
    want.SetParam("send_to_erms_targetLinkType", testType);
    StartAbilityUtils::startAbilityInfo = std::make_shared<StartAbilityInfo>();
    StartAbilityUtils::startAbilityInfo->abilityInfo.bundleName = "different.bundle";
    StartAbilityUtils::startAbilityInfo->abilityInfo.name = "DifferentAbility";
    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = std::make_shared<AppExecFwk::AbilityInfo>();
    abilityInfo->applicationInfo.appDistributionType = "test_dist_type2";
    abilityInfo->applicationInfo.appProvisionType = "test_provision_type2";
    abilityInfo->applicationInfo.bundleType =
    static_cast<AppExecFwk::BundleType>(AppExecFwk::BundleType::ATOMIC_SERVICE);
    abilityInfo->type = AppExecFwk::AbilityType::SERVICE;
    abilityInfo->extensionAbilityType = OHOS::AppExecFwk::ExtensionAbilityType::SERVICE;
    abilityInfo->applicationInfo.applicationReservedFlag = static_cast<AppExecFwk::ApplicationFlag>(456);
    ErmsCallerInfo callerInfo;
    interceptor->GetEcologicalTargetInfo(want, abilityInfo, callerInfo);
    EXPECT_EQ(callerInfo.targetLinkFeature, "testFeature");
    EXPECT_EQ(callerInfo.targetLinkType, 123);
    EXPECT_EQ(callerInfo.targetAppDistType, "test_dist_type2");
    EXPECT_EQ(callerInfo.targetAppProvisionType, "test_provision_type2");
    EXPECT_EQ(callerInfo.targetAppType, ErmsCallerInfo::TYPE_ATOM_SERVICE);
    EXPECT_EQ(callerInfo.targetAbilityType, AppExecFwk::AbilityType::SERVICE);
    StartAbilityUtils::startAbilityInfo = nullptr;
}

/**
 * @tc.name: GetEcologicalTargetInfo_003
 * @tc.desc: Tests GetEcologicalTargetInfo with null abilityInfo and no matching StartAbilityInfo
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, GetEcologicalTargetInfo_003, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    std::string bundleName = "com.example.test";
    std::string abilityName = "MainAbility";
    ElementName element("", bundleName, abilityName);
    want.SetElement(element);
    std::string testFeature = "testFeature";
    int testType = 123;
    want.SetParam("send_to_erms_targetLinkFeature", testFeature);
    want.SetParam("send_to_erms_targetLinkType", testType);
    StartAbilityUtils::startAbilityInfo = std::make_shared<StartAbilityInfo>();
    StartAbilityUtils::startAbilityInfo->abilityInfo.bundleName = "different.bundle";
    StartAbilityUtils::startAbilityInfo->abilityInfo.name = "DifferentAbility";
    ErmsCallerInfo callerInfo;
    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    interceptor->GetEcologicalTargetInfo(want, abilityInfo, callerInfo);
    EXPECT_EQ(callerInfo.targetLinkFeature, "testFeature");
    EXPECT_EQ(callerInfo.targetLinkType, 123);
    EXPECT_EQ(callerInfo.targetAppDistType, "");
    EXPECT_EQ(callerInfo.targetAppProvisionType, "");
    EXPECT_EQ(callerInfo.targetAppType, 0);
    EXPECT_EQ(callerInfo.targetAbilityType, AppExecFwk::AbilityType::UNKNOWN);
    StartAbilityUtils::startAbilityInfo = nullptr;
}

/**
 * @tc.name: GetEcologicalCallerInfo_001
 * @tc.desc: Tests GetEcologicalCallerInfo with callerToken is null
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, GetEcologicalCallerInfo_001, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    std::string callerBundleName = "com.example.caller";
    want.SetParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME, callerBundleName);
    want.SetParam(Want::PARAM_RESV_CALLER_UID, 1000);
    want.SetParam(Want::PARAM_RESV_CALLER_PID, 2000);
    ErmsCallerInfo callerInfo;
    sptr<IRemoteObject> callerToken = nullptr;
    int userId = 100;
    interceptor->GetEcologicalCallerInfo(want, callerInfo, userId, callerToken);
    EXPECT_EQ(callerInfo.callerAppProvisionType, "");
    EXPECT_EQ(callerInfo.callerAppType, 0);
}

/**
 * @tc.name: GetEcologicalCallerInfo_002
 * @tc.desc: Tests GetEcologicalCallerInfo with sceneboard bundle case
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, GetEcologicalCallerInfo_002, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    std::string callerBundleName = "com.ohos.sceneboard";
    want.SetParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME, callerBundleName);
    want.SetParam(Want::PARAM_RESV_CALLER_UID, 1000);
    want.SetParam(Want::PARAM_RESV_CALLER_PID, 2000);
    ErmsCallerInfo callerInfo;
    callerInfo.callerAppType = ErmsCallerInfo::TYPE_HARMONY_APP;
    callerInfo.packageName = "";
    sptr<IRemoteObject> callerToken = nullptr;
    int userId = 100;
    interceptor->GetEcologicalCallerInfo(want, callerInfo, userId, callerToken);
    EXPECT_NE(callerInfo.callerAppType, ErmsCallerInfo::TYPE_ATOM_SERVICE);
    EXPECT_NE(callerInfo.callerAppType, ErmsCallerInfo::TYPE_APP_SERVICE);
}

/**
 * @tc.name: InitErmsCallerInfo_001
 * @tc.desc: Tests InitErmsCallerInfo with non-null abilityInfo when want element bundleName is empty
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, InitErmsCallerInfo_001, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    ElementName element("", "", "MainAbility");
    want.SetElement(element);
    std::string callerBundleName = "com.example.caller";
    want.SetParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME, callerBundleName);
    want.SetParam(Want::PARAM_RESV_CALLER_UID, 1000);
    want.SetParam(Want::PARAM_RESV_CALLER_PID, 2000);
    want.SetParam("send_to_erms_embedded", 1);
    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = std::make_shared<AppExecFwk::AbilityInfo>();
    abilityInfo->bundleName = "com.example.target";
    ErmsCallerInfo callerInfo;
    sptr<IRemoteObject> callerToken = nullptr;
    int userId = 100;
    interceptor->InitErmsCallerInfo(want, abilityInfo, callerInfo, userId, callerToken);
    EXPECT_EQ(callerInfo.packageName, callerBundleName);
    EXPECT_EQ(callerInfo.uid, 1000);
    EXPECT_EQ(callerInfo.pid, 2000);
    EXPECT_EQ(callerInfo.embedded, 1);
    EXPECT_EQ(callerInfo.userId, userId);
    EXPECT_EQ(callerInfo.targetBundleName, "com.example.target");
}

/**
 * @tc.name: InitErmsCallerInfo_002
 * @tc.desc: Tests InitErmsCallerInfo with non-empty want element bundleName
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, InitErmsCallerInfo_002, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    std::string bundleName = "com.example.target";
    ElementName element("", bundleName, "MainAbility");
    want.SetElement(element);
    std::string callerBundleName = "com.example.caller";
    want.SetParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME, callerBundleName);
    want.SetParam(Want::PARAM_RESV_CALLER_UID, 1000);
    want.SetParam(Want::PARAM_RESV_CALLER_PID, 2000);
    want.SetParam("send_to_erms_embedded", 1);
    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = std::make_shared<AppExecFwk::AbilityInfo>();
    abilityInfo->bundleName = "com.example.different";
    ErmsCallerInfo callerInfo;
    sptr<IRemoteObject> callerToken = nullptr;
    int userId = 100;
    interceptor->InitErmsCallerInfo(want, abilityInfo, callerInfo, userId, callerToken);
    EXPECT_EQ(callerInfo.packageName, callerBundleName);
    EXPECT_EQ(callerInfo.uid, 1000);
    EXPECT_EQ(callerInfo.pid, 2000);
    EXPECT_EQ(callerInfo.embedded, 1);
    EXPECT_EQ(callerInfo.userId, userId);
    EXPECT_EQ(callerInfo.targetBundleName, "");
}

/**
 * @tc.name: InitErmsCallerInfo_003
 * @tc.desc: Tests InitErmsCallerInfo with null abilityInfo
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, InitErmsCallerInfo_003, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    ElementName element("", "", "MainAbility");
    want.SetElement(element);
    std::string callerBundleName = "com.example.caller";
    want.SetParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME, callerBundleName);
    want.SetParam(Want::PARAM_RESV_CALLER_UID, 1000);
    want.SetParam(Want::PARAM_RESV_CALLER_PID, 2000);
    want.SetParam("send_to_erms_embedded", 1);
    ErmsCallerInfo callerInfo;
    sptr<IRemoteObject> callerToken = nullptr;
    int userId = 100;
    interceptor->InitErmsCallerInfo(want, nullptr, callerInfo, userId, callerToken);
    EXPECT_EQ(callerInfo.packageName, callerBundleName);
    EXPECT_EQ(callerInfo.uid, 1000);
    EXPECT_EQ(callerInfo.pid, 2000);
    EXPECT_EQ(callerInfo.embedded, 1);
    EXPECT_EQ(callerInfo.userId, userId);
    EXPECT_EQ(callerInfo.targetBundleName, "");
}
/**
 * @tc.name: DoProcess_001
 * @tc.desc: Tests the first branch in DoProcess where skipErms is true
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, DoProcess_001, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    int requestCode = 0;
    int userId = 100;
    StartAbilityUtils::skipErms = true;
    auto shouldBlockFunc = []() { return false; };
    AbilityInterceptorParam param = AbilityInterceptorParam(want, requestCode, userId, false, nullptr,
        shouldBlockFunc);
    ErrCode result = interceptor->DoProcess(param);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(StartAbilityUtils::skipErms, false);
}

/**
 * @tc.name: DoProcess_002
 * @tc.desc: Tests the branch where caller bundle name equals target bundle name
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, DoProcess_002, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    std::string bundleName = "com.example.test";
    ElementName element("", bundleName, "MainAbility");
    want.SetElement(element);
    want.SetParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME, bundleName);
    int requestCode = 0;
    int userId = 100;
    auto shouldBlockFunc = []() { return false; };
    AbilityInterceptorParam param = AbilityInterceptorParam(want, requestCode, userId, false, nullptr,
        shouldBlockFunc);
    ErrCode result = interceptor->DoProcess(param);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: DoProcess_003
 * @tc.desc: Tests DoProcess with Want and userId parameters (overloaded version)
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, DoProcess_003, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    std::string bundleName = "com.example.test";
    ElementName element("", bundleName, "MainAbility");
    want.SetElement(element);
    want.SetParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME, bundleName);
    int userId = 100;
    bool result = interceptor->DoProcess(want, userId);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: DoProcess_004
 * @tc.desc: Tests DoProcess with different caller and target bundle names
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, DoProcess_004, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    std::string targetBundleName = "com.example.target";
    std::string callerBundleName = "com.example.caller";
    ElementName element("", targetBundleName, "MainAbility");
    want.SetElement(element);
    want.SetParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME, callerBundleName);
    int requestCode = 0;
    int userId = 100;
    StartAbilityUtils::skipErms = true;
    auto shouldBlockFunc = []() { return false; };
    AbilityInterceptorParam param = AbilityInterceptorParam(want, requestCode, userId, false, nullptr,
        shouldBlockFunc);
    ErrCode result = interceptor->DoProcess(param);
    EXPECT_EQ(result, ERR_OK);
    StartAbilityUtils::skipErms = false;
}

/**
 * @tc.name: DoProcess_005
 * @tc.desc: Tests DoProcess (Want overload) with different caller and target bundle names
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, DoProcess_005, TestSize.Level1)
{
    std::shared_ptr<EcologicalRuleInterceptor> interceptor = std::make_shared<EcologicalRuleInterceptor>();
    Want want;
    std::string targetBundleName = "com.example.target";
    std::string callerBundleName = "com.example.caller";
    ElementName element("", targetBundleName, "MainAbility");
    want.SetElement(element);
    want.SetParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME, callerBundleName);
    OHOS::system::SetParameter(ABILITY_SUPPORT_ECOLOGICAL_RULEMGRSERVICE, "false");
    int userId = 100;
    StartAbilityUtils::skipErms = true;
    bool result = interceptor->DoProcess(want, userId);
    EXPECT_TRUE(result);
    StartAbilityUtils::skipErms = false;
}
} // namespace AAFwk
} // namespace OHOS
