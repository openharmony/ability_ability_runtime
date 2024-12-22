/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "implicit_start_processor.h"
#include "operation.h"
#undef private
#undef protected
#include "ability_ecological_rule_mgr_service_param.h"
#include "hilog_tag_wrapper.h"
#include "parameters.h"
#include "mock_parameters.h"

using namespace OHOS;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace {
constexpr const char* SUPPORT_ACTION_START_SELECTOR = "persist.sys.ability.support.action_start_selector";
const std::string PARAM_ABILITY_APPINFOS = "ohos.ability.params.appInfos";
const std::string OPEN_LINK_APP_LINKING_ONLY = "appLinkingOnly";
const int NFC_CALLER_UID = 1027;
const std::string BUNDLE_NAME = "test_bundle";
const std::string NAME = "test_name";
}
namespace OHOS {
namespace AAFwk {

class ImplicitStartProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ImplicitStartProcessorTest::SetUpTestCase(void)
{}
void ImplicitStartProcessorTest::TearDownTestCase(void)
{}
void ImplicitStartProcessorTest::SetUp()
{}
void ImplicitStartProcessorTest::TearDown()
{}

/*
 * Feature: ImplicitStartProcessor
 * Function: ImplicitStartAbility
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor ImplicitStartAbility
 * EnvConditions: NA
 * CaseDescription: Verify ImplicitStartAbility
 */
HWTEST_F(ImplicitStartProcessorTest, ImplicitStartAbility_001, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    AbilityRequest request;
    int32_t userId = 0;
    bool res = processor->ImplicitStartAbility(request, userId,
        AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_UNDEFINED, "", true);
    EXPECT_TRUE(res);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: CheckImplicitStartExtensionIsValid
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor CheckImplicitStartExtensionIsValid
 * EnvConditions: NA
 * CaseDescription: Verify CheckImplicitStartExtensionIsValid
 */
HWTEST_F(ImplicitStartProcessorTest, CheckImplicitStartExtensionIsValid_001, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    AbilityRequest request;
    ExtensionAbilityInfo extensionInfo;
    Want want;
    want.SetElementName("bundle", "");
    request.want = want;
    bool res = processor->CheckImplicitStartExtensionIsValid(request, extensionInfo);
    EXPECT_TRUE(res);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: CheckImplicitStartExtensionIsValid
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor CheckImplicitStartExtensionIsValid
 * EnvConditions: NA
 * CaseDescription: Verify CheckImplicitStartExtensionIsValid
 */
HWTEST_F(ImplicitStartProcessorTest, CheckImplicitStartExtensionIsValid_002, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    AbilityRequest request;
    ExtensionAbilityInfo extensionInfo;
    Want want;
    want.SetElementName("", "");
    request.want = want;
    extensionInfo.type = ExtensionAbilityType::WORK_SCHEDULER;
    bool res = processor->CheckImplicitStartExtensionIsValid(request, extensionInfo);
    EXPECT_FALSE(res);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: CheckImplicitStartExtensionIsValid
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor CheckImplicitStartExtensionIsValid
 * EnvConditions: NA
 * CaseDescription: Verify CheckImplicitStartExtensionIsValid
 */
HWTEST_F(ImplicitStartProcessorTest, CheckImplicitStartExtensionIsValid_003, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    AbilityRequest request;
    ExtensionAbilityInfo extensionInfo;
    Want want;
    want.SetElementName("", "");
    request.want = want;
    extensionInfo.type = ExtensionAbilityType::FORM;
    bool res = processor->CheckImplicitStartExtensionIsValid(request, extensionInfo);
    EXPECT_TRUE(res);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: ImplicitStartAbilityInner
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor ImplicitStartAbilityInner
 * EnvConditions: NA
 * CaseDescription: Verify ImplicitStartAbilityInner
 */
HWTEST_F(ImplicitStartProcessorTest, ImplicitStartAbilityInner_001, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    Want want;
    AbilityRequest request;
    int32_t userId = 0;
    request.callType = AbilityCallType::START_OPTIONS_TYPE;
    bool res = processor->ImplicitStartAbilityInner(want, request, userId);
    EXPECT_NE(res, ERR_OK);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: ImplicitStartAbilityInner
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor ImplicitStartAbilityInner
 * EnvConditions: NA
 * CaseDescription: Verify ImplicitStartAbilityInner
 */
HWTEST_F(ImplicitStartProcessorTest, ImplicitStartAbilityInner_002, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    Want want;
    AbilityRequest request;
    int32_t userId = 0;
    request.callType = AbilityCallType::START_SETTINGS_TYPE;
    bool res = processor->ImplicitStartAbilityInner(want, request, userId);
    EXPECT_NE(res, ERR_OK);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: ImplicitStartAbilityInner
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor ImplicitStartAbilityInner
 * EnvConditions: NA
 * CaseDescription: Verify ImplicitStartAbilityInner
 */
HWTEST_F(ImplicitStartProcessorTest, ImplicitStartAbilityInner_003, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    Want want;
    AbilityRequest request;
    int32_t userId = 0;
    request.callType = AbilityCallType::START_EXTENSION_TYPE;
    bool res = processor->ImplicitStartAbilityInner(want, request, userId);
    EXPECT_NE(res, ERR_OK);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: ImplicitStartAbilityInner
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor ImplicitStartAbilityInner
 * EnvConditions: NA
 * CaseDescription: Verify ImplicitStartAbilityInner
 */
HWTEST_F(ImplicitStartProcessorTest, ImplicitStartAbilityInner_004, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    Want want;
    AbilityRequest request;
    int32_t userId = 0;
    request.callType = AbilityCallType::CALL_REQUEST_TYPE;
    bool res = processor->ImplicitStartAbilityInner(want, request, userId);
    EXPECT_NE(res, ERR_OK);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: CallStartAbilityInner
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor CallStartAbilityInner
 * EnvConditions: NA
 * CaseDescription: Verify CallStartAbilityInner
 */
HWTEST_F(ImplicitStartProcessorTest, CallStartAbilityInner_001, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    int32_t userId = 0;
    Want want;
    ImplicitStartProcessor::StartAbilityClosure callBack = []() -> int32_t {
        return 1;
    };
    AbilityCallType callType = AbilityCallType::INVALID_TYPE;
    bool res = processor->CallStartAbilityInner(userId, want, callBack, callType);
    EXPECT_NE(res, ERR_OK);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: CallStartAbilityInner
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor CallStartAbilityInner
 * EnvConditions: NA
 * CaseDescription: Verify CallStartAbilityInner
 */
HWTEST_F(ImplicitStartProcessorTest, CallStartAbilityInner_002, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    int32_t userId = 0;
    Want want;
    ImplicitStartProcessor::StartAbilityClosure callBack = []() -> int32_t {
        return 1;
    };
    AbilityCallType callType = AbilityCallType::CALL_REQUEST_TYPE;
    bool res = processor->CallStartAbilityInner(userId, want, callBack, callType);
    EXPECT_NE(res, ERR_OK);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: CallStartAbilityInner
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor CallStartAbilityInner
 * EnvConditions: NA
 * CaseDescription: Verify CallStartAbilityInner
 */
HWTEST_F(ImplicitStartProcessorTest, CallStartAbilityInner_003, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    int32_t userId = 0;
    Want want;
    ImplicitStartProcessor::StartAbilityClosure callBack = []() -> int32_t {
        return ERR_OK;
    };
    AbilityCallType callType = AbilityCallType::CALL_REQUEST_TYPE;
    bool res = processor->CallStartAbilityInner(userId, want, callBack, callType);
    EXPECT_EQ(res, ERR_OK);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: SetTargetLinkInfo
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor SetTargetLinkInfo
 * EnvConditions: NA
 * CaseDescription: Verify SetTargetLinkInfo
 */
HWTEST_F(ImplicitStartProcessorTest, SetTargetLinkInfo_001, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    std::vector<AppExecFwk::SkillUriForAbilityAndExtension> skillUri;
    AppExecFwk::SkillUriForAbilityAndExtension uri;
    uri.isMatch = true;
    uri.scheme = "https";
    skillUri.emplace_back(uri);
    Want want;
    want.SetParam("appLinkingOnly", true);
    processor->SetTargetLinkInfo(skillUri, want);
    int32_t targetLinkType = want.GetIntParam("send_to_erms_targetLinkType", 0);
    EXPECT_EQ(targetLinkType, 1);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: SetTargetLinkInfo
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor SetTargetLinkInfo
 * EnvConditions: NA
 * CaseDescription: Verify SetTargetLinkInfo
 */
HWTEST_F(ImplicitStartProcessorTest, SetTargetLinkInfo_002, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    std::vector<AppExecFwk::SkillUriForAbilityAndExtension> skillUri;
    AppExecFwk::SkillUriForAbilityAndExtension uri;
    uri.isMatch = true;
    uri.scheme = "https";
    skillUri.emplace_back(uri);
    Want want;
    want.SetAction("ohos.want.action.viewData");
    processor->SetTargetLinkInfo(skillUri, want);
    int32_t targetLinkType = want.GetIntParam("send_to_erms_targetLinkType", 0);
    EXPECT_EQ(targetLinkType, 3);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: SetTargetLinkInfo
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor SetTargetLinkInfo
 * EnvConditions: NA
 * CaseDescription: Verify SetTargetLinkInfo
 */
HWTEST_F(ImplicitStartProcessorTest, SetTargetLinkInfo_003, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    std::vector<AppExecFwk::SkillUriForAbilityAndExtension> skillUri;
    AppExecFwk::SkillUriForAbilityAndExtension uri;
    uri.isMatch = true;
    uri.scheme = "https";
    skillUri.emplace_back(uri);
    Want want;
    processor->SetTargetLinkInfo(skillUri, want);
    int32_t targetLinkType = want.GetIntParam("send_to_erms_targetLinkType", 0);
    EXPECT_EQ(targetLinkType, 2);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: MatchTypeAndUri
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor MatchTypeAndUri
 * EnvConditions: NA
 * CaseDescription: Verify MatchTypeAndUri
 */
HWTEST_F(ImplicitStartProcessorTest, MatchTypeAndUri_001, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    Want want;
    processor->MatchTypeAndUri(want);
    want.SetType("haha");
    EXPECT_EQ("haha", processor->MatchTypeAndUri(want));
    want.SetType("");
    want.SetUri("http://wwwsocom");
    EXPECT_EQ("", processor->MatchTypeAndUri(want));
    want.SetUri("http://www.so.com");
    processor->MatchTypeAndUri(want);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: ProcessLinkType
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor ProcessLinkType
 * EnvConditions: NA
 * CaseDescription: Verify ProcessLinkType SetUriReservedFlag SetUriReservedBundle etc.
 */
HWTEST_F(ImplicitStartProcessorTest, ProcessLinkType_001, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    AbilityInfo abilityInfo;
    abilityInfos.push_back(abilityInfo);
    AbilityInfo abilityInfo2;
    abilityInfo2.linkType = AppExecFwk::LinkType::APP_LINK;
    abilityInfos.push_back(abilityInfo2);
    EXPECT_TRUE(processor != nullptr);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: OnlyKeepReserveApp
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor OnlyKeepReserveApp
 * EnvConditions: NA
 * CaseDescription: Verify OnlyKeepReserveApp  etc.
 */
HWTEST_F(ImplicitStartProcessorTest, OnlyKeepReserveApp_001, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionAbInfos;
    AppExecFwk::ExtensionAbilityInfo  extensionAbInfo;
    extensionAbInfos.push_back(extensionAbInfo);
    AppExecFwk::AbilityInfo  abilityInfo;
    abilityInfo.bundleName = "haha";
    abilityInfos.push_back(abilityInfo);
    AbilityRequest abilityRequest;
    processor->OnlyKeepReserveApp(abilityInfos, extensionAbInfos, abilityRequest);
    EXPECT_TRUE(processor != nullptr);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: GetDefaultAppProxy
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor GetDefaultAppProxy
 * EnvConditions: NA
 * CaseDescription: Verify GetDefaultAppProxy  etc.
 */
HWTEST_F(ImplicitStartProcessorTest, GetDefaultAppProxy_001, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    auto result = processor->GetDefaultAppProxy();
    EXPECT_EQ(result, nullptr);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: FilterAbilityList
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor FilterAbilityList
 * EnvConditions: NA
 * CaseDescription: Verify FilterAbilityList  etc.
 */
HWTEST_F(ImplicitStartProcessorTest, FilterAbilityList_001, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    Want want;
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionAbInfos;
    int32_t  userId = 100;
    auto result = processor->FilterAbilityList(want, abilityInfos, extensionAbInfos, userId);
    EXPECT_EQ(result, true);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: AddIdentity
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor AddIdentity
 * EnvConditions: NA
 * CaseDescription: Verify AddIdentity  ResetCallingIdentityAsCaller AddAbilityInfoToDialogInfos etc.
 */
HWTEST_F(ImplicitStartProcessorTest, AddIdentity_001, TestSize.Level1)
{
    auto processor = std::make_shared<ImplicitStartProcessor>();
    int32_t  userId = 102;
    std::string  identity;
    processor->AddIdentity(userId, identity);
    processor->ResetCallingIdentityAsCaller(userId, true);
    AddInfoParam param;
    std::vector<DialogAppInfo> dialogAppInfos;
    param.isExtension = true;
    param.info.type = AbilityType::FORM;
    processor->AddAbilityInfoToDialogInfos(param, dialogAppInfos);
    param.isExtension = false;
    processor->AddAbilityInfoToDialogInfos(param, dialogAppInfos);
    EXPECT_TRUE(processor != nullptr);
}

/*
 * Feature: ImplicitStartProcessor
 * Function: IsExtensionInWhiteList
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor IsExtensionInWhiteList
 * EnvConditions: NA
 * CaseDescription: Verify IsExtensionInWhiteList.
 */
HWTEST_F(ImplicitStartProcessorTest, IsExtensionInWhiteList_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionInWhiteList_001 start");
    AppExecFwk::ExtensionAbilityType type = AppExecFwk::ExtensionAbilityType::FORM;
    auto processor = std::make_shared<ImplicitStartProcessor>();
    auto res = processor->IsExtensionInWhiteList(type);
    EXPECT_TRUE(res);
    type = AppExecFwk::ExtensionAbilityType::INPUTMETHOD;
    res = processor->IsExtensionInWhiteList(type);
    EXPECT_TRUE(res);
    type = AppExecFwk::ExtensionAbilityType::WALLPAPER;
    res = processor->IsExtensionInWhiteList(type);
    EXPECT_TRUE(res);
    type = AppExecFwk::ExtensionAbilityType::WINDOW;
    res = processor->IsExtensionInWhiteList(type);
    EXPECT_TRUE(res);
    type = AppExecFwk::ExtensionAbilityType::THUMBNAIL;
    res = processor->IsExtensionInWhiteList(type);
    EXPECT_TRUE(res);
    type = AppExecFwk::ExtensionAbilityType::PREVIEW;
    res = processor->IsExtensionInWhiteList(type);
    EXPECT_TRUE(res);
    type = AppExecFwk::ExtensionAbilityType::DRIVER;
    res = processor->IsExtensionInWhiteList(type);
    EXPECT_FALSE(res);
    TAG_LOGI(AAFwkTag::TEST, "IsExtensionInWhiteList_001 end");
}

/*
 * Feature: ImplicitStartProcessor
 * Function: FindExtensionInfo
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor FindExtensionInfo
 * EnvConditions: NA
 * CaseDescription: Verify FindExtensionInfo.
 */
HWTEST_F(ImplicitStartProcessorTest, FindExtensionInfo_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "FindExtensionInfo_001 start");
    auto processor = std::make_shared<ImplicitStartProcessor>();
    Want want;
    int32_t flags = 0;
    int32_t userId = 100;
    int32_t appIndex = 0;
    AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ElementName elementName("", "bundleName", "abilityName");
    want.SetElement(elementName);
    auto test = want.GetElement().GetBundleName();
    TAG_LOGI(AAFwkTag::TEST, "GetBundleName %{public}s", test.c_str());
    test = want.GetElement().GetAbilityName();
    TAG_LOGI(AAFwkTag::TEST, "GetAbilityName %{public}s", test.c_str());
    auto res = processor->FindExtensionInfo(want, flags, userId, appIndex, abilityInfo);
    EXPECT_EQ(res, RESOLVE_ABILITY_ERR);
    TAG_LOGI(AAFwkTag::TEST, "FindExtensionInfo_001 end");
}

/*
 * Feature: ImplicitStartProcessor
 * Function: IsActionImplicitStart
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor IsActionImplicitStart
 * EnvConditions: NA
 * CaseDescription: Verify IsActionImplicitStart.
 */
HWTEST_F(ImplicitStartProcessorTest, IsActionImplicitStart_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsActionImplicitStart_001 start");
    auto processor = std::make_shared<ImplicitStartProcessor>();
    Want want;
    system::SetParameter(SUPPORT_ACTION_START_SELECTOR, "false");
    bool findDeafultApp = true;
    auto res = processor->IsActionImplicitStart(want, findDeafultApp);
    EXPECT_FALSE(res);
    system::SetParameter(SUPPORT_ACTION_START_SELECTOR, "true");
    res = processor->IsActionImplicitStart(want, findDeafultApp);
    EXPECT_FALSE(res);
    findDeafultApp = false;
    res = processor->IsActionImplicitStart(want, findDeafultApp);
    EXPECT_FALSE(res);
    OHOS::AAFwk::Operation operation;
    operation.abilityName_ = "abilityName";
    operation.bundleName_ = "bundleName";
    operation.moduleName_ = "moduleName";
    std::string uriString = "action:com.ix.hi";
    OHOS::Uri uri(uriString);
    operation.SetUri(uri);
    want.operation_ = operation;
    res = processor->IsActionImplicitStart(want, findDeafultApp);
    EXPECT_FALSE(res);
    uri.uriString_ = "file";
    uri.scheme_ = "file";
    operation.SetUri(uri);
    want.operation_ = operation;
    res = processor->IsActionImplicitStart(want, findDeafultApp);
    EXPECT_FALSE(res);
    OHOS::AppExecFwk::ElementName elementName("deviceId", "", "abilityName");
    want.SetElement(elementName);
    res = processor->IsActionImplicitStart(want, findDeafultApp);
    EXPECT_TRUE(res);
    TAG_LOGI(AAFwkTag::TEST, "IsActionImplicitStart_001 end");
}

/*
 * Feature: ImplicitStartProcessor
 * Function: FindAbilityAppClone
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor FindAbilityAppClone
 * EnvConditions: NA
 * CaseDescription: Verify FindAbilityAppClone.
 */
HWTEST_F(ImplicitStartProcessorTest, FindAbilityAppClone_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "FindAbilityAppClone_001 start");
    auto processor = std::make_shared<ImplicitStartProcessor>();
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    bool res = processor->FindAbilityAppClone(abilityInfos);
    EXPECT_FALSE(res);
    AppExecFwk::AbilityInfo abilityInfo1;
    AppExecFwk::AbilityInfo abilityInfo2;
    abilityInfo1.bundleName = BUNDLE_NAME;
    abilityInfo1.name = NAME;
    abilityInfo2.bundleName = BUNDLE_NAME;
    abilityInfo2.name = NAME;
    abilityInfos.emplace_back(abilityInfo1);
    abilityInfos.emplace_back(abilityInfo2);
    res = processor->FindAbilityAppClone(abilityInfos);
    EXPECT_TRUE(res);
    TAG_LOGI(AAFwkTag::TEST, "FindAbilityAppClone_001 end");
}

/*
 * Feature: ImplicitStartProcessor
 * Function: FindExtensionAppClone
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor FindExtensionAppClone
 * EnvConditions: NA
 * CaseDescription: Verify FindExtensionAppClone.
 */
HWTEST_F(ImplicitStartProcessorTest, FindExtensionAppClone_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "FindExtensionAppClone start");
    auto processor = std::make_shared<ImplicitStartProcessor>();
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionAbilityInfos;
    bool res = processor->FindExtensionAppClone(extensionAbilityInfos);
    EXPECT_FALSE(res);
    AppExecFwk::ExtensionAbilityInfo extensionAbilityInfo1;
    AppExecFwk::ExtensionAbilityInfo extensionAbilityInfo2;
    extensionAbilityInfo1.bundleName = BUNDLE_NAME;
    extensionAbilityInfo1.name = NAME;
    extensionAbilityInfo2.bundleName = BUNDLE_NAME;
    extensionAbilityInfo2.name = NAME;
    extensionAbilityInfos.emplace_back(extensionAbilityInfo1);
    extensionAbilityInfos.emplace_back(extensionAbilityInfo2);
    res = processor->FindExtensionAppClone(extensionAbilityInfos);
    EXPECT_TRUE(res);
    TAG_LOGI(AAFwkTag::TEST, "FindExtensionAppClone end");
}

/*
 * Feature: ImplicitStartProcessor
 * Function: FindAppClone
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor FindAppClone
 * EnvConditions: NA
 * CaseDescription: Verify FindAppClone.
 */
HWTEST_F(ImplicitStartProcessorTest, FindAppClone_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "FindAppClone_001 start");
    auto processor = std::make_shared<ImplicitStartProcessor>();
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionAbilityInfos;
    AppExecFwk::AbilityInfo abilityInfo1;
    AppExecFwk::AbilityInfo abilityInfo2;
    AppExecFwk::ExtensionAbilityInfo extensionAbilityInfo1;
    AppExecFwk::ExtensionAbilityInfo extensionAbilityInfo2;
    extensionAbilityInfo1.name = NAME;
    extensionAbilityInfo1.bundleName = BUNDLE_NAME;
    extensionAbilityInfo2.name = NAME;
    extensionAbilityInfo2.bundleName = BUNDLE_NAME;
    abilityInfo1.bundleName = BUNDLE_NAME;
    abilityInfo1.name = NAME;
    abilityInfo2.bundleName = BUNDLE_NAME;
    abilityInfo2.name = NAME;
    bool isAppCloneSelector = false;
    abilityInfos.emplace_back(abilityInfo1);
    extensionAbilityInfos.emplace_back(extensionAbilityInfo1);
    auto res = processor->FindAppClone(abilityInfos, extensionAbilityInfos, isAppCloneSelector);
    EXPECT_EQ(res, ERR_OK);
    abilityInfos.clear();
    extensionAbilityInfos.emplace_back(extensionAbilityInfo2);
    res = processor->FindAppClone(abilityInfos, extensionAbilityInfos, isAppCloneSelector);
    EXPECT_EQ(res, ERR_OK);
    extensionAbilityInfos.clear();
    abilityInfos.emplace_back(abilityInfo1);
    abilityInfos.emplace_back(abilityInfo2);
    res = processor->FindAppClone(abilityInfos, extensionAbilityInfos, isAppCloneSelector);
    EXPECT_EQ(res, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "FindAppClone_001 end");
}
/*
 * Feature: ImplicitStartProcessor
 * Function: ImplicitStartAG
 * SubFunction: NA
 * FunctionPoints:ImplicitStartProcessor ImplicitStartAG
 * EnvConditions: NA
 * CaseDescription: Verify ImplicitStartAG.
 */
HWTEST_F(ImplicitStartProcessorTest, ImplicitStartAG_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ImplicitStartAG start");
    auto processor = std::make_shared<ImplicitStartProcessor>();
    int32_t userId = 100;
    AbilityRequest request;
    std::vector<DialogAppInfo> dialogAppInfos;
    GenerateRequestParam genReqParam;
    genReqParam.isMoreHapList = false;
    genReqParam.findDefaultApp = false;
    genReqParam.isAppCloneSelector = false;
    bool queryAGSuccess = true;
    auto ret = processor->ImplicitStartAG(userId, request, dialogAppInfos, genReqParam, queryAGSuccess);
    EXPECT_NE(ret, 0);
    TAG_LOGI(AAFwkTag::TEST, "ImplicitStartAG end");
}
}  // namespace AAFwk
}  // namespace OHOS
