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
#include "ability_manager_service.h"
#include "ability_record.h"
#include "mission_list_manager.h"
#include "ui_ability_lifecycle_manager.h"
#undef private
#undef protected

#include "ability_manager_errors.h"
#include "ability_manager_stub_mock_test.h"
#include "hilog_tag_wrapper.h"
#include "mock_ability_token.h"
#include "mock_bundle_manager_service.h"
#include "mock_my_flag.h"
#include "mock_permission_verification.h"
#include "mock_task_handler_wrap.h"
#include "process_options.h"
#include "scene_board_judgement.h"

using namespace testing;
using namespace testing::ext;
using testing::_;
using testing::Invoke;
using testing::Return;

using namespace OHOS::AppExecFwk;
using OHOS::AppExecFwk::AbilityType;
using OHOS::AppExecFwk::ExtensionAbilityType;
namespace OHOS {
namespace AAFwk {
namespace {
const int32_t USER_ID_U100 = 100;
const int32_t APP_MEMORY_SIZE = 512;
constexpr const char* DEBUG_APP = "debugApp";
const std::string TEST_BUNDLE_NAME = "testBundleName";
const std::string TEST_ABILITY_NAME = "testAbilityName";
const std::string CONTACTS_BUNDLE_NAME = "com.ohos.contacts";
const std::string CONTACTS_ABILITY_NAME = "com.ohos.contacts.MainAbility";
const std::string DEVICE_MANAGER_BUNDLE_NAME = "com.ohos.devicemanagerui";
const std::string DEVICE_MANAGER_NAME = "com.ohos.devicemanagerui.MainAbility";
const std::string UIEXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string AUTO_FILL_PASSWORD_TPYE = "autoFill/password";
const std::string AUTO_FILL_SMART_TPYE = "autoFill/smart";
const std::string AUTO_FILL_PASSWORD_ABILITY_NAME = "AutoFillAbility";
const std::string AUTO_FILL_PASSWORD_BUNDLE_NAME = "com.ohos.passwordbox";
const std::string AUTO_FILL_MODULE_NAME = "entry";
const std::string AUTO_FILL_SMART_ABILITY_NAME = "TextAutoFillAbility";
const std::string AUTO_FILL_SMART_BUNDLE_NAME = "com.ohos.textautofill";
const int32_t MAIN_USER_ID = 100;
const std::string EMPTY_DEVICE_ID = "";
constexpr const char* BUNDLE_NAME_LAUNCHER = "com.ohos.launcher";
constexpr const char* BUNDLE_NAME_SCENEBOARD = "com.ohos.sceneboard";
constexpr const char* LAUNCHER_ABILITY_NAME = "com.ohos.launcher.MainAbility";
constexpr const char* SCENEBOARD_ABILITY_NAME = "com.ohos.sceneboard.MainAbility";
constexpr const char* BUNDLE_NAME_TEST = "com.huawei.hmos.passwordvault";
constexpr const char* BUNDLE_NAME_SMART_TEST = "com.huawei.hms.textautofill";
}  // namespace
class AbilityManagerServiceSixthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    AbilityRequest GenerateAbilityRequest(const std::string& deviceName, const std::string& abilityName,
        const std::string& appName, const std::string& bundleName, const std::string& moduleName);

    std::shared_ptr<AbilityManagerService> MockAbilityManagerService();

public:
    AbilityRequest abilityRequest_{};
    Want want_{};
    AbilityStartSetting abilityStartSetting_;
};

AbilityRequest AbilityManagerServiceSixthTest::GenerateAbilityRequest(const std::string& deviceName,
    const std::string& abilityName, const std::string& appName, const std::string& bundleName,
    const std::string& moduleName)
{
    ElementName element(deviceName, bundleName, abilityName, moduleName);
    want_.SetElement(element);

    AbilityInfo abilityInfo;
    abilityInfo.visible = true;
    abilityInfo.applicationName = appName;
    abilityInfo.type = AbilityType::EXTENSION;
    abilityInfo.name = abilityName;
    abilityInfo.bundleName = bundleName;
    abilityInfo.moduleName = moduleName;
    abilityInfo.deviceId = deviceName;
    ApplicationInfo appinfo;
    appinfo.name = appName;
    appinfo.bundleName = bundleName;
    abilityInfo.applicationInfo = appinfo;
    AbilityRequest abilityRequest;
    abilityRequest.want = want_;
    abilityRequest.abilityInfo = abilityInfo;
    abilityRequest.appInfo = appinfo;

    return abilityRequest;
}

std::shared_ptr<AbilityManagerService> AbilityManagerServiceSixthTest::MockAbilityManagerService()
{
    auto abilityMs = std::make_shared<AbilityManagerService>();
    auto taskHandler = MockTaskHandlerWrap::CreateQueueHandler("StartAbilityDetails_003");
    auto eventHandler = std::make_shared<AbilityEventHandler>(taskHandler, abilityMs);
    abilityMs->taskHandler_ = taskHandler;
    abilityMs->interceptorExecuter_ = std::make_shared<AbilityInterceptorExecuter>();
    abilityMs->afterCheckExecuter_ = std::make_shared<AbilityInterceptorExecuter>();
    abilityMs->subManagersHelper_ = std::make_shared<SubManagersHelper>(taskHandler, eventHandler);
    return abilityMs;
}

void AbilityManagerServiceSixthTest::SetUpTestCase() {}

void AbilityManagerServiceSixthTest::TearDownTestCase() {}

void AbilityManagerServiceSixthTest::SetUp() {}

void AbilityManagerServiceSixthTest::TearDown() {}

/*
 * Feature: AbilityManagerService
 * Function: InitPushTask
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService InitPushTask
 */
HWTEST_F(AbilityManagerServiceSixthTest, InitPushTask_001, TestSize.Level1)
{
    auto abilityMs = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs, nullptr);
    std::shared_ptr<MockTaskHandlerWrap> taskHandler =
        MockTaskHandlerWrap::CreateQueueHandler("AbilityManagerServiceSixth");
    abilityMs->taskHandler_ = taskHandler;
    EXPECT_CALL(*taskHandler, SubmitTaskInner(_, _)).Times(testing::AtLeast(1));
    abilityMs->InitPushTask();
    EXPECT_NE(taskHandler, nullptr);
}

/*
 * Feature: AbilityManagerService
 * Function: SetReserveInfo
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService SetReserveInfo
 */
HWTEST_F(AbilityManagerServiceSixthTest, SetReserveInfo_001, TestSize.Level1)
{
    std::shared_ptr<AbilityManagerService> abilityMs = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs, nullptr);
    const std::string deviceName = "";
    const std::string abilityName = "EntryAbility";
    const std::string appName = "amstest";
    const std::string bundleName = "com.example.amstest";
    const std::string moduleName = "entry";
    AbilityRequest abilityRequest = AbilityManagerServiceSixthTest::GenerateAbilityRequest(deviceName,
        abilityName, appName, bundleName, moduleName);
    std::string linkString = "NaN";
    abilityMs->SetReserveInfo(linkString, abilityRequest);
    EXPECT_FALSE(abilityRequest.uriReservedFlag);
    EXPECT_EQ(abilityRequest.reservedBundleName, "");
}

/*
 * Feature: AbilityManagerService
 * Function: LockMissionForCleanup
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService LockMissionForCleanup
 */
HWTEST_F(AbilityManagerServiceSixthTest, LockMissionForCleanup_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest LockMissionForCleanup_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    EXPECT_EQ(abilityMs->LockMissionForCleanup(1), CHECK_PERMISSION_FAILED);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest LockMissionForCleanup_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: ReportEventToRss
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService ReportEventToRss
 */
HWTEST_F(AbilityManagerServiceSixthTest, ReportEventToRss_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest ReportEventToRss_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    std::shared_ptr<MockTaskHandlerWrap> taskHandler =
        MockTaskHandlerWrap::CreateQueueHandler("AbilityManagerServiceSixth");
    EXPECT_CALL(*taskHandler, SubmitTaskInner(_, _)).Times(testing::AtLeast(1));
    abilityMs->taskHandler_ = taskHandler;

    sptr<IRemoteObject> callerToken = nullptr;
    AppExecFwk::AbilityInfo abilityInfo1;
    abilityInfo1.type == AppExecFwk::AbilityType::PAGE;
    abilityMs->ReportEventToRSS(abilityInfo1, callerToken);

    AppExecFwk::AbilityInfo abilityInfo2;
    abilityInfo2.type == AppExecFwk::AbilityType::EXTENSION;
    abilityInfo2.extensionAbilityType == AppExecFwk::ExtensionAbilityType::SERVICE;
    abilityMs->ReportEventToRSS(abilityInfo2, callerToken);

    AppExecFwk::AbilityInfo abilityInfo3;
    abilityInfo3.type == AppExecFwk::AbilityType::EXTENSION;
    abilityInfo3.extensionAbilityType ==  AppExecFwk::ExtensionAbilityType::UI;
    abilityMs->ReportEventToRSS(abilityInfo3, callerToken);
    EXPECT_NE(taskHandler, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest ReportEventToRss_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: StartUIAbilityBySCBDefault
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService StartUIAbilityBySCBDefault
 */
HWTEST_F(AbilityManagerServiceSixthTest, StartUIAbilityBySCBDefault_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartUIAbilityBySCBDefault_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    ASSERT_NE(abilityMs, nullptr);
    std::shared_ptr<MockTaskHandlerWrap> taskHandler =
        MockTaskHandlerWrap::CreateQueueHandler("AbilityManagerServiceSixth");
    abilityMs->taskHandler_ = taskHandler;
    sptr<SessionInfo> sessionInfo = new SessionInfo();
    uint32_t sceneFlag = 0;
    bool isColdStart = true;
    abilityMs->interceptorExecuter_ = std::make_shared<AbilityInterceptorExecuter>();
    EXPECT_EQ(abilityMs->StartUIAbilityBySCBDefault(sessionInfo, sceneFlag, isColdStart), RESOLVE_ABILITY_ERR);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartUIAbilityBySCBDefault_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: StartAbilityDetails
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService StartAbilityDetails
 */
HWTEST_F(AbilityManagerServiceSixthTest, StartAbilityDetails_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartAbilityDetails_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    Want want;
    want.SetParam(DEBUG_APP, true);
    want.SetElementName(TEST_BUNDLE_NAME, "");

    /**
     * @tc.steps: step1. DEBUG app which is not exists
     * @tc.expected: step1. expect RESOLVE_ABILITY_ERR
     */
    auto ret = abilityMs->StartAbilityDetails(want, abilityStartSetting_, nullptr, -1, -1, false);
    EXPECT_EQ(ret, RESOLVE_ABILITY_ERR);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartAbilityDetails_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: StartAbilityDetails
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService StartAbilityDetails
 */
HWTEST_F(AbilityManagerServiceSixthTest, StartAbilityDetails_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartAbilityDetails_0200 start");

    Want want;
    want.SetParam(DEBUG_APP, true);
    want.SetElementName(CONTACTS_BUNDLE_NAME, CONTACTS_ABILITY_NAME);
    auto abilityMs = std::make_shared<AbilityManagerService>();
    auto ret = abilityMs->StartAbilityDetails(want, abilityStartSetting_, nullptr, -1, -1, false);

    /**
     * @tc.steps: step2. CONTACTS_BUNDLE_NAME
     * @tc.expected: step2. expect ERR_NOT_IN_APP_PROVISION_MODE
     */
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        EXPECT_EQ(ret, RESOLVE_ABILITY_ERR);
    } else {
        EXPECT_EQ(ret, ERR_NOT_IN_APP_PROVISION_MODE);
    }
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartAbilityDetails_0200 end");
}

/*
 * Feature: AbilityManagerService
 * Function: StartAbilityDetails
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService StartAbilityDetails
 */
HWTEST_F(AbilityManagerServiceSixthTest, StartAbilityDetails_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartAbilityDetails_002 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();

    /**
     * @tc.steps: step1. interceptorExecuter_ is null
     * @tc.expected: step1. expect return ERR_INVALID_VALUE when interceptorExecuter_ null
     */
    Want want1;
    want1.SetElementName(DEVICE_MANAGER_BUNDLE_NAME, DEVICE_MANAGER_NAME);
    auto ret = abilityMs->StartAbilityDetails(want1, abilityStartSetting_, nullptr, MAIN_USER_ID, -1, false);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartAbilityDetails_002 end");
}

/*
 * Feature: AbilityManagerService
 * Function: StartAbilityDetails
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService StartAbilityDetails
 */
HWTEST_F(AbilityManagerServiceSixthTest, StartAbilityDetails_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartAbilityDetails_003 start");

    Want want;
    want.SetElementName(CONTACTS_BUNDLE_NAME, CONTACTS_ABILITY_NAME);
    auto abilityMs = MockAbilityManagerService();
    auto ret = abilityMs->StartAbilityDetails(want, abilityStartSetting_, nullptr, -1, -1, false);

    /**
     * @tc.steps: step2. interceptorExecuter_ is inited, for CONTACTS_BUNDLE_NAME is sigeleton，usrid 0
     * @tc.expected: step2. expect missionListManager/uiAbilityManager null, return ERR_INVALID_VALUE
     */
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        EXPECT_EQ(ret, RESOLVE_ABILITY_ERR);
    } else {
        EXPECT_EQ(ret, ERR_INVALID_VALUE);
    }
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartAbilityDetails_003 end");
}

/*
 * Feature: AbilityManagerService
 * Function: StartAbilityDetails
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService StartAbilityInner
 */
HWTEST_F(AbilityManagerServiceSixthTest, StartAbilityInner_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartAbilityInner_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    abilityMs->taskHandler_ = MockTaskHandlerWrap::CreateQueueHandler("StartAbilityInner_001");
    abilityMs->interceptorExecuter_ = std::make_shared<AbilityInterceptorExecuter>();
    abilityMs->afterCheckExecuter_ = std::make_shared<AbilityInterceptorExecuter>();
    Want want;
    want.SetElementName(CONTACTS_BUNDLE_NAME, CONTACTS_ABILITY_NAME);
    auto ret = abilityMs->StartAbilityInner(want, nullptr, -1, false);

    /**
     * @tc.steps: step2. interceptorExecuter_ is inited, for CONTACTS_BUNDLE_NAME is sigeleton，usrid 0
     * @tc.expected: step2. expect missionListManager/uiAbilityManager null, return ERR_INVALID_VALUE
     */
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        EXPECT_EQ(ret, RESOLVE_ABILITY_ERR);
    } else {
        EXPECT_EQ(ret, ERR_INVALID_VALUE);
    }
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartAbilityInner_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: StartAbilityDetails
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService StartAbilityInner
 */
HWTEST_F(AbilityManagerServiceSixthTest, StartAbilityInner_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartAbilityInner_002 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();

    abilityMs->taskHandler_ = MockTaskHandlerWrap::CreateQueueHandler("StartAbilityInner_002");
    abilityMs->interceptorExecuter_ = std::make_shared<AbilityInterceptorExecuter>();
    abilityMs->afterCheckExecuter_ = std::make_shared<AbilityInterceptorExecuter>();
    Want want;
    want.SetFlags(Want::FLAG_ABILITY_PREPARE_CONTINUATION);
    auto ret = abilityMs->StartAbilityInner(want, nullptr, -1, false, -1, false, -1, true);
    EXPECT_EQ(ret, ERR_INVALID_CONTINUATION_FLAG);

    /**
     * @tc.steps: step2. interceptorExecuter_ is inited, for CONTACTS_BUNDLE_NAME is sigeleton，usrid 0
     * @tc.expected: step2. expect missionListManager/uiAbilityManager null, return ERR_INVALID_VALUE
     */
    auto callerToken = sptr<MockAbilityToken>::MakeSptr();
    MyFlag::flag_ = MyFlag::IS_SA_CALL;
    Want want2;
    want2.SetElementName(CONTACTS_BUNDLE_NAME, CONTACTS_ABILITY_NAME);
    ret = abilityMs->StartAbilityInner(want2, callerToken, -1, false, -1, true, 1, true);
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        EXPECT_EQ(ret, RESOLVE_ABILITY_ERR);
    } else {
        EXPECT_EQ(ret, ERR_INVALID_VALUE);
    }
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartAbilityInner_002 end");
}

/*
 * Feature: AbilityManagerService
 * Function: SetAutoFillElementName
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService SetAutoFillElementName
 */
HWTEST_F(AbilityManagerServiceSixthTest, SetAutoFillElementName_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest SetAutoFillElementName_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    sptr<SessionInfo> extensionSessionInfo = sptr<SessionInfo>::MakeSptr();
    extensionSessionInfo->want.SetParam(UIEXTENSION_TYPE_KEY, AUTO_FILL_PASSWORD_TPYE);
    abilityMs->SetAutoFillElementName(extensionSessionInfo);
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        EXPECT_EQ(extensionSessionInfo->want.GetBundle(), BUNDLE_NAME_TEST);
        EXPECT_EQ(extensionSessionInfo->want.GetModuleName(), AUTO_FILL_MODULE_NAME);
    } else {
        EXPECT_EQ(extensionSessionInfo->want.GetBundle(), AUTO_FILL_PASSWORD_BUNDLE_NAME);
        EXPECT_EQ(extensionSessionInfo->want.GetModuleName(), AUTO_FILL_MODULE_NAME);
    }

    extensionSessionInfo->want.SetParam(UIEXTENSION_TYPE_KEY, AUTO_FILL_SMART_TPYE);
    abilityMs->SetAutoFillElementName(extensionSessionInfo);
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        EXPECT_EQ(extensionSessionInfo->want.GetBundle(), BUNDLE_NAME_SMART_TEST);
        EXPECT_EQ(extensionSessionInfo->want.GetModuleName(), AUTO_FILL_MODULE_NAME);
    } else {
        EXPECT_EQ(extensionSessionInfo->want.GetBundle(), AUTO_FILL_PASSWORD_BUNDLE_NAME);
        EXPECT_EQ(extensionSessionInfo->want.GetModuleName(), AUTO_FILL_MODULE_NAME);
    }

    extensionSessionInfo->want = Want();
    EXPECT_EQ(extensionSessionInfo->want.GetBundle(), "");
    EXPECT_EQ(extensionSessionInfo->want.GetModuleName(), "");
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest SetAutoFillElementName_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: CheckUIExtensionUsage
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckUIExtensionUsage
 */
HWTEST_F(AbilityManagerServiceSixthTest, CheckUIExtensionUsage_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest CheckUIExtensionUsage_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    AppExecFwk::UIExtensionUsage uiExtensionUsage = UIExtensionUsage::MODAL;
    AppExecFwk::ExtensionAbilityType extensionType = ExtensionAbilityType::WINDOW;
    auto ret = abilityMs->CheckUIExtensionUsage(uiExtensionUsage, extensionType);
    EXPECT_EQ(ret, ERR_OK);

    MyFlag::flag_ = MyFlag::IS_SA_CALL;
    uiExtensionUsage = UIExtensionUsage::EMBEDDED;
    extensionType = AppExecFwk::ExtensionAbilityType::AUTO_FILL_PASSWORD;
    ret = abilityMs->CheckUIExtensionUsage(uiExtensionUsage, extensionType);
    EXPECT_EQ(ret, ERR_OK);

    extensionType = AppExecFwk::ExtensionAbilityType::SERVICE;
    ret = abilityMs->CheckUIExtensionUsage(uiExtensionUsage, extensionType);
    EXPECT_EQ(ret, ERR_OK);

    uiExtensionUsage = UIExtensionUsage::CONSTRAINED_EMBEDDED;
    extensionType = AppExecFwk::ExtensionAbilityType::SYSPICKER_PHOTOPICKER;
    ret = abilityMs->CheckUIExtensionUsage(uiExtensionUsage, extensionType);
    EXPECT_EQ(ret, ERR_OK);

    uiExtensionUsage = UIExtensionUsage::CONSTRAINED_EMBEDDED;
    extensionType = AppExecFwk::ExtensionAbilityType::WINDOW;
    ret = abilityMs->CheckUIExtensionUsage(uiExtensionUsage, extensionType);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest CheckUIExtensionUsage_001 end");
    MyFlag::flag_ = 0;
}

/*
 * Feature: AbilityManagerService
 * Function: CheckProcessOptions
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckProcessOptions
 */
HWTEST_F(AbilityManagerServiceSixthTest, CheckProcessOptions_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest CheckProcessOptions_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();

    Want want;
    StartOptions startOptions;
    auto ret = abilityMs->CheckProcessOptions(want, startOptions, -1);
    EXPECT_EQ(ret, ERR_OK);

    startOptions.processOptions = std::make_shared<ProcessOptions>();
    ret = abilityMs->CheckProcessOptions(want, startOptions, -1);
    EXPECT_EQ(ret, ERR_OK);

    startOptions.processOptions->processMode = ProcessMode::NEW_PROCESS_ATTACH_TO_PARENT;
    ret = abilityMs->CheckProcessOptions(want, startOptions, -1);
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        EXPECT_EQ(ret, ERR_CAPABILITY_NOT_SUPPORT);
    }
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest CheckProcessOptions_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: PreStartFreeInstall
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService PreStartFreeInstall
 */
HWTEST_F(AbilityManagerServiceSixthTest, PreStartFreeInstall_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest PreStartFreeInstall_001 start");
    Want want;
    Want localWant;
    uint32_t specifyTokenId { 0 };
    bool isStartAsCaller { false };
    auto callerToken = sptr<MockAbilityToken>::MakeSptr();
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    abilityMs_->freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    auto ret = abilityMs_->PreStartFreeInstall(want, callerToken, specifyTokenId, isStartAsCaller, localWant);
    EXPECT_EQ(ret, ERR_OK);

    specifyTokenId = 1;
    ret = abilityMs_->PreStartFreeInstall(want, callerToken, specifyTokenId, isStartAsCaller, localWant);
    EXPECT_EQ(ret, ERR_OK);

    localWant.SetDeviceId("testDevice");
    specifyTokenId = 1;
    callerToken = nullptr;
    ret = abilityMs_->PreStartFreeInstall(want, callerToken, specifyTokenId, isStartAsCaller, localWant);
    EXPECT_EQ(ret, ERR_OK);

    ret = abilityMs_->PreStartFreeInstall(want, callerToken, specifyTokenId, true, localWant);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest PreStartFreeInstall_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: CheckOptExtensionAbility
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckOptExtensionAbility
 */
HWTEST_F(AbilityManagerServiceSixthTest, CheckOptExtensionAbility_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest CheckOptExtensionAbility_001 start");
    Want want;
    AbilityRequest abilityRequest;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    AppExecFwk::ExtensionAbilityType extensionType = ExtensionAbilityType::FORM;
    int32_t validUserId = 0;
    bool isImplicit = false;
    bool isStartAsCaller = true;
    auto ret = abilityMs_->CheckOptExtensionAbility(want, abilityRequest, validUserId, extensionType,
        isImplicit, isStartAsCaller);
    EXPECT_EQ(ret, ERR_WRONG_INTERFACE_CALL);

    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    extensionType = AppExecFwk::ExtensionAbilityType::SERVICE;
    ret = abilityMs_->CheckOptExtensionAbility(want, abilityRequest, validUserId, extensionType,
        isImplicit, isStartAsCaller);
    EXPECT_EQ(ret, ERR_WRONG_INTERFACE_CALL);

    extensionType = AppExecFwk::ExtensionAbilityType::SERVICE;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SERVICE;
    abilityRequest.want.SetElementName(TEST_BUNDLE_NAME, CONTACTS_ABILITY_NAME);
    ret = abilityMs_->CheckOptExtensionAbility(want, abilityRequest, validUserId, extensionType,
        isImplicit, isStartAsCaller);
    EXPECT_EQ(ret, ERR_OK);

    extensionType = AppExecFwk::ExtensionAbilityType::DATASHARE;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::DATASHARE;
    ret = abilityMs_->CheckOptExtensionAbility(want, abilityRequest, validUserId, extensionType,
        isImplicit, isStartAsCaller);
    EXPECT_EQ(ret, ERR_OK);

    extensionType = AppExecFwk::ExtensionAbilityType::UI_SERVICE;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI_SERVICE;
    ret = abilityMs_->CheckOptExtensionAbility(want, abilityRequest, validUserId, extensionType,
        isImplicit, isStartAsCaller);
    EXPECT_EQ(ret, ERR_OK);

    isStartAsCaller = false;
    extensionType = ExtensionAbilityType::FORM;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::FORM;
    ret = abilityMs_->CheckOptExtensionAbility(want, abilityRequest, validUserId, extensionType,
        isImplicit, isStartAsCaller);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest CheckOptExtensionAbility_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: StartExtensionAbility
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService StartExtensionAbility
 */
HWTEST_F(AbilityManagerServiceSixthTest, StartExtensionAbility_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartExtensionAbility_001 start");
    auto abilityMs = MockAbilityManagerService();
    Want want;
    AppExecFwk::ExtensionAbilityType extensionType = AppExecFwk::ExtensionAbilityType::UI_SERVICE;
    auto ret = abilityMs->StartExtensionAbility(want, nullptr, -1, extensionType);
    EXPECT_EQ(ret, ERR_CAPABILITY_NOT_SUPPORT);

    extensionType = AppExecFwk::ExtensionAbilityType::VPN;
    ret = abilityMs->StartExtensionAbility(want, nullptr, -1, extensionType);
    EXPECT_EQ(ret, ERR_IMPLICIT_START_ABILITY_FAIL); // implicit start ability failed

    auto callerToken = sptr<MockAbilityToken>::MakeSptr(); // callerToken not null
    ret = abilityMs->StartExtensionAbility(want, callerToken, -1, extensionType);
    EXPECT_EQ(ret, ERR_INVALID_CALLER); // caller is not null,expect Invalid caller

    extensionType = AppExecFwk::ExtensionAbilityType::DATASHARE;
    ret = abilityMs->StartExtensionAbility(want, nullptr, -1, extensionType);
    EXPECT_EQ(ret, ERR_IMPLICIT_START_ABILITY_FAIL); // expect implicit start fail
}

/*
 * Feature: AbilityManagerService
 * Function: RecordProcessExitReason
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService RecordProcessExitReason
 */
HWTEST_F(AbilityManagerServiceSixthTest, RecordProcessExitReason_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest RecordProcessExitReason_001 start");
    auto abilityMs = MockAbilityManagerService();
    MyFlag::flag_ = 0;
    ExitReason exitReason;
    auto ret = abilityMs->RecordProcessExitReason(1, exitReason);
    EXPECT_EQ(ret, ERR_PERMISSION_DENIED);

    MyFlag::flag_ = MyFlag::IS_SA_CALL;
    ret = abilityMs->RecordProcessExitReason(1, exitReason);
    EXPECT_EQ(ret, ERR_NAME_NOT_FOUND); // init process not record

    MyFlag::flag_ = MyFlag::IS_SHELL_CALL;
    ret = abilityMs->RecordProcessExitReason(1, exitReason);
    EXPECT_EQ(ret, ERR_NAME_NOT_FOUND); // init process not record
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest RecordProcessExitReason_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: AnonymizeDeviceId
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService AnonymizeDeviceId
 */
HWTEST_F(AbilityManagerServiceSixthTest, AnonymizeDeviceId_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest AnonymizeDeviceId_001 start");
    auto abilityMs = MockAbilityManagerService();
    std::string deviceId;
    auto ret = abilityMs->AnonymizeDeviceId(deviceId);
    EXPECT_EQ(ret, EMPTY_DEVICE_ID);

    deviceId = std::string("1234567890");
    ret = abilityMs->AnonymizeDeviceId(deviceId);
    EXPECT_EQ(ret, "123456******");
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest AnonymizeDeviceId_001 start");
}

/*
 * Feature: AbilityManagerService
 * Function: MinimizeAbility
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService MinimizeAbility
 */
HWTEST_F(AbilityManagerServiceSixthTest, MinimizeAbility_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest MinimizeAbility_001 start");
    auto abilityMs = MockAbilityManagerService();
    bool fromUser = true;
    auto ret = abilityMs->MinimizeAbility(nullptr, fromUser);
    EXPECT_EQ(ret, ERR_INVALID_VALUE); // expect nullptr callerToken invalid
    Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo applicationInfo;
    auto abilityRecord = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    abilityRecord->Init();
    auto token = abilityRecord->token_;
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
        uiAbilityLifecycleManager->sessionAbilityMap_.emplace(0, abilityRecord);
        abilityMs->subManagersHelper_->uiAbilityManagers_.emplace(0, uiAbilityLifecycleManager);
    } else {
        auto missionListManager = std::make_shared<MissionListManager>(0);
        missionListManager->terminateAbilityList_.emplace_back(abilityRecord);
        abilityMs->subManagersHelper_->missionListManagers_.emplace(0, missionListManager);
        ret = abilityMs->MinimizeAbility(token, fromUser);
        EXPECT_EQ(ret, ERR_WRONG_INTERFACE_CALL); // expect ERR_WRONG_INTERFACE_CALL abilityRecord type not page

        abilityRecord->abilityInfo_.type = AppExecFwk::AbilityType::PAGE;
        ret = abilityMs->MinimizeAbility(token, fromUser);
        EXPECT_EQ(ret, ERR_INVALID_VALUE); // expect ERR_INVALID_VALUE
    }
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest MinimizeAbility_001 start");
}

/*
 * Feature: AbilityManagerService
 * Function: TerminateAbility
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService TerminateAbility
 */
HWTEST_F(AbilityManagerServiceSixthTest, TerminateAbility_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest TerminateAbility_001 start");
    auto abilityMs = MockAbilityManagerService();
    Want resultWant;
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        resultWant.SetElementName(BUNDLE_NAME_SCENEBOARD, SCENEBOARD_ABILITY_NAME);
    } else {
        resultWant.SetElementName(BUNDLE_NAME_LAUNCHER, LAUNCHER_ABILITY_NAME);
    }

    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo applicationInfo;
    auto abilityRecord = std::make_shared<AbilityRecord>(resultWant, abilityInfo, applicationInfo);
    abilityRecord->Init();
    auto token = abilityRecord->token_;
    int resultCode = 0;
    auto ret = abilityMs->TerminateAbility(nullptr, resultCode, &resultWant);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    ret = abilityMs->TerminateAbility(token, resultCode, &resultWant);
    EXPECT_EQ(ret, ERR_OK);

    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        resultWant.SetElementName(BUNDLE_NAME_SCENEBOARD, "");
    } else {
        resultWant.SetElementName(BUNDLE_NAME_LAUNCHER, "");
    }
    ret = abilityMs->TerminateAbility(token, resultCode, &resultWant);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest TerminateAbility_001 start");
}

/*
 * Feature: AbilityManagerService
 * Function: MinimizeUIAbilityBySCB
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService MinimizeUIAbilityBySCB
 */
HWTEST_F(AbilityManagerServiceSixthTest, MinimizeUIAbilityBySCB_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest MinimizeUIAbilityBySCB_001 start");
    auto abilityMs = MockAbilityManagerService();
    auto ret = abilityMs->MinimizeUIAbilityBySCB(nullptr, false, 0);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    auto sessionInfo = sptr<SessionInfo>::MakeSptr();
    ret = abilityMs->MinimizeUIAbilityBySCB(sessionInfo, false, 0);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo applicationInfo;
    Want resultWant;
    auto abilityRecord = std::make_shared<AbilityRecord>(resultWant, abilityInfo, applicationInfo);
    abilityRecord->Init();
    sessionInfo->sessionToken = abilityRecord->token_;
    ret = abilityMs->MinimizeUIAbilityBySCB(sessionInfo, false, 0);
    if (!abilityMs->IsCallerSceneBoard()) {
        EXPECT_EQ(ret, ERR_WRONG_INTERFACE_CALL);
    } else {
        EXPECT_EQ(ret, ERR_INVALID_VALUE);
    }
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest MinimizeUIAbilityBySCB_001 start");
}

/*
 * Feature: AbilityManagerService
 * Function: DumpState
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpState
 */
HWTEST_F(AbilityManagerServiceSixthTest, DumpState_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest DumpState_001 start");
    auto abilityMs = MockAbilityManagerService();
    std::string args;
    std::vector<std::string> info;
    MyFlag::flag_ = 0;
    abilityMs->DumpState(args, info);
    EXPECT_TRUE(info.empty()); // permission deny

    MyFlag::flag_ = MyFlag::IS_SHELL_CALL;
    args = std::string("");
    abilityMs->DumpState(args, info);
    EXPECT_TRUE(info.empty()); // null string
    args = std::string("-e");
    abilityMs->DumpState(args, info); // KEY_DUMP_SERVICE
    EXPECT_TRUE(info.empty());
    args = std::string("-d");
    abilityMs->DumpState(args, info); // KEY_DUMP_DATA
    args = std::string("-a"); // KEY_DUMP_ALL
    abilityMs->DumpState(args, info);
    args = std::string("-m"); // KEY_DUMP_MISSION
    abilityMs->DumpState(args, info);
    EXPECT_FALSE(info.empty());
    args = std::string("-m 999999999"); // KEY_DUMP_MISSION 999999999 means missionID
    abilityMs->DumpState(args, info);
    args = std::string("-L"); // KEY_DUMP_MISSION_LIST
    abilityMs->DumpState(args, info);
    args = std::string("-S");
    abilityMs->DumpState(args, info);
    info.clear();
    args = std::string("-NAN"); // not exsist
    abilityMs->DumpState(args, info);
    EXPECT_TRUE(info.empty());
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest DumpState_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: DumpSysState
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DumpSysState
 */
HWTEST_F(AbilityManagerServiceSixthTest, DumpSysState_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest DumpSysState_001 start");
    auto abilityMs = MockAbilityManagerService();
    std::string args;
    std::vector<std::string> info;
    MyFlag::flag_ = 0;
    abilityMs->DumpSysState(args, info, false, true, 0);
    EXPECT_TRUE(info.empty()); // permission deny
    MyFlag::flag_ = MyFlag::IS_SHELL_CALL;
    args = std::string("");
    abilityMs->DumpState(args, info);
    EXPECT_TRUE(info.empty()); // null string
    args = std::string("-a");
    abilityMs->DumpSysState(args, info, false, true, 0); // KEY_DUMP_SYS_ALL
    EXPECT_FALSE(info.empty());
    info.clear();
    args = std::string("-p");
    abilityMs->DumpSysState(args, info, false, true, 0); // KEY_DUMP_SYS_PENDING
    args = std::string("-r");
    abilityMs->DumpSysState(args, info, false, true, INT_MAX); // KEY_DUMP_SYS_PROCESS
    info.clear();
    args = std::string("-d"); // KEY_DUMP_SYS_DATA
    abilityMs->DumpSysState(args, info, false, true, INT_MAX); // int_max MEANS userid
    args = std::string("--mission-list"); // KEY_DUMP_SYS_MISSION_LIST
    abilityMs->DumpSysState(args, info, false, true, 0);
    args = std::string("-i"); // KEY_DUMP_MISSION 999999999 means missionID
    abilityMs->DumpSysState(args, info, false, true, 0);
    info.clear();
    args = std::string("-NAN"); // not exsist
    abilityMs->DumpSysState(args, info, false, true, 0);
    EXPECT_TRUE(info.empty());
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest DumpSysState_001 end");
}
/*
 * Feature: AbilityManagerService
 * Function: TerminateMission
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService TerminateMission
 */
HWTEST_F(AbilityManagerServiceSixthTest, TerminateMission_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest TerminateMission_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    ASSERT_NE(abilityMs, nullptr);
    int32_t missionId = -1;
    EXPECT_EQ(abilityMs->TerminateMission(missionId), 1);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest TerminateMission_001 end");
}
}  // namespace AAFwk
}  // namespace OHOS
