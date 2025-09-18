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

#include "ability_manager_errors.h"
#include "access_token.h"
#include "bundle_mgr_helper.h"
#include "hilog_tag_wrapper.h"
#define private public
#define protected public
#include "interceptor/ability_jump_interceptor.h"
#undef private
#undef protected
#include "mock_my_flag.h"
#include "mock_app_control_manager.h"
#include "start_ability_utils.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
namespace {
const std::string JUMP_DIALOG_CALLER_BUNDLE_NAME = "interceptor_callerBundleName";
const std::string JUMP_DIALOG_CALLER_MODULE_NAME = "interceptor_callerModuleName";
const std::string JUMP_DIALOG_CALLER_LABEL_ID = "interceptor_callerLabelId";
const std::string JUMP_DIALOG_TARGET_MODULE_NAME = "interceptor_targetModuleName";
const std::string JUMP_DIALOG_TARGET_LABEL_ID = "interceptor_targetLabelId";
}

class AbilityJumpInterceptorTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: AbilityJumpInterceptorTest_LoadAppLabelInfo_001
 * @tc.desc: LoadAppLabelInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, LoadAppLabelInfo_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "LoadAppLabelInfo_001 start");
    MyFlag::retCallerGetApplicationInfo_ = true;
    MyFlag::retCallerApplicationInfo_.labelResource.moduleName = "module1";
    MyFlag::retCallerApplicationInfo_.labelId = 123456789;
    MyFlag::retTargetGetApplicationInfo_ = true;
    MyFlag::retTargetApplicationInfo_.labelResource.moduleName = "module2";
    MyFlag::retTargetApplicationInfo_.labelId = 987654321;

    AbilityJumpInterceptor interceptor;
    Want want;
    AppExecFwk::AppJumpControlRule rule;
    rule.callerPkg = "caller";
    rule.targetPkg = "target";
    int32_t userId = 101;
    auto ret = interceptor.LoadAppLabelInfo(want, rule, userId);
    EXPECT_TRUE(ret);
    EXPECT_EQ(want.GetStringParam(JUMP_DIALOG_CALLER_BUNDLE_NAME), "caller");
    EXPECT_EQ(want.GetStringParam(JUMP_DIALOG_CALLER_MODULE_NAME), "module1");
    EXPECT_EQ(want.GetStringParam(JUMP_DIALOG_TARGET_MODULE_NAME), "module2");
    EXPECT_EQ(want.GetLongParam(JUMP_DIALOG_CALLER_LABEL_ID, 0), 123456789);
    EXPECT_EQ(want.GetLongParam(JUMP_DIALOG_TARGET_LABEL_ID, 0), 987654321);
    TAG_LOGI(AAFwkTag::TEST, "LoadAppLabelInfo_001 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_LoadAppLabelInfo_002
 * @tc.desc: LoadAppLabelInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, LoadAppLabelInfo_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "LoadAppLabelInfo_002 start");
    MyFlag::retCallerGetApplicationInfo_ = false;

    AbilityJumpInterceptor interceptor;
    Want want;
    AppExecFwk::AppJumpControlRule rule;
    int32_t userId = 101;
    auto ret = interceptor.LoadAppLabelInfo(want, rule, userId);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "LoadAppLabelInfo_002 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_LoadAppLabelInfo_003
 * @tc.desc: LoadAppLabelInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, LoadAppLabelInfo_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "LoadAppLabelInfo_003 start");
    MyFlag::retCallerGetApplicationInfo_ = true;
    MyFlag::retTargetGetApplicationInfo_ = false;

    AbilityJumpInterceptor interceptor;
    Want want;
    AppExecFwk::AppJumpControlRule rule;
    int32_t userId = 101;
    auto ret = interceptor.LoadAppLabelInfo(want, rule, userId);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "LoadAppLabelInfo_003 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckIfExemptByBundleName_001
 * @tc.desc: CheckIfExemptByBundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckIfExemptByBundleName_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckIfExemptByBundleName_001 start");
    MyFlag::retTargetGetApplicationInfo_ = false;

    AbilityJumpInterceptor interceptor;
    std::string bundleName = "bundle";
    std::string permission = "permission";
    int32_t userId = 101;
    auto ret = interceptor.CheckIfExemptByBundleName(bundleName, permission, userId);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckIfExemptByBundleName_001 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckIfExemptByBundleName_002
 * @tc.desc: CheckIfExemptByBundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckIfExemptByBundleName_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckIfExemptByBundleName_002 start");
    MyFlag::retTargetGetApplicationInfo_ = true;
    MyFlag::retTargetApplicationInfo_.isSystemApp = true;

    AbilityJumpInterceptor interceptor;
    std::string bundleName = "bundle";
    std::string permission = "permission";
    int32_t userId = 101;
    auto ret = interceptor.CheckIfExemptByBundleName(bundleName, permission, userId);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckIfExemptByBundleName_002 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckIfExemptByBundleName_003
 * @tc.desc: CheckIfExemptByBundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckIfExemptByBundleName_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckIfExemptByBundleName_003 start");
    MyFlag::retTargetGetApplicationInfo_ = true;
    MyFlag::retTargetApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_DENIED;

    AbilityJumpInterceptor interceptor;
    std::string bundleName = "bundle";
    std::string permission = "permission";
    int32_t userId = 101;
    auto ret = interceptor.CheckIfExemptByBundleName(bundleName, permission, userId);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckIfExemptByBundleName_003 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckIfExemptByBundleName_004
 * @tc.desc: CheckIfExemptByBundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckIfExemptByBundleName_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckIfExemptByBundleName_004 start");
    MyFlag::retTargetGetApplicationInfo_ = true;
    MyFlag::retTargetApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_GRANTED;

    AbilityJumpInterceptor interceptor;
    std::string bundleName = "bundle";
    std::string permission = "permission";
    int32_t userId = 101;
    auto ret = interceptor.CheckIfExemptByBundleName(bundleName, permission, userId);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckIfExemptByBundleName_004 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckIfJumpExempt_001
 * @tc.desc: CheckIfJumpExempt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckIfJumpExempt_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckIfJumpExempt_001 start");
    MyFlag::retCallerGetApplicationInfo_ = false;
    MyFlag::retTargetGetApplicationInfo_ = false;

    AbilityJumpInterceptor interceptor;
    AppExecFwk::AppJumpControlRule controlRule;
    controlRule.callerPkg = "caller";
    controlRule.targetPkg = "target";
    int32_t userId = 101;
    auto ret = interceptor.CheckIfJumpExempt(controlRule, userId);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckIfJumpExempt_001 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckIfJumpExempt_002
 * @tc.desc: CheckIfJumpExempt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckIfJumpExempt_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckIfJumpExempt_002 start");
    MyFlag::retCallerGetApplicationInfo_ = true;
    MyFlag::retCallerApplicationInfo_.isSystemApp = false;
    MyFlag::retTargetGetApplicationInfo_ = true;
    MyFlag::retTargetApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_DENIED;

    AbilityJumpInterceptor interceptor;
    AppExecFwk::AppJumpControlRule controlRule;
    controlRule.callerPkg = "caller";
    controlRule.targetPkg = "target";
    int32_t userId = 101;
    auto ret = interceptor.CheckIfJumpExempt(controlRule, userId);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckIfJumpExempt_002 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckIfJumpExempt_003
 * @tc.desc: CheckIfJumpExempt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckIfJumpExempt_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckIfJumpExempt_003 start");
    MyFlag::retCallerGetApplicationInfo_ = true;
    MyFlag::retCallerApplicationInfo_.isSystemApp = true;

    AbilityJumpInterceptor interceptor;
    AppExecFwk::AppJumpControlRule controlRule;
    controlRule.callerPkg = "caller";
    controlRule.targetPkg = "target";
    int32_t userId = 101;
    auto ret = interceptor.CheckIfJumpExempt(controlRule, userId);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckIfJumpExempt_003 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckIfJumpExempt_004
 * @tc.desc: CheckIfJumpExempt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckIfJumpExempt_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckIfJumpExempt_004 start");
    MyFlag::retCallerGetApplicationInfo_ = true;
    MyFlag::retCallerApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_DENIED;
    MyFlag::retTargetGetApplicationInfo_ = true;
    MyFlag::retTargetApplicationInfo_.isSystemApp = true;

    AbilityJumpInterceptor interceptor;
    AppExecFwk::AppJumpControlRule controlRule;
    controlRule.callerPkg = "caller";
    controlRule.targetPkg = "target";
    int32_t userId = 101;
    auto ret = interceptor.CheckIfJumpExempt(controlRule, userId);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckIfJumpExempt_004 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckIfJumpExempt_005
 * @tc.desc: CheckIfJumpExempt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckIfJumpExempt_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckIfJumpExempt_005 start");
    MyFlag::retCallerGetApplicationInfo_ = true;
    MyFlag::retCallerApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_GRANTED;

    AbilityJumpInterceptor interceptor;
    AppExecFwk::AppJumpControlRule controlRule;
    controlRule.callerPkg = "caller";
    controlRule.targetPkg = "target";
    int32_t userId = 101;
    auto ret = interceptor.CheckIfJumpExempt(controlRule, userId);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckIfJumpExempt_005 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckIfJumpExempt_006
 * @tc.desc: CheckIfJumpExempt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckIfJumpExempt_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckIfJumpExempt_006 start");
    MyFlag::retCallerGetApplicationInfo_ = false;
    MyFlag::retTargetGetApplicationInfo_ = true;
    MyFlag::retTargetApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_GRANTED;

    AbilityJumpInterceptor interceptor;
    AppExecFwk::AppJumpControlRule controlRule;
    controlRule.callerPkg = "caller";
    controlRule.targetPkg = "target";
    int32_t userId = 101;
    auto ret = interceptor.CheckIfJumpExempt(controlRule, userId);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckIfJumpExempt_006 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckControl_001
 * @tc.desc: CheckControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckControl_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_001 start");
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "caller";
    MyFlag::retCallerGetApplicationInfo_ = false;
    MyFlag::retTargetGetApplicationInfo_ = true;
    MyFlag::retTargetApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_DENIED;

    auto appControlMgr = new (std::nothrow) AppControlProxy(nullptr);
    MyFlag::mockAppControlManager_ = appControlMgr;
    MyFlag::retGetAppJumpControlRule_ = ERR_OK;
    MyFlag::mockControlRule_.jumpMode = AppExecFwk::AbilityJumpMode::INTERCEPT;

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "", "");
    int32_t userId = 1001;
    bool isWithUI = false;
    AppExecFwk::AppJumpControlRule controlRule;
    auto ret = interceptor.CheckControl(bundleMgrHelper, want, userId, controlRule);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_001 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckControl_002
 * @tc.desc: CheckControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckControl_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_002 start");
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    MyFlag::retGetNameForUid_ = -1;

    AbilityJumpInterceptor interceptor;
    Want want;
    int32_t userId = 1001;
    bool isWithUI = false;
    AppExecFwk::AppJumpControlRule controlRule;
    auto ret = interceptor.CheckControl(bundleMgrHelper, want, userId, controlRule);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_002 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckControl_003
 * @tc.desc: CheckControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckControl_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_003 start");
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "";

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "", "");
    int32_t userId = 1001;
    bool isWithUI = false;
    AppExecFwk::AppJumpControlRule controlRule;
    auto ret = interceptor.CheckControl(bundleMgrHelper, want, userId, controlRule);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_003 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckControl_004
 * @tc.desc: CheckControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckControl_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_004 start");
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "caller";

    AbilityJumpInterceptor interceptor;
    Want want;
    int32_t userId = 1001;
    bool isWithUI = false;
    AppExecFwk::AppJumpControlRule controlRule;
    auto ret = interceptor.CheckControl(bundleMgrHelper, want, userId, controlRule);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_004 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckControl_005
 * @tc.desc: CheckControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckControl_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_005 start");
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "target";

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "", "");
    int32_t userId = 1001;
    bool isWithUI = false;
    AppExecFwk::AppJumpControlRule controlRule;
    auto ret = interceptor.CheckControl(bundleMgrHelper, want, userId, controlRule);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_005 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckControl_006
 * @tc.desc: CheckControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckControl_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_006 start");
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "caller";
    MyFlag::retCallerGetApplicationInfo_ = false;
    MyFlag::retTargetGetApplicationInfo_ = true;
    MyFlag::retTargetApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_GRANTED;

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "", "");
    int32_t userId = 1001;
    bool isWithUI = false;
    AppExecFwk::AppJumpControlRule controlRule;
    auto ret = interceptor.CheckControl(bundleMgrHelper, want, userId, controlRule);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_006 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckControl_007
 * @tc.desc: CheckControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckControl_007, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_007 start");
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "caller";
    MyFlag::retCallerGetApplicationInfo_ = false;
    MyFlag::retTargetGetApplicationInfo_ = true;
    MyFlag::retTargetApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_DENIED;
    MyFlag::mockAppControlManager_ = nullptr;

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "", "");
    int32_t userId = 1001;
    bool isWithUI = false;
    AppExecFwk::AppJumpControlRule controlRule;
    auto ret = interceptor.CheckControl(bundleMgrHelper, want, userId, controlRule);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_007 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckControl_008
 * @tc.desc: CheckControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckControl_008, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_008 start");
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "caller";
    MyFlag::retCallerGetApplicationInfo_ = false;
    MyFlag::retTargetGetApplicationInfo_ = true;
    MyFlag::retTargetApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_DENIED;

    auto appControlMgr = new (std::nothrow) AppControlProxy(nullptr);
    MyFlag::mockAppControlManager_ = appControlMgr;
    MyFlag::retGetAppJumpControlRule_ = -1;

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "", "");
    int32_t userId = 1001;
    bool isWithUI = false;
    AppExecFwk::AppJumpControlRule controlRule;
    auto ret = interceptor.CheckControl(bundleMgrHelper, want, userId, controlRule);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_008 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckControl_009
 * @tc.desc: CheckControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckControl_009, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_009 start");
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "caller";
    MyFlag::retCallerGetApplicationInfo_ = false;
    MyFlag::retTargetGetApplicationInfo_ = true;
    MyFlag::retTargetApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_DENIED;

    auto appControlMgr = new (std::nothrow) AppControlProxy(nullptr);
    MyFlag::mockAppControlManager_ = appControlMgr;
    MyFlag::retGetAppJumpControlRule_ = ERR_OK;
    MyFlag::mockControlRule_.jumpMode = AppExecFwk::AbilityJumpMode::DIRECT;

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "", "");
    int32_t userId = 1001;
    bool isWithUI = false;
    AppExecFwk::AppJumpControlRule controlRule;
    auto ret = interceptor.CheckControl(bundleMgrHelper, want, userId, controlRule);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_009 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckControl_010
 * @tc.desc: CheckControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckControl_010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_010 start");
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "caller";
    MyFlag::retCallerGetApplicationInfo_ = true;
    MyFlag::retCallerApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_DENIED;

    auto appControlMgr = new (std::nothrow) AppControlProxy(nullptr);
    MyFlag::mockAppControlManager_ = appControlMgr;
    MyFlag::retGetAppJumpControlRule_ = ERR_OK;
    MyFlag::mockControlRule_.jumpMode = AppExecFwk::AbilityJumpMode::INTERCEPT;

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "", "");
    int32_t userId = 1001;
    bool isWithUI = false;
    AppExecFwk::AppJumpControlRule controlRule;
    auto ret = interceptor.CheckControl(bundleMgrHelper, want, userId, controlRule);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_010 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckControl_011
 * @tc.desc: CheckControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckControl_011, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_011 start");
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "caller";
    MyFlag::retCallerGetApplicationInfo_ = true;
    MyFlag::retCallerApplicationInfo_.isSystemApp = true;
    auto appControlMgr = nullptr;

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "", "");
    int32_t userId = 1001;
    bool isWithUI = false;
    AppExecFwk::AppJumpControlRule controlRule;
    auto ret = interceptor.CheckControl(bundleMgrHelper, want, userId, controlRule);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_011 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckControl_012
 * @tc.desc: CheckControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckControl_012, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_012 start");
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "caller";
    MyFlag::retCallerGetApplicationInfo_ = true;
    MyFlag::retCallerApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_DENIED;

    auto appControlMgr = new (std::nothrow) AppControlProxy(nullptr);
    MyFlag::mockAppControlManager_ = appControlMgr;
    MyFlag::retGetAppJumpControlRule_ = -1;

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "", "");
    int32_t userId = 1001;
    bool isWithUI = false;
    AppExecFwk::AppJumpControlRule controlRule;
    auto ret = interceptor.CheckControl(bundleMgrHelper, want, userId, controlRule);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_012 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_CheckControl_013
 * @tc.desc: CheckControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, CheckControl_013, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_013 start");
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "caller";
    MyFlag::retCallerGetApplicationInfo_ = true;
    MyFlag::retCallerApplicationInfo_.isSystemApp = true;

    auto appControlMgr = new (std::nothrow) AppControlProxy(nullptr);
    MyFlag::mockAppControlManager_ = appControlMgr;
    MyFlag::retGetAppJumpControlRule_ = ERR_OK;
    MyFlag::mockControlRule_.jumpMode = AppExecFwk::AbilityJumpMode::DIRECT;

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "", "");
    int32_t userId = 1001;
    bool isWithUI = false;
    AppExecFwk::AppJumpControlRule controlRule;
    auto ret = interceptor.CheckControl(bundleMgrHelper, want, userId, controlRule);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "CheckControl_013 end");
}

#ifdef SUPPORT_GRAPHICS
/**
 * @tc.name: AbilityJumpInterceptorTest_DoProcess_001
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, DoProcess_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_001 start");
    AbilityJumpInterceptor interceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = false;
    sptr<IRemoteObject> callerToken = nullptr;
    std::function<bool(void)> shouldAbilityJumpFunc = nullptr;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldAbilityJumpFunc);
    auto ret = interceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_001 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_DoProcess_002
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, DoProcess_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_002 start");
    MyFlag::isStartIncludeAtomicService_ = true;

    AbilityJumpInterceptor interceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken = nullptr;
    std::function<bool(void)> shouldAbilityJumpFunc = nullptr;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldAbilityJumpFunc);
    auto ret = interceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_002 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_DoProcess_003
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, DoProcess_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_003 start");
    MyFlag::isStartIncludeAtomicService_ = false;
    MyFlag::bundleMgrHelper_ = nullptr;

    AbilityJumpInterceptor interceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken = nullptr;
    std::function<bool(void)> shouldAbilityJumpFunc = nullptr;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldAbilityJumpFunc);
    auto ret = interceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_003 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_DoProcess_004
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, DoProcess_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_004 start");
    MyFlag::isStartIncludeAtomicService_ = false;
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    StartAbilityUtils::startAbilityInfo = std::make_shared<StartAbilityInfo>();
    StartAbilityUtils::startAbilityInfo->abilityInfo.bundleName = "target";
    StartAbilityUtils::startAbilityInfo->abilityInfo.name = "MainAbility";
    StartAbilityUtils::startAbilityInfo->abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "MainAbility", "");
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken = nullptr;
    std::function<bool(void)> shouldAbilityJumpFunc = nullptr;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldAbilityJumpFunc);
    auto ret = interceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_004 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_DoProcess_005
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, DoProcess_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_005 start");
    MyFlag::isStartIncludeAtomicService_ = false;
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    StartAbilityUtils::startAbilityInfo = nullptr;
    MyFlag::retAbilityInfo_.type = AppExecFwk::AbilityType::EXTENSION;

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "MainAbility", "");
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken = nullptr;
    std::function<bool(void)> shouldAbilityJumpFunc = nullptr;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldAbilityJumpFunc);
    auto ret = interceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_005 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_DoProcess_006
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, DoProcess_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_006 start");
    MyFlag::isStartIncludeAtomicService_ = false;
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    StartAbilityUtils::startAbilityInfo = std::make_shared<StartAbilityInfo>();
    StartAbilityUtils::startAbilityInfo->abilityInfo.bundleName = "target";
    StartAbilityUtils::startAbilityInfo->abilityInfo.name = "MainAbility";
    StartAbilityUtils::startAbilityInfo->abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "caller";
    MyFlag::retCallerGetApplicationInfo_ = true;
    MyFlag::retCallerApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_DENIED;
    auto appControlMgr = new (std::nothrow) AppControlProxy(nullptr);
    MyFlag::mockAppControlManager_ = appControlMgr;
    MyFlag::retGetAppJumpControlRule_ = ERR_OK;
    MyFlag::mockControlRule_.jumpMode = AppExecFwk::AbilityJumpMode::INTERCEPT;
    MyFlag::startAbilityRet_ = -1;

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "MainAbility", "");
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken = nullptr;
    std::function<bool(void)> shouldAbilityJumpFunc = nullptr;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldAbilityJumpFunc);
    auto ret = interceptor.DoProcess(param);
    EXPECT_EQ(ret, -1);
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_006 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_DoProcess_007
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, DoProcess_007, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_007 start");
    MyFlag::isStartIncludeAtomicService_ = false;
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    StartAbilityUtils::startAbilityInfo = std::make_shared<StartAbilityInfo>();
    StartAbilityUtils::startAbilityInfo->abilityInfo.bundleName = "target";
    StartAbilityUtils::startAbilityInfo->abilityInfo.name = "MainAbility";
    StartAbilityUtils::startAbilityInfo->abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "caller";
    MyFlag::retCallerGetApplicationInfo_ = true;
    MyFlag::retCallerApplicationInfo_.isSystemApp = false;
    MyFlag::retVerifyAccessTokenId_ = Security::AccessToken::PermissionState::PERMISSION_DENIED;
    auto appControlMgr = new (std::nothrow) AppControlProxy(nullptr);
    MyFlag::mockAppControlManager_ = appControlMgr;
    MyFlag::retGetAppJumpControlRule_ = ERR_OK;
    MyFlag::mockControlRule_.jumpMode = AppExecFwk::AbilityJumpMode::INTERCEPT;
    MyFlag::startAbilityRet_ = ERR_OK;

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "MainAbility", "");
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken = nullptr;
    std::function<bool(void)> shouldAbilityJumpFunc = nullptr;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldAbilityJumpFunc);
    auto ret = interceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_APP_JUMP_INTERCEPTOR_STATUS);
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_007 end");
}

/**
 * @tc.name: AbilityJumpInterceptorTest_DoProcess_008
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityJumpInterceptorTest, DoProcess_008, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_008 start");
    MyFlag::isStartIncludeAtomicService_ = false;
    auto bundleMgrHelper = AppExecFwk::BundleMgrHelper::GetInstance();
    MyFlag::bundleMgrHelper_ = bundleMgrHelper;
    StartAbilityUtils::startAbilityInfo = std::make_shared<StartAbilityInfo>();
    StartAbilityUtils::startAbilityInfo->abilityInfo.bundleName = "target";
    StartAbilityUtils::startAbilityInfo->abilityInfo.name = "MainAbility";
    StartAbilityUtils::startAbilityInfo->abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    MyFlag::retGetNameForUid_ = ERR_OK;
    MyFlag::callerBundleName_ = "";

    AbilityJumpInterceptor interceptor;
    Want want;
    want.SetElementName("", "target", "MainAbility", "");
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken = nullptr;
    std::function<bool(void)> shouldAbilityJumpFunc = nullptr;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldAbilityJumpFunc);
    auto ret = interceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "DoProcess_008 end");
}
#endif
} // namespace AAFwk
} // namespace OHOS
