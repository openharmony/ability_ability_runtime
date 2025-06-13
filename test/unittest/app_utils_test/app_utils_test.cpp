/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "app_utils.h"
#undef private
#include "hilog_tag_wrapper.h"
#include "parameters.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class AppUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AppUtilsTest::SetUpTestCase(void)
{}

void AppUtilsTest::TearDownTestCase(void)
{}

void AppUtilsTest::SetUp()
{}

void AppUtilsTest::TearDown()
{}

/**
 * @tc.number: AppUtilsTest_0100
 * @tc.desc: Test IsInheritWindowSplitScreenMode works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_0100 called.");
    bool isInheritWindowSplitScreenMode = AAFwk::AppUtils::GetInstance().IsInheritWindowSplitScreenMode();
    std::string deviceType = OHOS::system::GetDeviceType();
    TAG_LOGI(AAFwkTag::TEST, "current deviceType is %{public}s", deviceType.c_str());
    if (deviceType == "default") {
        EXPECT_TRUE(isInheritWindowSplitScreenMode == true);
    } else if (deviceType == "phone") {
        EXPECT_TRUE(isInheritWindowSplitScreenMode == true);
    } else if (deviceType == "2in1") {
        EXPECT_TRUE(isInheritWindowSplitScreenMode == false);
    }
}

/**
 * @tc.number: AppUtilsTest_0200
 * @tc.desc: Test IsSupportAncoApp works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_0200, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_0200 called.");
    bool isSupportAncoApp = AAFwk::AppUtils::GetInstance().IsSupportAncoApp();
    std::string deviceType = OHOS::system::GetDeviceType();
    TAG_LOGI(AAFwkTag::TEST, "current deviceType is %{public}s", deviceType.c_str());
    if (deviceType == "default") {
        EXPECT_TRUE(isSupportAncoApp == false);
    } else if (deviceType == "phone") {
        EXPECT_TRUE(isSupportAncoApp == true);
    } else if (deviceType == "2in1") {
        EXPECT_TRUE(isSupportAncoApp == false);
    }
}

/**
 * @tc.number: AppUtilsTest_0300
 * @tc.desc: Test GetTimeoutUnitTimeRatio works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_0300, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_0300 called.");
    int32_t timeoutUnitTimeRatio = AAFwk::AppUtils::GetInstance().GetTimeoutUnitTimeRatio();
    std::string deviceType = OHOS::system::GetDeviceType();
    TAG_LOGI(AAFwkTag::TEST, "current deviceType is %{public}s", deviceType.c_str());
    if (deviceType == "default") {
        EXPECT_TRUE(timeoutUnitTimeRatio == 1);
    } else if (deviceType == "phone") {
        EXPECT_TRUE(timeoutUnitTimeRatio == 1);
    } else if (deviceType == "2in1") {
        EXPECT_TRUE(timeoutUnitTimeRatio == 10);
    }
}

/**
 * @tc.number: AppUtilsTest_0400
 * @tc.desc: Test IsSelectorDialogDefaultPossion works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_0400, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_0400 called.");
    bool isSelectorDialogDefaultPossion = AAFwk::AppUtils::GetInstance().IsSelectorDialogDefaultPossion();
    std::string deviceType = OHOS::system::GetDeviceType();
    TAG_LOGI(AAFwkTag::TEST, "current deviceType is %{public}s", deviceType.c_str());
    if (deviceType == "default") {
        EXPECT_TRUE(isSelectorDialogDefaultPossion == true);
    } else if (deviceType == "phone") {
        EXPECT_TRUE(isSelectorDialogDefaultPossion == true);
    } else if (deviceType == "2in1") {
        EXPECT_TRUE(isSelectorDialogDefaultPossion == false);
    }
}

/**
 * @tc.number: AppUtilsTest_0500
 * @tc.desc: Test IsStartSpecifiedProcess works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_0500, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_0500 called.");
    bool isStartSpecifiedProcess = AAFwk::AppUtils::GetInstance().IsStartSpecifiedProcess();
    std::string deviceType = OHOS::system::GetDeviceType();
    TAG_LOGI(AAFwkTag::TEST, "current deviceType is %{public}s", deviceType.c_str());
    if (deviceType == "default") {
        EXPECT_TRUE(isStartSpecifiedProcess == false);
    } else if (deviceType == "phone") {
        EXPECT_TRUE(isStartSpecifiedProcess == false);
    } else if (deviceType == "2in1") {
        EXPECT_TRUE(isStartSpecifiedProcess == true);
    }
}

/**
 * @tc.number: AppUtilsTest_0600
 * @tc.desc: Test IsUseMultiRenderProcess works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_0600, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_0600 called.");
    bool isUseMultiRenderProcess = AAFwk::AppUtils::GetInstance().IsUseMultiRenderProcess();
    std::string deviceType = OHOS::system::GetDeviceType();
    TAG_LOGI(AAFwkTag::TEST, "current deviceType is %{public}s", deviceType.c_str());
    if (deviceType == "default") {
        EXPECT_TRUE(isUseMultiRenderProcess == true);
    } else if (deviceType == "phone") {
        EXPECT_TRUE(isUseMultiRenderProcess == true);
    } else if (deviceType == "2in1") {
        EXPECT_TRUE(isUseMultiRenderProcess == true);
    }
}

/**
 * @tc.number: AppUtilsTest_0700
 * @tc.desc: Test IsLimitMaximumOfRenderProcess works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_0700, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_0700 called.");
    bool isLimitMaximumOfRenderProcess = AAFwk::AppUtils::GetInstance().IsLimitMaximumOfRenderProcess();
    std::string deviceType = OHOS::system::GetDeviceType();
    TAG_LOGI(AAFwkTag::TEST, "current deviceType is %{public}s", deviceType.c_str());
    if (deviceType == "default") {
        EXPECT_TRUE(isLimitMaximumOfRenderProcess == true);
    } else if (deviceType == "phone") {
        EXPECT_TRUE(isLimitMaximumOfRenderProcess == true);
    } else if (deviceType == "2in1") {
        EXPECT_TRUE(isLimitMaximumOfRenderProcess == false);
    }
}

/**
 * @tc.number: AppUtilsTest_0800
 * @tc.desc: Test IsGrantPersistUriPermission works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_0800, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_0800 called.");
    bool isGrantPersistUriPermission = AAFwk::AppUtils::GetInstance().IsGrantPersistUriPermission();
    std::string deviceType = OHOS::system::GetDeviceType();
    TAG_LOGI(AAFwkTag::TEST, "current deviceType is %{public}s", deviceType.c_str());
    if (deviceType == "default") {
        EXPECT_TRUE(isGrantPersistUriPermission == false);
    } else if (deviceType == "phone") {
        EXPECT_TRUE(isGrantPersistUriPermission == false);
    } else if (deviceType == "2in1") {
        EXPECT_TRUE(isGrantPersistUriPermission == true);
    }
}

/**
 * @tc.number: AppUtilsTest_0900
 * @tc.desc: Test IsStartOptionsWithAnimation works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_0900, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_0900 called.");
    bool isStartOptionsWithAnimation = AAFwk::AppUtils::GetInstance().IsStartOptionsWithAnimation();
    std::string deviceType = OHOS::system::GetDeviceType();
    TAG_LOGI(AAFwkTag::TEST, "current deviceType is %{public}s", deviceType.c_str());
    if (deviceType == "default") {
        EXPECT_TRUE(isStartOptionsWithAnimation == false);
    } else if (deviceType == "phone") {
        EXPECT_TRUE(isStartOptionsWithAnimation == false);
    } else if (deviceType == "2in1") {
        EXPECT_TRUE(isStartOptionsWithAnimation == true);
    }
}

/**
 * @tc.number: AppUtilsTest_1000
 * @tc.desc: Test IsMultiProcessModel works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_1000, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_1000 called.");
    bool isMultiProcessModel = AAFwk::AppUtils::GetInstance().IsMultiProcessModel();
    std::string deviceType = OHOS::system::GetDeviceType();
    TAG_LOGI(AAFwkTag::TEST, "current deviceType is %{public}s", deviceType.c_str());
    if (deviceType == "default") {
        EXPECT_TRUE(isMultiProcessModel == false);
    } else if (deviceType == "phone") {
        EXPECT_TRUE(isMultiProcessModel == false);
    } else if (deviceType == "2in1") {
        EXPECT_TRUE(isMultiProcessModel == true);
    }
}

/**
 * @tc.number: AppUtilsTest_1100
 * @tc.desc: Test IsStartOptionsWithProcessOptions works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_1100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_1100 called.");
    bool isStartOptionsWithProcessOptions = AAFwk::AppUtils::GetInstance().IsStartOptionsWithProcessOptions();
    std::string deviceType = OHOS::system::GetDeviceType();
    TAG_LOGI(AAFwkTag::TEST, "current deviceType is %{public}s", deviceType.c_str());
    if (deviceType == "default") {
        EXPECT_TRUE(isStartOptionsWithProcessOptions == false);
    } else if (deviceType == "phone") {
        EXPECT_TRUE(isStartOptionsWithProcessOptions == false);
    } else if (deviceType == "2in1") {
        EXPECT_TRUE(isStartOptionsWithProcessOptions == true);
    }
}

/**
 * @tc.number: AppUtilsTest_1200
 * @tc.desc: Test EnableMoveUIAbilityToBackgroundApi works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_1200, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_1200 called.");
    bool enableMoveUIAbilityToBackgroundApi = AAFwk::AppUtils::GetInstance().EnableMoveUIAbilityToBackgroundApi();
    std::string deviceType = OHOS::system::GetDeviceType();
    TAG_LOGI(AAFwkTag::TEST, "current deviceType is %{public}s", deviceType.c_str());
    if (deviceType == "default") {
        EXPECT_TRUE(enableMoveUIAbilityToBackgroundApi == true);
    } else if (deviceType == "phone") {
        EXPECT_TRUE(enableMoveUIAbilityToBackgroundApi == true);
    } else if (deviceType == "2in1") {
        EXPECT_TRUE(enableMoveUIAbilityToBackgroundApi == false);
    }
}

/**
 * @tc.number: AppUtilsTest_1300
 * @tc.desc: Test MaxChildProcess works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_1300, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_1300 called.");
    auto maxChildProcess = AAFwk::AppUtils::GetInstance().MaxChildProcess();
    std::string deviceType = OHOS::system::GetDeviceType();
    TAG_LOGI(AAFwkTag::TEST, "current deviceType is %{public}s", deviceType.c_str());
    if (deviceType == "phone" || deviceType == "2in1") {
        EXPECT_TRUE(maxChildProcess != 0);
    }
}

/**
 * @tc.number: AppUtilsTest_1400
 * @tc.desc: Test IsAllowNativeChildProcess works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_1400, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_1400 called.");
    auto allow = AAFwk::AppUtils::GetInstance().IsAllowNativeChildProcess("com.test.demo");
    EXPECT_FALSE(allow);
}

/**
 * @tc.number: AppUtilsTest_1500
 * @tc.desc: Test IsSupportMultiInstance works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_1500, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_1500 called.");
    bool isSupportMultiInstance = AAFwk::AppUtils::GetInstance().IsSupportMultiInstance();
    std::string deviceType = OHOS::system::GetDeviceType();
    TAG_LOGI(AAFwkTag::TEST, "current deviceType is %{public}s", deviceType.c_str());
    if (deviceType == "default") {
        EXPECT_TRUE(isSupportMultiInstance == false);
    } else if (deviceType == "phone") {
        EXPECT_TRUE(isSupportMultiInstance == false);
    } else if (deviceType == "2in1") {
        EXPECT_TRUE(isSupportMultiInstance == true);
    }
}

/**
 * @tc.number: AppUtilsTest_1600
 * @tc.desc: Test AllowChildProcessInMultiProcessFeatureApp works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_1600, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_1600 start.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    bool allow = appUtils.AllowChildProcessInMultiProcessFeatureApp();
    EXPECT_FALSE(allow);

    appUtils.allowChildProcessInMultiProcessFeatureApp_.value = true;
    allow = appUtils.AllowChildProcessInMultiProcessFeatureApp();
    EXPECT_TRUE(allow);
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_1600 end.");
}

/**
 * @tc.number: AppUtilsTest_1700
 * @tc.desc: Test MaxMultiProcessFeatureChildProcess works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_1700, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_1700 called.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();

    appUtils.maxMultiProcessFeatureChildProcess_.isLoaded = true;
    appUtils.maxMultiProcessFeatureChildProcess_.value = 512;
    auto maxProcess = appUtils.MaxMultiProcessFeatureChildProcess();
    EXPECT_TRUE(maxProcess == 512);
}

/**
 * @tc.number: AppUtilsTest_1800
 * @tc.desc: Test InResidentWhiteList works
 * @tc.desc: Test InResidentWhiteList works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_1800, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_1800 called.");
    auto allow = AAFwk::AppUtils::GetInstance().InResidentWhiteList("com.test.demo");
    EXPECT_FALSE(allow);
}

/**
 * @tc.number: AppUtilsTest_1900
 * @tc.desc: Test GetResidentWhiteList works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_1900, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_1900 called.");
    auto residentWhiteList = AAFwk::AppUtils::GetInstance().GetResidentWhiteList();
    bool isExist = false;
    for (const auto &item: residentWhiteList) {
        if (item == "com.test.demo") {
            isExist = true;
        }
    }
    EXPECT_FALSE(isExist);
}

/**
 * @tc.number: AppUtilsTest_2000
 * @tc.desc: Test IsSupportGrantUriPermission works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_2000, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_2000 called.");
    auto isSupport = AAFwk::AppUtils::GetInstance().IsSupportGrantUriPermission();
    EXPECT_TRUE(isSupport);
}

/**
 * @tc.number: AppUtilsTest_2100
 * @tc.desc: Test IsSupportGrantUriPermission works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, AppUtilsTest_2100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "AppUtilsTest_2100 called.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    appUtils.isGrantTempUriPermission_.isLoaded = true;
    auto isSupport = appUtils.IsSupportGrantUriPermission();
    EXPECT_TRUE(isSupport);
}

/**
 * @tc.number: IsLauncher_0100
 * @tc.desc: Test IsLauncher works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, IsLauncher_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "IsLauncher_0100 called.");
    std::string bundleName = "com.ohos.launcher";
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    bool result = appUtils.IsLauncher(bundleName);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: IsLauncher_0200
 * @tc.desc: Test IsLauncher works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, IsLauncher_0200, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "IsLauncher_0200 called.");
    std::string bundleName = "com.ohos.launcher.test";
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    bool result = appUtils.IsLauncher(bundleName);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: IsLauncher_0300
 * @tc.desc: Test IsLauncher works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, IsLauncher_0300, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "IsLauncher_0200 called.");
    std::string bundleName = "com.ohos.sceneboard";
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    appUtils.isSceneBoard_ = true;
    bool result = appUtils.IsLauncher(bundleName);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: IsSupportNativeChildProcess_0100
 * @tc.desc: Test IsSupportNativeChildProcess works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, IsSupportNativeChildProcess_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "IsSupportNativeChildProcess_0100 called.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    bool result = appUtils.IsSupportNativeChildProcess();
    EXPECT_FALSE(result);
}

/**
 * @tc.number: IsSupportNativeChildProcess_0200
 * @tc.desc: Test IsSupportNativeChildProcess works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, IsSupportNativeChildProcess_0200, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "IsSupportNativeChildProcess_0200 called.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    appUtils.isSupportNativeChildProcess_.isLoaded = true;
    appUtils.isSupportNativeChildProcess_.value = true;
    bool result = appUtils.IsSupportNativeChildProcess();
    EXPECT_TRUE(result);
}

/**
 * @tc.number: GetAncoAppIdentifiers_0100
 * @tc.desc: Test GetAncoAppIdentifiers works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, GetAncoAppIdentifiers_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAncoAppIdentifiers_0100 called.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    std::string result = appUtils.GetAncoAppIdentifiers();
    EXPECT_EQ(result, "");
}

/**
 * @tc.number: IsCacheAbilityEnabled_0100
 * @tc.desc: Test IsCacheAbilityEnabled works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, IsCacheAbilityEnabled_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "IsCacheAbilityEnabled_0100 called.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    bool result = appUtils.IsCacheAbilityEnabled();
    EXPECT_FALSE(result);
}

/**
 * @tc.number: IsSupportAppServiceExtension_0100
 * @tc.desc: Test IsSupportAppServiceExtension works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, IsSupportAppServiceExtension_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "IsSupportAppServiceExtension_0100 called.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    bool result = appUtils.IsSupportAppServiceExtension();
    EXPECT_FALSE(result);
}

/**
 * @tc.number: IsSupportAppServiceExtension_0200
 * @tc.desc: Test IsSupportAppServiceExtension works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, IsSupportAppServiceExtension_0200, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "IsSupportAppServiceExtension_0200 called.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    appUtils.isSupportAppServiceExtension_.isLoaded = true;
    appUtils.isSupportAppServiceExtension_.value = true;
    bool result = appUtils.IsSupportAppServiceExtension();
    EXPECT_TRUE(result);
}

/**
 * @tc.number: MaxMultiProcessFeatureChildProcess_0100
 * @tc.desc: Test MaxMultiProcessFeatureChildProcess works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, MaxMultiProcessFeatureChildProcess_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "MaxMultiProcessFeatureChildProcess_0100 called.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    appUtils.maxMultiProcessFeatureChildProcess_.isLoaded = false;
    bool result = appUtils.MaxMultiProcessFeatureChildProcess();
    EXPECT_FALSE(result);
}

/**
 * @tc.number: IsSystemReasonMessage_0100
 * @tc.desc: Test IsSystemReasonMessage works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, IsSystemReasonMessage_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "IsSystemReasonMessage_0100 called.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    std::string reasonMessage = "";
    bool result = appUtils.IsSystemReasonMessage(reasonMessage);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: IsGrantPersistUriPermission_0100
 * @tc.desc: Test IsGrantPersistUriPermission works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, IsGrantPersistUriPermission_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "IsGrantPersistUriPermission_0100 called.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    appUtils.isGrantPersistUriPermission_.isLoaded = false;
    bool result = appUtils.IsGrantPersistUriPermission();
    EXPECT_FALSE(result);
}

/**
 * @tc.number: GetMigrateClientBundleName_0100
 * @tc.desc: Test GetMigrateClientBundleName works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, GetMigrateClientBundleName_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "GetMigrateClientBundleName_0100 called.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    appUtils.migrateClientBundleName_.isLoaded = false;
    std::string result = appUtils.GetMigrateClientBundleName();
    EXPECT_EQ(result, "");
}

/**
 * @tc.number: IsUseMultiRenderProcess_0100
 * @tc.desc: Test IsUseMultiRenderProcess works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, IsUseMultiRenderProcess_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "IsUseMultiRenderProcess_0100 called.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    appUtils.isUseMultiRenderProcess_.isLoaded = false;
    bool result = appUtils.IsUseMultiRenderProcess();
    EXPECT_TRUE(result);
}

/**
 * @tc.number: IsLaunchEmbededUIAbility_0100
 * @tc.desc: Test IsLaunchEmbededUIAbility works
 * @tc.type: FUNC
 */
HWTEST_F(AppUtilsTest, IsLaunchEmbededUIAbility_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "IsLaunchEmbededUIAbility_0100 called.");
    auto &appUtils = AAFwk::AppUtils::GetInstance();
    appUtils.isLaunchEmbededUIAbility_.isLoaded = false;
    bool result = appUtils.IsLaunchEmbededUIAbility();
    EXPECT_FALSE(result);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
