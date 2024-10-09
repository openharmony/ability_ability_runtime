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

#include "ability_manager_errors.h"
#include "app_running_record.h"
#include "app_utils.h"
#include "hilog_tag_wrapper.h"
#include "mock_app_mgr_service_inner.h"
#include "mock_kia_interceptor_impl.h"
#include "permission_verification.h"
#include "window_manager.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
namespace OHOS {
namespace AppExecFwk {
class AppMgrServiceInnerMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AppMgrServiceInnerMockTest::SetUpTestCase() {}

void AppMgrServiceInnerMockTest::TearDownTestCase() {}

void AppMgrServiceInnerMockTest::SetUp() {}

void AppMgrServiceInnerMockTest::TearDown() {}

/*
 * Feature: AppMgrServiceInner
 * Name: MakeKiaProcess_001
 * Function: MakeKiaProcess
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner MakeKiaProcess
 */
HWTEST_F(AppMgrServiceInnerMockTest, MakeKiaProcess_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_001 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);
    serviceInner_->kiaInterceptor_ = new (std::nothrow) MockKiaInterceptorImpl();
    EXPECT_NE(serviceInner_->kiaInterceptor_, nullptr);

    MockKiaInterceptorImpl::onInterceptRetCode = 0;
    MockKiaInterceptorImpl::kiaWatermarkBusinessName = "watermark";
    MockKiaInterceptorImpl::isWatermarkEnabled = true;

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    auto want = std::make_shared<AAFwk::Want>();
    EXPECT_NE(want, nullptr);
    want->SetUri("file://kia-file-uri");
    bool isKia = false;
    std::string watermarkBusinessName;
    bool isWatermarkEnabled = false;
    bool isFileUri = false;
    std::string processName = "process";
    auto retCode = serviceInner_->MakeKiaProcess(want, isKia, watermarkBusinessName,
        isWatermarkEnabled, isFileUri, processName);
    EXPECT_EQ(retCode, ERR_OK);
    EXPECT_EQ(isKia, true);
    EXPECT_EQ(isFileUri, true);
    EXPECT_EQ(watermarkBusinessName, "watermark");
    EXPECT_EQ(isWatermarkEnabled, true);
    EXPECT_EQ(processName, "process_KIA");
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_001 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: MakeKiaProcess_002
 * Function: MakeKiaProcess
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner MakeKiaProcess
 */
HWTEST_F(AppMgrServiceInnerMockTest, MakeKiaProcess_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_002 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = false;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), false);
    bool isKia = false;
    std::string watermarkBusinessName;
    bool isWatermarkEnabled = false;
    bool isFileUri = false;
    std::string processName = "process";
    auto retCode = serviceInner_->MakeKiaProcess(nullptr, isKia, watermarkBusinessName,
        isWatermarkEnabled, isFileUri, processName);
    EXPECT_EQ(retCode, ERR_OK);
    EXPECT_EQ(isKia, false);
    EXPECT_EQ(isFileUri, false);
    EXPECT_EQ(watermarkBusinessName.empty(), true);
    EXPECT_EQ(isWatermarkEnabled, false);
    EXPECT_EQ(processName, "process");
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_002 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: MakeKiaProcess_003
 * Function: MakeKiaProcess
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner MakeKiaProcess
 */
HWTEST_F(AppMgrServiceInnerMockTest, MakeKiaProcess_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_003 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);
    bool isKia = false;
    std::string watermarkBusinessName;
    bool isWatermarkEnabled = false;
    bool isFileUri = false;
    std::string processName = "process";
    auto retCode = serviceInner_->MakeKiaProcess(nullptr, isKia, watermarkBusinessName,
        isWatermarkEnabled, isFileUri, processName);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    EXPECT_EQ(isKia, false);
    EXPECT_EQ(isFileUri, false);
    EXPECT_EQ(watermarkBusinessName.empty(), true);
    EXPECT_EQ(isWatermarkEnabled, false);
    EXPECT_EQ(processName, "process");
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_002 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: MakeKiaProcess_004
 * Function: MakeKiaProcess
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner MakeKiaProcess
 */
HWTEST_F(AppMgrServiceInnerMockTest, MakeKiaProcess_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_004 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);
    serviceInner_->kiaInterceptor_ = new (std::nothrow) MockKiaInterceptorImpl();
    EXPECT_NE(serviceInner_->kiaInterceptor_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    auto want = std::make_shared<AAFwk::Want>();
    EXPECT_NE(want, nullptr);
    want->SetUri("not-kia-file-uri");
    bool isKia = false;
    std::string watermarkBusinessName;
    bool isWatermarkEnabled = false;
    bool isFileUri = false;
    std::string processName = "process";
    auto retCode = serviceInner_->MakeKiaProcess(want, isKia, watermarkBusinessName,
        isWatermarkEnabled, isFileUri, processName);
    EXPECT_EQ(retCode, ERR_OK);
    EXPECT_EQ(isKia, false);
    EXPECT_EQ(isFileUri, false);
    EXPECT_EQ(watermarkBusinessName.empty(), true);
    EXPECT_EQ(isWatermarkEnabled, false);
    EXPECT_EQ(processName, "process");
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_004 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: MakeKiaProcess_005
 * Function: MakeKiaProcess
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner MakeKiaProcess
 */
HWTEST_F(AppMgrServiceInnerMockTest, MakeKiaProcess_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_005 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);
    serviceInner_->kiaInterceptor_ = nullptr;

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    auto want = std::make_shared<AAFwk::Want>();
    EXPECT_NE(want, nullptr);
    want->SetUri("file://kia-file-uri");
    bool isKia = false;
    std::string watermarkBusinessName;
    bool isWatermarkEnabled = false;
    bool isFileUri = false;
    std::string processName = "process";
    auto retCode = serviceInner_->MakeKiaProcess(want, isKia, watermarkBusinessName,
        isWatermarkEnabled, isFileUri, processName);
    EXPECT_EQ(retCode, ERR_OK);
    EXPECT_EQ(isKia, false);
    EXPECT_EQ(isFileUri, true);
    EXPECT_EQ(watermarkBusinessName.empty(), true);
    EXPECT_EQ(isWatermarkEnabled, false);
    EXPECT_EQ(processName, "process");
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_005 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: MakeKiaProcess_006
 * Function: MakeKiaProcess
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner MakeKiaProcess
 */
HWTEST_F(AppMgrServiceInnerMockTest, MakeKiaProcess_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_006 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);
    serviceInner_->kiaInterceptor_ = new (std::nothrow) MockKiaInterceptorImpl();
    EXPECT_NE(serviceInner_->kiaInterceptor_, nullptr);

    MockKiaInterceptorImpl::onInterceptRetCode = -1;
    MockKiaInterceptorImpl::kiaWatermarkBusinessName = "watermark";
    MockKiaInterceptorImpl::isWatermarkEnabled = true;

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    auto want = std::make_shared<AAFwk::Want>();
    EXPECT_NE(want, nullptr);
    want->SetUri("file://kia-file-uri");
    bool isKia = false;
    std::string watermarkBusinessName;
    bool isWatermarkEnabled = false;
    bool isFileUri = false;
    std::string processName = "process";
    auto retCode = serviceInner_->MakeKiaProcess(want, isKia, watermarkBusinessName,
        isWatermarkEnabled, isFileUri, processName);
    EXPECT_EQ(retCode, ERR_OK);
    EXPECT_EQ(isKia, false);
    EXPECT_EQ(isFileUri, true);
    EXPECT_EQ(watermarkBusinessName.empty(), true);
    EXPECT_EQ(isWatermarkEnabled, false);
    EXPECT_EQ(processName, "process");
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_006 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: MakeKiaProcess_007
 * Function: MakeKiaProcess
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner MakeKiaProcess
 */
HWTEST_F(AppMgrServiceInnerMockTest, MakeKiaProcess_007, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_007 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);
    serviceInner_->kiaInterceptor_ = new (std::nothrow) MockKiaInterceptorImpl();
    EXPECT_NE(serviceInner_->kiaInterceptor_, nullptr);

    MockKiaInterceptorImpl::onInterceptRetCode = 0;
    MockKiaInterceptorImpl::kiaWatermarkBusinessName.clear();
    MockKiaInterceptorImpl::isWatermarkEnabled = true;

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    auto want = std::make_shared<AAFwk::Want>();
    EXPECT_NE(want, nullptr);
    want->SetUri("file://kia-file-uri");
    bool isKia = false;
    std::string watermarkBusinessName;
    bool isWatermarkEnabled = false;
    bool isFileUri = false;
    std::string processName = "process";
    auto retCode = serviceInner_->MakeKiaProcess(want, isKia, watermarkBusinessName,
        isWatermarkEnabled, isFileUri, processName);
    EXPECT_EQ(retCode, ERR_OK);
    EXPECT_EQ(isKia, false);
    EXPECT_EQ(isFileUri, true);
    EXPECT_EQ(watermarkBusinessName.empty(), true);
    EXPECT_EQ(isWatermarkEnabled, true);
    EXPECT_EQ(processName, "process");
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_007 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: MakeKiaProcess_008
 * Function: MakeKiaProcess
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner MakeKiaProcess
 */
HWTEST_F(AppMgrServiceInnerMockTest, MakeKiaProcess_008, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_008 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);
    serviceInner_->kiaInterceptor_ = new (std::nothrow) MockKiaInterceptorImpl();
    EXPECT_NE(serviceInner_->kiaInterceptor_, nullptr);

    MockKiaInterceptorImpl::onInterceptRetCode = 0;
    MockKiaInterceptorImpl::kiaWatermarkBusinessName = "watermark";
    MockKiaInterceptorImpl::isWatermarkEnabled = false;

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    auto want = std::make_shared<AAFwk::Want>();
    EXPECT_NE(want, nullptr);
    want->SetUri("file://kia-file-uri");
    bool isKia = false;
    std::string watermarkBusinessName;
    bool isWatermarkEnabled = false;
    bool isFileUri = false;
    std::string processName = "process";
    auto retCode = serviceInner_->MakeKiaProcess(want, isKia, watermarkBusinessName,
        isWatermarkEnabled, isFileUri, processName);
    EXPECT_EQ(retCode, ERR_OK);
    EXPECT_EQ(isKia, false);
    EXPECT_EQ(isFileUri, true);
    EXPECT_EQ(watermarkBusinessName, "watermark");
    EXPECT_EQ(isWatermarkEnabled, false);
    EXPECT_EQ(processName, "process");
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest MakeKiaProcess_008 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: ProcessKia_001
 * Function: ProcessKia
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner ProcessKia
 */
HWTEST_F(AppMgrServiceInnerMockTest, ProcessKia_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest ProcessKia_001 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    auto appRecord = std::make_shared<AppRunningRecord>();
    EXPECT_NE(appRecord, nullptr);
    appRecord->pid_ = 1000;
    EXPECT_EQ(appRecord->GetPid(), 1000);
    bool isKia = true;
    std::string watermarkBusinessName;
    bool isWatermarkEnabled = false;
    WindowManager::retCodeSetProcessWatermark = 0;
    WindowManager::retCodeSkipSnapshotForAppProcess = 0;
    auto retCode = serviceInner_->ProcessKia(isKia, appRecord, watermarkBusinessName, isWatermarkEnabled);
    EXPECT_EQ(retCode, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest ProcessKia_001 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: ProcessKia_002
 * Function: ProcessKia
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner ProcessKia
 */
HWTEST_F(AppMgrServiceInnerMockTest, ProcessKia_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest ProcessKia_002 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = false;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), false);

    auto retCode = serviceInner_->ProcessKia(false, nullptr, "", false);
    EXPECT_EQ(retCode, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest ProcessKia_002 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: ProcessKia_003
 * Function: ProcessKia
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner ProcessKia
 */
HWTEST_F(AppMgrServiceInnerMockTest, ProcessKia_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest ProcessKia_003 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    auto retCode = serviceInner_->ProcessKia(false, nullptr, "", false);
    EXPECT_EQ(retCode, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest ProcessKia_003 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: ProcessKia_004
 * Function: ProcessKia
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner ProcessKia
 */
HWTEST_F(AppMgrServiceInnerMockTest, ProcessKia_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest ProcessKia_004 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    auto retCode = serviceInner_->ProcessKia(true, nullptr, "", false);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest ProcessKia_004 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: ProcessKia_005
 * Function: ProcessKia
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner ProcessKia
 */
HWTEST_F(AppMgrServiceInnerMockTest, ProcessKia_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest ProcessKia_005 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    auto appRecord = std::make_shared<AppRunningRecord>();
    EXPECT_NE(appRecord, nullptr);
    appRecord->pid_ = 1000;
    EXPECT_EQ(appRecord->GetPid(), 1000);
    bool isKia = true;
    std::string watermarkBusinessName;
    bool isWatermarkEnabled = false;
    WindowManager::retCodeSetProcessWatermark = -1;
    auto retCode = serviceInner_->ProcessKia(isKia, appRecord, watermarkBusinessName, isWatermarkEnabled);
    EXPECT_EQ(retCode, -1);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest ProcessKia_005 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: ProcessKia_006
 * Function: ProcessKia
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner ProcessKia
 */
HWTEST_F(AppMgrServiceInnerMockTest, ProcessKia_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest ProcessKia_006 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    auto appRecord = std::make_shared<AppRunningRecord>();
    EXPECT_NE(appRecord, nullptr);
    appRecord->pid_ = 1000;
    EXPECT_EQ(appRecord->GetPid(), 1000);
    bool isKia = true;
    std::string watermarkBusinessName;
    bool isWatermarkEnabled = false;
    WindowManager::retCodeSetProcessWatermark = 0;
    WindowManager::retCodeSkipSnapshotForAppProcess = -1;
    auto retCode = serviceInner_->ProcessKia(isKia, appRecord, watermarkBusinessName, isWatermarkEnabled);
    EXPECT_EQ(retCode, -1);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest ProcessKia_006 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: RegisterKiaInterceptor_001
 * Function: RegisterKiaInterceptor
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner RegisterKiaInterceptor
 */
HWTEST_F(AppMgrServiceInnerMockTest, RegisterKiaInterceptor_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest RegisterKiaInterceptor_001 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    PermissionVerification::flag = PermissionVerification::FLAG::IS_SA_CALL;
    PermissionVerification::hasSuperviseKiaServicePermission = true;
    EXPECT_EQ(PermissionVerification::GetInstance()->VerifySuperviseKiaServicePermission(), true);

    sptr<IKiaInterceptor> kiaInterceptor = new (std::nothrow) MockKiaInterceptorImpl();
    EXPECT_NE(kiaInterceptor, nullptr);
    auto retCode = serviceInner_->RegisterKiaInterceptor(kiaInterceptor);
    EXPECT_EQ(retCode, ERR_OK);
    EXPECT_EQ(serviceInner_->kiaInterceptor_, kiaInterceptor);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest RegisterKiaInterceptor_001 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: RegisterKiaInterceptor_002
 * Function: RegisterKiaInterceptor
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner RegisterKiaInterceptor
 */
HWTEST_F(AppMgrServiceInnerMockTest, RegisterKiaInterceptor_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest RegisterKiaInterceptor_002 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = false;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), false);

    auto retCode = serviceInner_->RegisterKiaInterceptor(nullptr);
    EXPECT_EQ(retCode, ERR_PERMISSION_DENIED);
    EXPECT_EQ(serviceInner_->kiaInterceptor_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest RegisterKiaInterceptor_002 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: RegisterKiaInterceptor_003
 * Function: RegisterKiaInterceptor
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner RegisterKiaInterceptor
 */
HWTEST_F(AppMgrServiceInnerMockTest, RegisterKiaInterceptor_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest RegisterKiaInterceptor_003 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    PermissionVerification::flag = 0;

    auto retCode = serviceInner_->RegisterKiaInterceptor(nullptr);
    EXPECT_EQ(retCode, ERR_PERMISSION_DENIED);
    EXPECT_EQ(serviceInner_->kiaInterceptor_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest RegisterKiaInterceptor_003 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: RegisterKiaInterceptor_004
 * Function: RegisterKiaInterceptor
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner RegisterKiaInterceptor
 */
HWTEST_F(AppMgrServiceInnerMockTest, RegisterKiaInterceptor_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest RegisterKiaInterceptor_004 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    PermissionVerification::flag = PermissionVerification::FLAG::IS_SA_CALL;
    PermissionVerification::hasSuperviseKiaServicePermission = false;
    EXPECT_EQ(PermissionVerification::GetInstance()->VerifySuperviseKiaServicePermission(), false);

    auto retCode = serviceInner_->RegisterKiaInterceptor(nullptr);
    EXPECT_EQ(retCode, ERR_PERMISSION_DENIED);
    EXPECT_EQ(serviceInner_->kiaInterceptor_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest RegisterKiaInterceptor_004 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: RegisterKiaInterceptor_005
 * Function: RegisterKiaInterceptor
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner RegisterKiaInterceptor
 */
HWTEST_F(AppMgrServiceInnerMockTest, RegisterKiaInterceptor_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest RegisterKiaInterceptor_005 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    PermissionVerification::flag = PermissionVerification::FLAG::IS_SA_CALL;
    PermissionVerification::hasSuperviseKiaServicePermission = true;
    EXPECT_EQ(PermissionVerification::GetInstance()->VerifySuperviseKiaServicePermission(), true);

    auto retCode = serviceInner_->RegisterKiaInterceptor(nullptr);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    EXPECT_EQ(serviceInner_->kiaInterceptor_, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest RegisterKiaInterceptor_005 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: CheckIsKiaProcess_001
 * Function: CheckIsKiaProcess
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner CheckIsKiaProcess
 */
HWTEST_F(AppMgrServiceInnerMockTest, CheckIsKiaProcess_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest CheckIsKiaProcess_001 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    PermissionVerification::flag = PermissionVerification::FLAG::IS_SA_CALL;
    PermissionVerification::hasSuperviseKiaServicePermission = true;
    EXPECT_EQ(PermissionVerification::GetInstance()->VerifySuperviseKiaServicePermission(), true);

    serviceInner_->appRunningManager_ = std::make_shared<AppRunningManager>();
    EXPECT_NE(serviceInner_->appRunningManager_, nullptr);
    serviceInner_->appRunningManager_->retCode_ = ERR_OK;
    serviceInner_->appRunningManager_->isKia_ = true;

    bool isKia = false;
    auto retCode = serviceInner_->CheckIsKiaProcess(1000, isKia);
    EXPECT_EQ(retCode, ERR_OK);
    EXPECT_EQ(isKia, true);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest CheckIsKiaProcess_001 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: CheckIsKiaProcess_002
 * Function: CheckIsKiaProcess
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner CheckIsKiaProcess
 */
HWTEST_F(AppMgrServiceInnerMockTest, CheckIsKiaProcess_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest CheckIsKiaProcess_002 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = false;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), false);

    bool isKia = false;
    auto retCode = serviceInner_->CheckIsKiaProcess(1000, isKia);
    EXPECT_EQ(retCode, ERR_PERMISSION_DENIED);
    EXPECT_EQ(isKia, false);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest CheckIsKiaProcess_002 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: CheckIsKiaProcess_003
 * Function: CheckIsKiaProcess
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner CheckIsKiaProcess
 */
HWTEST_F(AppMgrServiceInnerMockTest, CheckIsKiaProcess_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest CheckIsKiaProcess_003 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    PermissionVerification::flag = 0;

    bool isKia = false;
    auto retCode = serviceInner_->CheckIsKiaProcess(1000, isKia);
    EXPECT_EQ(retCode, ERR_PERMISSION_DENIED);
    EXPECT_EQ(isKia, false);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest CheckIsKiaProcess_003 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: CheckIsKiaProcess_004
 * Function: CheckIsKiaProcess
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner CheckIsKiaProcess
 */
HWTEST_F(AppMgrServiceInnerMockTest, CheckIsKiaProcess_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest CheckIsKiaProcess_004 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    PermissionVerification::flag = PermissionVerification::FLAG::IS_SA_CALL;
    PermissionVerification::hasSuperviseKiaServicePermission = false;
    EXPECT_EQ(PermissionVerification::GetInstance()->VerifySuperviseKiaServicePermission(), false);

    bool isKia = false;
    auto retCode = serviceInner_->CheckIsKiaProcess(1000, isKia);
    EXPECT_EQ(retCode, ERR_PERMISSION_DENIED);
    EXPECT_EQ(isKia, false);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest CheckIsKiaProcess_004 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: CheckIsKiaProcess_005
 * Function: CheckIsKiaProcess
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner CheckIsKiaProcess
 */
HWTEST_F(AppMgrServiceInnerMockTest, CheckIsKiaProcess_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest CheckIsKiaProcess_005 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    PermissionVerification::flag = PermissionVerification::FLAG::IS_SA_CALL;
    PermissionVerification::hasSuperviseKiaServicePermission = true;
    EXPECT_EQ(PermissionVerification::GetInstance()->VerifySuperviseKiaServicePermission(), true);

    serviceInner_->appRunningManager_ = nullptr;
    EXPECT_EQ(serviceInner_->appRunningManager_, nullptr);

    bool isKia = false;
    auto retCode = serviceInner_->CheckIsKiaProcess(1000, isKia);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    EXPECT_EQ(isKia, false);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest CheckIsKiaProcess_005 end");
}

/*
 * Feature: AppMgrServiceInner
 * Name: CheckIsKiaProcess_006
 * Function: CheckIsKiaProcess
 * SubFunction: NA
 * FunctionPoints: AppMgrServiceInner CheckIsKiaProcess
 */
HWTEST_F(AppMgrServiceInnerMockTest, CheckIsKiaProcess_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest CheckIsKiaProcess_006 start");
    auto serviceInner_ = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(serviceInner_, nullptr);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);

    PermissionVerification::flag = PermissionVerification::FLAG::IS_SA_CALL;
    PermissionVerification::hasSuperviseKiaServicePermission = true;
    EXPECT_EQ(PermissionVerification::GetInstance()->VerifySuperviseKiaServicePermission(), true);

    serviceInner_->appRunningManager_ = std::make_shared<AppRunningManager>();
    EXPECT_NE(serviceInner_->appRunningManager_, nullptr);
    serviceInner_->appRunningManager_->retCode_ = -1;

    bool isKia = false;
    auto retCode = serviceInner_->CheckIsKiaProcess(1000, isKia);
    EXPECT_EQ(retCode, -1);
    EXPECT_EQ(isKia, false);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerMockTest CheckIsKiaProcess_006 end");
}
}  // namespace AppExecFwk
}  // namespace OHOS
