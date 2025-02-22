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

#include "ability_manager_service.h"
#include "task_handler_wrap.h"
#include "ability_record.h"
#include "sa_mgr_client.h"

using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace AppExecFwk {
namespace {
const int BUNDLE_MGR_SERVICE_SYS_ABILITY_ID = 401;
}
class FreeInstallTest : public testing::Test {
public:
    FreeInstallTest()
    {}
    ~FreeInstallTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    sptr<Token> MockToken();
    std::shared_ptr<FreeInstallManager> freeInstallManager_ = nullptr;
};

void FreeInstallTest::SetUpTestCase(void) {}

void FreeInstallTest::TearDownTestCase(void) {}

void FreeInstallTest::SetUp(void) {}

void FreeInstallTest::TearDown(void)
{}

sptr<Token> FreeInstallTest::MockToken()
{
    sptr<Token> token = nullptr;
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.test.demo";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    if (!abilityRecord) {
        return nullptr;
    }
    return abilityRecord->GetToken();
}

/**
 * @tc.number: RemoteFreeInstall_001
 * @tc.name: RemoteFreeInstall
 * @tc.desc: Test RemoteFreeInstall.
 */
HWTEST_F(FreeInstallTest, FreeInstall_RemoteFreeInstall_001, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "com.test.demo", "MainAbility");
    want.SetElement(element);
    const int32_t userId = 100;
    const int requestCode = 0;
    want.SetParam(Want::PARAM_RESV_START_TIME, std::string("0"));
    // mock callerToken
    const sptr<IRemoteObject> callerToken = MockToken();
    int res = 0;

    usleep(100000); // 100000 means us.
    // from freeInstallManager_->freeInstallList_ find startInstallTime
    for (auto it = freeInstallManager_->freeInstallList_.begin(); it != freeInstallManager_->freeInstallList_.end();) {
        std::string bundleName = (*it).want.GetElement().GetBundleName();
        std::string abilityName = (*it).want.GetElement().GetAbilityName();
        if (want.GetElement().GetBundleName().compare(bundleName) != 0 ||
            want.GetElement().GetAbilityName().compare(abilityName) != 0) {
            want.SetParam(Want::PARAM_RESV_START_TIME, (*it).want.GetStringParam(Want::PARAM_RESV_START_TIME));
            break;
        }
    }
    res = freeInstallManager_->RemoteFreeInstall(want, userId, requestCode, callerToken);
    EXPECT_EQ(res, NOT_TOP_ABILITY);
}

/**
 * @tc.number: RemoteFreeInstall_002
 * @tc.name: RemoteFreeInstall
 * @tc.desc: Test RemoteFreeInstall.
 */
HWTEST_F(FreeInstallTest, FreeInstall_RemoteFreeInstall_002, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "com.test.demo", "MainAbility");
    want.SetElement(element);
    const int32_t userId = 100;
    const int requestCode = 0;
    want.SetParam(Want::PARAM_RESV_START_TIME, std::string("0"));
    want.SetParam(FROM_REMOTE_KEY, true);
    // mock callerToken
    const sptr<IRemoteObject> callerToken = MockToken();
    int res = 0;

    usleep(100000); // 100000 means us.
    // from freeInstallManager_->freeInstallList_ find startInstallTime
    for (auto it = freeInstallManager_->freeInstallList_.begin(); it != freeInstallManager_->freeInstallList_.end();) {
        std::string bundleName = (*it).want.GetElement().GetBundleName();
        std::string abilityName = (*it).want.GetElement().GetAbilityName();
        if (want.GetElement().GetBundleName().compare(bundleName) != 0 ||
            want.GetElement().GetAbilityName().compare(abilityName) != 0) {
            want.SetParam(Want::PARAM_RESV_START_TIME, (*it).want.GetStringParam(Want::PARAM_RESV_START_TIME));
            break;
        }
    }
    res = freeInstallManager_->RemoteFreeInstall(want, userId, requestCode, callerToken);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: StartRemoteFreeInstall_001
 * @tc.name: StartRemoteFreeInstall
 * @tc.desc: Test StartRemoteFreeInstall.
 */
HWTEST_F(FreeInstallTest, FreeInstall_StartRemoteFreeInstall_001, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "com.test.demo", "MainAbility");
    want.SetElement(element);
    const int32_t userId = 100;
    const int requestCode = 0;
    want.SetParam(Want::PARAM_RESV_START_TIME, std::string("0"));
    want.SetParam(Want::PARAM_RESV_FOR_RESULT, true);
    // mock callerToken
    const sptr<IRemoteObject> callerToken = MockToken();
    int res = 0;

    usleep(100000); // 100000 means us.
    // from freeInstallManager_->freeInstallList_ find startInstallTime
    for (auto it = freeInstallManager_->freeInstallList_.begin(); it != freeInstallManager_->freeInstallList_.end();) {
        std::string bundleName = (*it).want.GetElement().GetBundleName();
        std::string abilityName = (*it).want.GetElement().GetAbilityName();
        if (want.GetElement().GetBundleName().compare(bundleName) != 0 ||
            want.GetElement().GetAbilityName().compare(abilityName) != 0) {
            want.SetParam(Want::PARAM_RESV_START_TIME, (*it).want.GetStringParam(Want::PARAM_RESV_START_TIME));
            break;
        }
    }
    res = freeInstallManager_->StartRemoteFreeInstall(want, userId, requestCode, callerToken);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: StartRemoteFreeInstall_002
 * @tc.name: StartRemoteFreeInstall
 * @tc.desc: Test StartRemoteFreeInstall.
 */
HWTEST_F(FreeInstallTest, FreeInstall_StartRemoteFreeInstall_002, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "com.test.demo", "MainAbility");
    want.SetElement(element);
    const int32_t userId = 100;
    const int requestCode = 0;
    want.SetParam(Want::PARAM_RESV_START_TIME, std::string("0"));
    want.SetParam(Want::PARAM_RESV_FOR_RESULT, false);
    // mock callerToken
    const sptr<IRemoteObject> callerToken = MockToken();
    int res = 0;
    usleep(100000); // 100000 means us.
    // from freeInstallManager_->freeInstallList_ find startInstallTime
    for (auto it = freeInstallManager_->freeInstallList_.begin(); it != freeInstallManager_->freeInstallList_.end();) {
        std::string bundleName = (*it).want.GetElement().GetBundleName();
        std::string abilityName = (*it).want.GetElement().GetAbilityName();
        if (want.GetElement().GetBundleName().compare(bundleName) != 0 ||
            want.GetElement().GetAbilityName().compare(abilityName) != 0) {
            want.SetParam(Want::PARAM_RESV_START_TIME, (*it).want.GetStringParam(Want::PARAM_RESV_START_TIME));
            break;
        }
    }
    res = freeInstallManager_->StartRemoteFreeInstall(want, userId, requestCode, callerToken);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: NotifyDmsCallback_001
 * @tc.name: NotifyDmsCallback
 * @tc.desc: Test NotifyDmsCallback.
 */
HWTEST_F(FreeInstallTest, FreeInstall_NotifyDmsCallback_001, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "com.test.demo", "MainAbility");
    want.SetElement(element);
    const int32_t userId = 100;
    const int requestCode = 0;
    want.SetParam(Want::PARAM_RESV_START_TIME, std::string("0"));
    int res = 0;
    res = freeInstallManager_->NotifyDmsCallback(want, requestCode);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
}

/**
 * @tc.number: HandleOnFreeInstallSuccess_001
 * @tc.name: HandleOnFreeInstallSuccess
 * @tc.desc: Test HandleOnFreeInstallSuccess.
 */
HWTEST_F(FreeInstallTest, FreeInstall_HandleOnFreeInstallSuccess_001, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "com.test.demo", "MainAbility");
    want.SetElement(element);
    want.SetParam(Want::PARAM_RESV_START_TIME, std::string("0"));
    int32_t recordId = 100;
    FreeInstallInfo freeInstallInfo;
    freeInstallInfo.want = want;
    bool isAsync = true;
    freeInstallInfo.isPreStartMissionCalled = true;
    freeInstallManager_->HandleOnFreeInstallSuccess(recordId, freeInstallInfo, isAsync);
    EXPECT_EQ(freeInstallInfo.isOpenAtomicServiceShortUrl, false);
}

/**
 * @tc.number: HandleOnFreeInstallSuccess_002
 * @tc.name: HandleOnFreeInstallSuccess
 * @tc.desc: Test HandleOnFreeInstallSuccess.
 */
HWTEST_F(FreeInstallTest, FreeInstall_HandleOnFreeInstallSuccess_002, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "com.test.demo", "MainAbility");
    want.SetElement(element);
    int32_t recordId = 100;
    want.SetParam(Want::PARAM_RESV_START_TIME, std::string("0"));
    FreeInstallInfo freeInstallInfo;
    freeInstallInfo.want = want;
    bool isAsync = true;
    freeInstallInfo.isOpenAtomicServiceShortUrl = true;
    freeInstallManager_->HandleOnFreeInstallSuccess(recordId, freeInstallInfo, isAsync);
    EXPECT_EQ(freeInstallInfo.isPreStartMissionCalled, false);
}

/**
 * @tc.number: HandleOnFreeInstallFail_001
 * @tc.name: HandleOnFreeInstallFail
 * @tc.desc: Test HandleOnFreeInstallFail.
 */
HWTEST_F(FreeInstallTest, FreeInstall_HandleOnFreeInstallFail_001, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "com.ohos.param.sessionId", "MainAbility");
    want.SetElement(element);
    int32_t recordId = 100;
    int resultCode = 0;
    want.SetParam(Want::PARAM_RESV_START_TIME, std::string("0"));
    FreeInstallInfo freeInstallInfo;
    freeInstallInfo.want = want;
    bool isAsync = true;
    freeInstallInfo.isPreStartMissionCalled = true;
    freeInstallInfo.isStartUIAbilityBySCBCalled = true;
    freeInstallManager_->HandleOnFreeInstallFail(recordId, freeInstallInfo, resultCode, isAsync);
    EXPECT_EQ(freeInstallInfo.isOpenAtomicServiceShortUrl, false);
}

/**
 * @tc.number: HandleOnFreeInstallFail_002
 * @tc.name: HandleOnFreeInstallFail
 * @tc.desc: Test HandleOnFreeInstallFail.
 */
HWTEST_F(FreeInstallTest, FreeInstall_HandleOnFreeInstallFail_002, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "com.ohos.param.sessionId", "MainAbility");
    want.SetElement(element);
    int32_t recordId = 100;
    int resultCode = 0;
    want.SetParam(Want::PARAM_RESV_START_TIME, std::string("0"));
    FreeInstallInfo freeInstallInfo;
    freeInstallInfo.want = want;
    bool isAsync = true;
    freeInstallInfo.isOpenAtomicServiceShortUrl = true;
    freeInstallManager_->HandleOnFreeInstallFail(recordId, freeInstallInfo, resultCode, isAsync);
    EXPECT_EQ(freeInstallInfo.isPreStartMissionCalled, false);
}

/**
 * @tc.number: StartAbilityByFreeInstall_001
 * @tc.name: StartAbilityByFreeInstall
 * @tc.desc: Test StartAbilityByFreeInstall.
 */
HWTEST_F(FreeInstallTest, FreeInstall_StartAbilityByFreeInstall_001, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "com.test.demo", "MainAbility");
    want.SetElement(element);
    FreeInstallInfo freeInstallInfo;
    std::string bundleName = "com.test.demo";
    std::string abilityName = "MainAbility";
    std::string startTime = "2024-7-17 00:00:00";
    std::shared_ptr<FreeInstallParams> param = std::make_shared<FreeInstallParams>();
    freeInstallInfo.startOptions = param->startOptions;
    want.SetParam(Want::PARAM_RESV_START_TIME, startTime);
    freeInstallInfo.want = want;
    freeInstallManager_->StartAbilityByFreeInstall(freeInstallInfo, bundleName, abilityName, startTime);
    freeInstallInfo.startOptions = nullptr;
    freeInstallManager_->StartAbilityByFreeInstall(freeInstallInfo, bundleName, abilityName, startTime);
    EXPECT_EQ(freeInstallInfo.isPreStartMissionCalled, false);
}

/**
 * @tc.number: StartAbilityByFreeInstall_002
 * @tc.name: StartAbilityByFreeInstall
 * @tc.desc: Test StartAbilityByFreeInstall.
 */
HWTEST_F(FreeInstallTest, FreeInstall_StartAbilityByFreeInstall_002, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "", "");
    want.SetElement(element);
    FreeInstallInfo freeInstallInfo;
    std::string bundleName = "com.test.demo";
    std::string abilityName = "MainAbility";
    std::string startTime = "2024-7-17 00:00:00";
    want.SetParam(Want::PARAM_RESV_START_TIME, startTime);
    freeInstallInfo.want = want;
    freeInstallManager_->StartAbilityByFreeInstall(freeInstallInfo, bundleName, abilityName, startTime);
    EXPECT_EQ(freeInstallInfo.isPreStartMissionCalled, false);
}

/**
 * @tc.number: StartAbilityByPreInstall_001
 * @tc.name: StartAbilityByPreInstall
 * @tc.desc: Test StartAbilityByPreInstall.
 */
HWTEST_F(FreeInstallTest, FreeInstall_StartAbilityByPreInstall_001, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "com.test.demo", "MainAbility");
    want.SetElement(element);
    FreeInstallInfo freeInstallInfo;
    std::string bundleName = "com.test.demo";
    std::string abilityName = "MainAbility";
    std::string startTime = "2024-7-17 00:00:00";
    std::shared_ptr<FreeInstallParams> param = std::make_shared<FreeInstallParams>();
    freeInstallInfo.startOptions = param->startOptions;
    int32_t recordId = 100;
    want.SetParam(Want::PARAM_RESV_START_TIME, startTime);
    freeInstallInfo.want = want;
    freeInstallInfo.isStartUIAbilityBySCBCalled = true;
    freeInstallInfo.isOpenAtomicServiceShortUrl = true;
    freeInstallManager_->StartAbilityByPreInstall(recordId, freeInstallInfo, bundleName, abilityName, startTime);
    freeInstallInfo.startOptions = nullptr;
    freeInstallManager_->StartAbilityByPreInstall(recordId, freeInstallInfo, bundleName, abilityName, startTime);
    EXPECT_EQ(freeInstallInfo.isPreStartMissionCalled, false);
}

/**
 * @tc.number: StartAbilityByPreInstall_002
 * @tc.name: StartAbilityByPreInstall
 * @tc.desc: Test StartAbilityByPreInstall.
 */
HWTEST_F(FreeInstallTest, FreeInstall_StartAbilityByPreInstall_002, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "", "");
    want.SetElement(element);
    int32_t recordId = 100;
    FreeInstallInfo freeInstallInfo;
    std::string bundleName = "com.test.demo";
    std::string abilityName = "MainAbility";
    std::string startTime = "2024-7-17 00:00:00";
    want.SetParam(Want::PARAM_RESV_START_TIME, startTime);
    freeInstallInfo.want = want;
    freeInstallManager_->StartAbilityByPreInstall(recordId, freeInstallInfo, bundleName, abilityName, startTime);
    EXPECT_EQ(freeInstallInfo.isPreStartMissionCalled, false);
}

/**
 * @tc.number: SetSCBCallStatus_001
 * @tc.name: SetSCBCallStatus
 * @tc.desc: Test SetSCBCallStatus.
 */
HWTEST_F(FreeInstallTest, FreeInstall_SetSCBCallStatus_001, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "com.test.demo", "MainAbility");
    want.SetElement(element);
    std::string bundleName = "com.test.demo";
    std::string abilityName = "MainAbility";
    std::string startTime = "2024-7-17 00:00:00";
    want.SetParam(Want::PARAM_RESV_START_TIME, startTime);
    const int32_t userId = 1;
    const int requestCode = 0;
    FreeInstallInfo info = freeInstallManager_->BuildFreeInstallInfo(want, userId, requestCode, nullptr);
    {
        std::lock_guard<ffrt::mutex> lock(freeInstallManager_->freeInstallListLock_);
        freeInstallManager_->freeInstallList_.push_back(info);
    }
    bool scbCallStatus = true;
    freeInstallManager_->SetSCBCallStatus(bundleName, abilityName, startTime, scbCallStatus);
    EXPECT_EQ(info.isStartUIAbilityBySCBCalled, false);
}

/**
 * @tc.number: SetPreStartMissionCallStatus_001
 * @tc.name: SetPreStartMissionCallStatus
 * @tc.desc: Test SetPreStartMissionCallStatus.
 */
HWTEST_F(FreeInstallTest, FreeInstall_SetPreStartMissionCallStatus_001, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    ElementName element("", "com.test.demo", "MainAbility");
    want.SetElement(element);
    std::string bundleName = "com.test.demo";
    std::string abilityName = "MainAbility";
    std::string startTime = "2024-7-17 00:00:00";
    want.SetParam(Want::PARAM_RESV_START_TIME, startTime);
    const int32_t userId = 1;
    const int requestCode = 0;
    FreeInstallInfo info = freeInstallManager_->BuildFreeInstallInfo(want, userId, requestCode, nullptr);
    {
        std::lock_guard<ffrt::mutex> lock(freeInstallManager_->freeInstallListLock_);
        freeInstallManager_->freeInstallList_.push_back(info);
    }
    bool preStartMissionCallStatus = true;
    freeInstallManager_->SetPreStartMissionCallStatus(bundleName, abilityName, startTime, preStartMissionCallStatus);
    EXPECT_EQ(info.isPreStartMissionCalled, false);
}
}  // namespace AppExecFwk
}  // namespace OHOS