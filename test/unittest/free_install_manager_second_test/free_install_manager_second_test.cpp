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
#include "ability_manager_service.h"
#include "task_handler_wrap.h"
#undef private

#include "ability_record.h"
#include "sa_mgr_client.h"
#include "string_wrapper.h"
#include "int_wrapper.h"

using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace AppExecFwk {
namespace {
const int BUNDLE_MGR_SERVICE_SYS_ABILITY_ID = 401;
}
class FreeInstallManagerSecondTest : public testing::Test {
public:
    FreeInstallManagerSecondTest()
    {}
    ~FreeInstallManagerSecondTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    sptr<Token> MockToken();
    std::shared_ptr<FreeInstallManager> freeInstallManager_ = nullptr;
};

void FreeInstallManagerSecondTest::SetUpTestCase(void) {}

void FreeInstallManagerSecondTest::TearDownTestCase(void) {}

void FreeInstallManagerSecondTest::SetUp(void) {}

void FreeInstallManagerSecondTest::TearDown(void) {}

sptr<Token> FreeInstallManagerSecondTest::MockToken()
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
 * @tc.number: GetFreeInstallTaskInfo_001
 * @tc.name: GetFreeInstallTaskInfo
 * @tc.desc: Test GetFreeInstallTaskInfo.
 */
HWTEST_F(FreeInstallManagerSecondTest, GetFreeInstallTaskInfo_001, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    const std::string bundleName("com.test.demo");
    std::string abilityName("MainAbility");
    const std::string startTime = "startTime";
    FreeInstallInfo taskInfo;
    FreeInstallInfo info;
    ElementName element("", "com.test.demo", "MainAbility");
    info.want.SetElement(element);
    sptr<OHOS::AAFwk::IInterface> iInterface = String::Box("startTime");
    info.want.parameters_.SetParam(Want::PARAM_RESV_START_TIME, iInterface);
    freeInstallManager_->freeInstallList_.push_back(info);
    bool ret = freeInstallManager_->GetFreeInstallTaskInfo(bundleName, abilityName, startTime, taskInfo);
    EXPECT_TRUE(ret);

    ret = freeInstallManager_->GetFreeInstallTaskInfo("", abilityName, startTime, taskInfo);
    EXPECT_FALSE(ret);

    ret = freeInstallManager_->GetFreeInstallTaskInfo(bundleName, "", startTime, taskInfo);
    EXPECT_FALSE(ret);

    ret = freeInstallManager_->GetFreeInstallTaskInfo(bundleName, abilityName, "", taskInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SetSCBCallStatus_001
 * @tc.name: SetSCBCallStatus
 * @tc.desc: Test GetFreeInstallTaskInfo.
 */
HWTEST_F(FreeInstallManagerSecondTest, SetSCBCallStatus_001, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    const std::string bundleName("com.test.demo");
    std::string abilityName("MainAbility");
    const std::string startTime = "startTime";
    bool scbCallStatus = true;

    FreeInstallInfo info;
    ElementName element("", "com.test.demo", "MainAbility");
    info.want.SetElement(element);
    sptr<OHOS::AAFwk::IInterface> iInterface = String::Box("startTime");
    info.want.parameters_.SetParam(Want::PARAM_RESV_START_TIME, iInterface);
    freeInstallManager_->freeInstallList_.push_back(info);

    freeInstallManager_->SetSCBCallStatus("", abilityName, startTime, scbCallStatus);
    EXPECT_FALSE(info.isStartUIAbilityBySCBCalled);

    freeInstallManager_->SetSCBCallStatus(bundleName, "", startTime, scbCallStatus);
    EXPECT_FALSE(info.isStartUIAbilityBySCBCalled);

    freeInstallManager_->SetSCBCallStatus(bundleName, abilityName, "", scbCallStatus);
    EXPECT_FALSE(info.isStartUIAbilityBySCBCalled);

    freeInstallManager_->SetSCBCallStatus(bundleName, abilityName, startTime, scbCallStatus);
    FreeInstallInfo infoRet;
    EXPECT_TRUE(freeInstallManager_->GetFreeInstallTaskInfo(bundleName, abilityName, startTime, infoRet));
    EXPECT_TRUE(infoRet.isStartUIAbilityBySCBCalled);
}

/**
 * @tc.number: NotifyInsightIntentFreeInstallResult_001
 * @tc.name: NotifyInsightIntentFreeInstallResult
 * @tc.desc: Test NotifyInsightIntentFreeInstallResult.
 */
HWTEST_F(FreeInstallManagerSecondTest, NotifyInsightIntentFreeInstallResult_001, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    Want want;
    int32_t resultCode = ERR_OK + 1;
    //resultCode != ERR_OK and freeInstallList_ is NULL
    want.SetParam("ohos.insightIntent.executeParam.id", std::string("0"));
    freeInstallManager_->NotifyInsightIntentFreeInstallResult(want, resultCode);
    EXPECT_EQ(freeInstallManager_->freeInstallList_.size(), 0);

    resultCode = ERR_OK;
    freeInstallManager_->NotifyInsightIntentFreeInstallResult(want, resultCode);
    EXPECT_EQ(freeInstallManager_->freeInstallList_.size(), 0);

    ElementName element("", "com.test.demo", "MainAbility");
    want.SetElement(element);
    sptr<OHOS::AAFwk::IInterface> iInterface = String::Box("startTime");
    want.parameters_.SetParam(Want::PARAM_RESV_START_TIME, iInterface);
    want.parameters_.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_NAME, iInterface);
    want.parameters_.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_MODE, iInterface);
    FreeInstallInfo info;
    ElementName element2("", "com.test.demo2", "MainAbility2");
    info.want.SetElement(element2);
    info.want.parameters_.SetParam(Want::PARAM_RESV_START_TIME, iInterface);
    freeInstallManager_->freeInstallList_.push_back(info);
    freeInstallManager_->NotifyInsightIntentFreeInstallResult(want, resultCode);
    EXPECT_EQ(freeInstallManager_->freeInstallList_.size(), 1);
   
    ElementName element3("", "com.test.demo", "MainAbility2");
    info.want.SetElement(element3);
    iInterface = String::Box("startTime2");
    info.want.parameters_.SetParam(Want::PARAM_RESV_START_TIME, iInterface);
    freeInstallManager_->freeInstallList_.clear();
    freeInstallManager_->freeInstallList_.push_back(info);
    freeInstallManager_->NotifyInsightIntentFreeInstallResult(want, resultCode);
    EXPECT_EQ(freeInstallManager_->freeInstallList_.size(), 1);

    ElementName element4("", "com.test.demo", "MainAbility");
    info.want.SetElement(element4);
    iInterface = String::Box("startTime");
    info.want.parameters_.SetParam(Want::PARAM_RESV_START_TIME, iInterface);
    freeInstallManager_->freeInstallList_.clear();
    freeInstallManager_->freeInstallList_.push_back(info);
    freeInstallManager_->NotifyInsightIntentFreeInstallResult(want, resultCode);
    EXPECT_EQ(freeInstallManager_->freeInstallList_.size(), 0);

    ElementName element5("", "com.test.demo", "MainAbility", "modename");
    info.want.SetElement(element5);
    iInterface = String::Box("startTime");
    info.want.parameters_.SetParam(Want::PARAM_RESV_START_TIME, iInterface);
    info.want.parameters_.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_NAME, iInterface);
    iInterface = Integer::Box(1);
    info.want.parameters_.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_MODE, iInterface);
    freeInstallManager_->freeInstallList_.clear();
    freeInstallManager_->freeInstallList_.push_back(info);
    freeInstallManager_->NotifyInsightIntentFreeInstallResult(want, resultCode);
    EXPECT_EQ(freeInstallManager_->freeInstallList_.size(), 0);
}
}  // namespace AppExecFwk
}  // namespace OHOS