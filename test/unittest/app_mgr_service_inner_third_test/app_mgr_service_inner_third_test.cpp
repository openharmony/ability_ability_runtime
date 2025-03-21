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
#include "ams_configuration_parameter.h"
#include "app_mgr_service_inner.h"
#undef private

#include "app_spawn_client.h"
#include "app_utils.h"
#include "bundle_mgr_helper.h"
#include "hilog_tag_wrapper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace AAFwk {
namespace {
constexpr int8_t DEFAULT_USERID = 0;
const std::string START_MSG_BUNDLE_NAME = "com.test.bundle";
const std::string START_MSG_BUNDLE_NAME2 = "com.test.bundle1";
const std::string START_MSG_BUNDLE_NAME3 = "com.test.bundle2";
}  // namespace
class AppMgrServiceInnerThirdTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AppMgrServiceInnerThirdTest::SetUpTestCase() {}

void AppMgrServiceInnerThirdTest::TearDownTestCase() {}

void AppMgrServiceInnerThirdTest::SetUp() {}

void AppMgrServiceInnerThirdTest::TearDown() {}

/**
 * @tc.name: SetStartMsgCustomSandboxFlag_001
 * @tc.type: FUNC
 * @tc.Function: SetStartMsgCustomSandboxFlag
 * @tc.SubFunction: NA
 * @tc.EnvConditions: NA
 */
HWTEST_F(AppMgrServiceInnerThirdTest, SetStartMsgCustomSandboxFlag_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerThirdTest SetStartMsgCustomSandboxFlag_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    AppSpawnStartMsg startMsg;
    startMsg.bundleName = START_MSG_BUNDLE_NAME;
    appMgrServiceInner->SetStartMsgCustomSandboxFlag(startMsg, DEFAULT_USERID);
    EXPECT_FALSE(startMsg.isCustomSandboxFlag);

    AmsConfigurationParameter::GetInstance().supportCustomSandbox_ = true;
    appMgrServiceInner->SetStartMsgCustomSandboxFlag(startMsg, DEFAULT_USERID);
    EXPECT_FALSE(startMsg.isCustomSandboxFlag);

    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);
    appMgrServiceInner->remoteClientManager_ = nullptr;
    appMgrServiceInner->SetStartMsgCustomSandboxFlag(startMsg, DEFAULT_USERID);
    EXPECT_FALSE(startMsg.isCustomSandboxFlag);

    appMgrServiceInner->remoteClientManager_ = std::make_shared<RemoteClientManager>();
    EXPECT_NE(appMgrServiceInner->remoteClientManager_, nullptr);
    appMgrServiceInner->SetStartMsgCustomSandboxFlag(startMsg, DEFAULT_USERID);
    EXPECT_FALSE(startMsg.isCustomSandboxFlag);

    startMsg.bundleName = START_MSG_BUNDLE_NAME2;
    appMgrServiceInner->SetStartMsgCustomSandboxFlag(startMsg, DEFAULT_USERID);
    EXPECT_TRUE(startMsg.isCustomSandboxFlag);

    AppSpawnStartMsg startMsg1;
    startMsg1.bundleName = START_MSG_BUNDLE_NAME3;
    appMgrServiceInner->SetStartMsgCustomSandboxFlag(startMsg1, DEFAULT_USERID);
    EXPECT_FALSE(startMsg1.isCustomSandboxFlag);
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceInnerThirdTest SetStartMsgCustomSandboxFlag_001 end");
}
}  // namespace AAFwk
}  // namespace OHOS
