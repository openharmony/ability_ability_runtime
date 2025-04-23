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
#include "app_mgr_service_inner.h"
#include "user_record_manager.h"
#include "mock_my_status.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace AppExecFwk {
class AppMgrServiceInnerSeventhTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AppMgrServiceInnerSeventhTest::SetUpTestCase() {}

void AppMgrServiceInnerSeventhTest::TearDownTestCase() {}

void AppMgrServiceInnerSeventhTest::SetUp() {}

void AppMgrServiceInnerSeventhTest::TearDown() {}

/**
 * @tc.name: GetBundleAndHapInfo_001
 * @tc.desc: test GetBundleAndHapInfo_001
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerSeventhTest, GetBundleAndHapInfo_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetBundleAndHapInfo_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    AAFwk::MyStatus::GetInstance().getBundleManagerHelper_ = nullptr;
    AbilityInfo abilityInfo;
    std::shared_ptr<ApplicationInfo> appInfo = std::make_shared<ApplicationInfo>();
    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    int32_t appIndex = 0;
    bool ret = appMgrServiceInner->GetBundleAndHapInfo(abilityInfo, appInfo, bundleInfo, hapModuleInfo, appIndex);
    EXPECT_EQ(ret, false);
    TAG_LOGI(AAFwkTag::TEST, "GetBundleAndHapInfo_001 end");
}

/**
 * @tc.name: GetBundleAndHapInfo_002
 * @tc.desc: test GetBundleAndHapInfo_002
 * @tc.type: FUNC
 */
 HWTEST_F(AppMgrServiceInnerSeventhTest, GetBundleAndHapInfo_002, TestSize.Level1)
 {
     TAG_LOGI(AAFwkTag::TEST, "GetBundleAndHapInfo_002 start");
     auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
     AAFwk::MyStatus::GetInstance().getBundleManagerHelper_ = std::make_shared<BundleMgrHelper>();
     AAFwk::MyStatus::GetInstance().getSandboxBundleInfo_ = ERR_OK;
     AAFwk::MyStatus::GetInstance().getSandboxHapModuleInfo_ = ERR_OK;
     AbilityInfo abilityInfo;
     std::shared_ptr<ApplicationInfo> appInfo = std::make_shared<ApplicationInfo>();
     BundleInfo bundleInfo;
     HapModuleInfo hapModuleInfo;
     int32_t appIndex = 1001;
     bool ret = appMgrServiceInner->GetBundleAndHapInfo(abilityInfo, appInfo, bundleInfo, hapModuleInfo, appIndex);
     EXPECT_EQ(ret, true);
     TAG_LOGI(AAFwkTag::TEST, "GetBundleAndHapInfo_002 end");
 }
} // namespace AppExecFwk
} // namespace OHOS