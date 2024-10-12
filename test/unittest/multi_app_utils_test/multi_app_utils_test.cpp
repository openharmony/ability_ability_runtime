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

#include "hilog_tag_wrapper.h"
#include "app_mgr_util.h"
#include "mock_app_mgr_service.h"
#include "multi_app_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class MultiAppUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void MultiAppUtilsTest::SetUpTestCase(void) {}
void MultiAppUtilsTest::TearDownTestCase(void) {}
void MultiAppUtilsTest::SetUp() {}
void MultiAppUtilsTest::TearDown() {}

/**
 * @tc.name: GetRunningMultiAppIndex_0100
 * @tc.desc: GetRunningMultiAppIndex
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(MultiAppUtilsTest, GetRunningMultiAppIndex_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetRunningMultiAppIndex_0100 start");
    std::string bundleName = "testBundleName";
    int32_t uid = 1000;
    int32_t appIndex = -1;
    auto appMgr = AppMgrUtil::GetAppMgr();
    EXPECT_NE(appMgr, nullptr);

    AppExecFwk::MockAppMgrService::retCode_ = 0;
    AppExecFwk::RunningAppClone appClone = {
        .appCloneIndex = 13,
        .uid = 1000
    };
    std::vector<AppExecFwk::RunningAppClone> appClones = { appClone };
    AppExecFwk::MockAppMgrService::retInfo_.runningAppClones = appClones;
    MultiAppUtils::GetRunningMultiAppIndex(bundleName, uid, appIndex);
    EXPECT_EQ(appIndex, 13);

    TAG_LOGI(AAFwkTag::TEST, "GetRunningMultiAppIndex_0100 end");
}

/**
 * @tc.name: GetRunningMultiAppIndex_0200
 * @tc.desc: GetRunningMultiAppIndex
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(MultiAppUtilsTest, GetRunningMultiAppIndex_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetRunningMultiAppIndex_0200 start");
    std::string bundleName = "testBundleName";
    int32_t uid = 1000;
    int32_t appIndex = -1;
    auto appMgr = AppMgrUtil::GetAppMgr();
    EXPECT_NE(appMgr, nullptr);

    AppExecFwk::MockAppMgrService::retCode_ = -1;
    MultiAppUtils::GetRunningMultiAppIndex(bundleName, uid, appIndex);
    EXPECT_EQ(appIndex, -1);

    TAG_LOGI(AAFwkTag::TEST, "GetRunningMultiAppIndex_0200 end");
}
}  // namespace AAFwk
}  // namespace OHOS
