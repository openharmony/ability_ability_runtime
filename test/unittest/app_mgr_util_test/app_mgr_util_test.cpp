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
#define protected public
#include "app_mgr_util.h"
#undef private
#undef protected
#include "hilog_tag_wrapper.h"
#include "mock_app_mgr_service.h"
#include "mock_my_flag.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
class AppMgrUtilTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: AppMgrUtilTest_GetAppMgr_001
 * @tc.desc: GetAppMgr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppMgrUtilTest, GetAppMgr_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAppMgr_001 start");
    auto mockAppMgr = sptr<AppExecFwk::MockAppMgrService>::MakeSptr();
    ASSERT_NE(mockAppMgr, nullptr);
    AppMgrUtil::appMgr_ = mockAppMgr;
    auto appMgr = AppMgrUtil::GetAppMgr();
    EXPECT_NE(appMgr, nullptr);
    EXPECT_EQ(appMgr->AsObject(), mockAppMgr->AsObject());
    TAG_LOGI(AAFwkTag::TEST, "GetAppMgr_001 end");
}

/**
 * @tc.name: AppMgrUtilTest_GetAppMgr_002
 * @tc.desc: GetAppMgr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppMgrUtilTest, GetAppMgr_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAppMgr_002 start");
    AppMgrUtil::appMgr_ = nullptr;
    MyFlag::systemAbility_ = nullptr;

    auto appMgr = AppMgrUtil::GetAppMgr();
    EXPECT_EQ(appMgr, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetAppMgr_002 end");
}

/**
 * @tc.name: AppMgrUtilTest_GetAppMgr_003
 * @tc.desc: GetAppMgr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppMgrUtilTest, GetAppMgr_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAppMgr_003 start");
    AppMgrUtil::appMgr_ = nullptr;
    MyFlag::systemAbility_ = nullptr;

    auto appMgr = AppMgrUtil::GetAppMgr();
    EXPECT_EQ(appMgr, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetAppMgr_003 end");
}

/**
 * @tc.name: AppMgrUtilTest_GetAppMgr_004
 * @tc.desc: GetAppMgr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppMgrUtilTest, GetAppMgr_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAppMgr_004 start");
    AppMgrUtil::appMgr_ = nullptr;

    auto mockAppMgr = sptr<AppExecFwk::MockAppMgrService>::MakeSptr();
    ASSERT_NE(mockAppMgr, nullptr);
    MyFlag::systemAbility_ = mockAppMgr->AsObject();

    auto appMgr = AppMgrUtil::GetAppMgr();
    EXPECT_NE(appMgr, nullptr);
    EXPECT_EQ(appMgr->AsObject(), mockAppMgr->AsObject());
    TAG_LOGI(AAFwkTag::TEST, "GetAppMgr_004 end");
}
} // namespace AAFwk
} // namespace OHOS
