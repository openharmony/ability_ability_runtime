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

#include "cj_want_agent_utils.h"
#include "cj_want_agent_ffi.h"
#include "context_impl.h"
#include "cj_ability_runtime_error.h"
#include "cj_common_ffi.h"
#include "errors.h"
#include "ffi_remote_data.h"
#include "hilog_tag_wrapper.h"
#include "message_parcel.h"
#include "pending_want.h"
#include "trigger_info.h"
#include "want_agent_helper.h"
#include "want_agent_info.h"
#include "want_agent.h"
#include "want_sender_interface.h"
#include "want_agent_client.h"
#include "want_sender_info.h"
#include "want.h"

#include <memory>
#include <functional>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AbilityRuntime {
class CjWantAgentFfiTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void CjWantAgentFfiTest::SetUpTestCase()
{}
void CjWantAgentFfiTest::TearDownTestCase()
{}
void CjWantAgentFfiTest::SetUp()
{}
void CjWantAgentFfiTest::TearDown()
{}

/**
 * @tc.name: CjWantAgentFfiTestOnGetBundleName_0010
 * @tc.desc: CjWantAgentFfiTest test for OnGetBundleName.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestOnGetBundleName_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnGetBundleName start");
    auto pendingWant = std::make_shared<OHOS::AbilityRuntime::WantAgent::PendingWant>();
    std::shared_ptr<WantAgent::WantAgent> wantAgent = std::make_shared<WantAgent::WantAgent>(pendingWant);
    auto cjWantAgent = std::make_shared<FfiWantAgent::CJWantAgent>(wantAgent);
    int32_t err = -1;
    int32_t *errCode = &err;
    std::string bundleName = cjWantAgent->OnGetBundleName(errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_WANTAGENT);
    EXPECT_EQ(bundleName, "");
    TAG_LOGI(AAFwkTag::TEST, "OnGetBundleName end");
}

/**
 * @tc.name: CjWantAgentFfiTestOnGetUid_0010
 * @tc.desc: CjWantAgentFfiTest test for OnGetUid.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestOnGetUid_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnGetUid start");
    auto pendingWant = std::make_shared<OHOS::AbilityRuntime::WantAgent::PendingWant>();
    std::shared_ptr<WantAgent::WantAgent> wantAgent = std::make_shared<WantAgent::WantAgent>(pendingWant);
    auto cjWantAgent = std::make_shared<FfiWantAgent::CJWantAgent>(wantAgent);
    int err = -2;
    int* errCode = &err;
    int32_t uid = cjWantAgent->OnGetUid(errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_WANTAGENT);
    EXPECT_EQ(uid, -1);
    TAG_LOGI(AAFwkTag::TEST, "OnGetUid end");
}

/**
 * @tc.name: CjWantAgentFfiTestOnCancel_0010
 * @tc.desc: CjWantAgentFfiTest test for OnCancel.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestOnCancel_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnCancel start");
    auto pendingWant = std::make_shared<OHOS::AbilityRuntime::WantAgent::PendingWant>();
    std::shared_ptr<WantAgent::WantAgent> wantAgent = std::make_shared<WantAgent::WantAgent>(pendingWant);
    auto cjWantAgent = std::make_shared<FfiWantAgent::CJWantAgent>(wantAgent);
    int32_t err = -1;
    int32_t *errCode = &err;
    cjWantAgent->OnCancel(errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
    TAG_LOGI(AAFwkTag::TEST, "OnCancel end");
}

/**
 * @tc.name: CjWantAgentFfiTestOnTrigger_0010
 * @tc.desc: CjWantAgentFfiTest test for OnTrigger.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestOnTrigger_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnTrigger start");
    FfiWantAgent::CJTriggerInfo cjtriggerInfo {
        .hasWant = false,
        .extraInfos = strdup("extroinfo"),
        .permission = strdup("Permission"),
        .code = 1
    };
    std::function<void(FfiWantAgent::CJCompleteData)> callback =
        [](FfiWantAgent::CJCompleteData) {};
    auto pendingWant = std::make_shared<OHOS::AbilityRuntime::WantAgent::PendingWant>();
    std::shared_ptr<WantAgent::WantAgent> wantAgent = std::make_shared<WantAgent::WantAgent>(pendingWant);
    auto cjWantAgent = std::make_shared<FfiWantAgent::CJWantAgent>(wantAgent);
    int32_t err = -1;
    int32_t *errCode = &err;
    cjWantAgent->OnTrigger(cjtriggerInfo, callback, errCode);
    EXPECT_EQ(*errCode, NO_ERROR);
    free(cjtriggerInfo.extraInfos);
    free(cjtriggerInfo.permission);
    TAG_LOGI(AAFwkTag::TEST, "OnTrigger end");
}

/**
 * @tc.name: CjWantAgentFfiTestOnGetOperationType_0010
 * @tc.desc: CjWantAgentFfiTest test for OnGetOperationType.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestOnGetOperationType_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnGetOperationType start");
    auto pendingWant = std::make_shared<OHOS::AbilityRuntime::WantAgent::PendingWant>();
    std::shared_ptr<WantAgent::WantAgent> wantAgent = std::make_shared<WantAgent::WantAgent>(pendingWant);
    auto cjWantAgent = std::make_shared<FfiWantAgent::CJWantAgent>(wantAgent);
    int32_t err = -1;
    int32_t *errCode = &err;
    int oprationType = 0;
    *errCode = cjWantAgent->OnGetOperationType(errCode);
    EXPECT_EQ(*errCode, NO_ERROR);
    EXPECT_NE(oprationType, -1);
    TAG_LOGI(AAFwkTag::TEST, "OnGetOperationType end");
}

/**
 * @tc.name: CjWantAgentFfiTestOnEqual_0010
 * @tc.desc: CjWantAgentFfiTest test for OnEqual.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestOnEqual_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnEqual start");
    int32_t err = -1;
    int32_t *errCode = &err;
    auto second = std::make_shared<WantAgent::WantAgent>();
    auto pendingWant = std::make_shared<OHOS::AbilityRuntime::WantAgent::PendingWant>();
    auto wantAgent = std::make_shared<WantAgent::WantAgent>(pendingWant);
    auto cjWantAgent = std::make_shared<FfiWantAgent::CJWantAgent>(wantAgent);
    bool result = cjWantAgent->OnEqual(second, errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
    EXPECT_EQ(result, false);
    TAG_LOGI(AAFwkTag::TEST, "OnEqual end");
}

/**
 * @tc.name: CjWantAgentFfiTestOnSendFinished_0010
 * @tc.desc: CjWantAgentFfiTest test for OnSendFinished.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestOnSendFinished_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnSendFinished start");
    auto cjtriggerCompletecb = std::make_shared<FfiWantAgent::CJTriggerCompleteCallBack>();
    AAFwk::Want want;
    int resultCode = 1;
    std::string resultData = "resultData";
    AAFwk::WantParams resultExtras;
    cjtriggerCompletecb->SetWantAgentInstance(1);
    FfiWantAgent::CJCompleteData mydata;
    auto cb = [&mydata](const FfiWantAgent::CJCompleteData &data) -> void {
        mydata.finalCode = data.finalCode;
    };
    cjtriggerCompletecb->SetCallbackInfo(cb);
    cjtriggerCompletecb->OnSendFinished(want, resultCode, resultData, resultExtras);
    EXPECT_EQ(mydata.finalCode, resultCode);
    TAG_LOGI(AAFwkTag::TEST, "OnSendFinished end");
}

/**
 * @tc.name: CjWantAgentFfiTestFfiWantAgentGetWantAgent_0010
 * @tc.desc: CjWantAgentFfiTest test for FfiWantAgentGetWantAgent.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestFfiWantAgentGetWantAgent_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "FfiWantAgentGetWantAgent start");
    FfiWantAgent::CJWantAgentInfo cjWantAgentInfo{
        .actionFlags = {.head = nullptr, .size = 0},
        .actionType = 1,
        .extraInfos = strdup("extroinfo"),
        .requestCode = 1,
        .wants = {.head = nullptr, .size = 0}
    };
    int32_t err = -1;
    int32_t *errCode = &err;
    int64_t ret = FfiWantAgent::FfiWantAgentGetWantAgent(cjWantAgentInfo, errCode);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
    free(cjWantAgentInfo.extraInfos);
    TAG_LOGI(AAFwkTag::TEST, "FfiWantAgentGetWantAgent end");
}

/**
 * @tc.name: CjWantAgentFfiTestFfiWantAgentGetBoundleName_0010
 * @tc.desc: CjWantAgentFfiTest test for FfiWantAgentGetBoundleName.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestFfiWantAgentGetBoundleName_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "FfiWantAgentGetBoundleName start");
    int64_t cjWantAgent = -1;
    int32_t err = 0;
    int32_t *errCode = &err;
    char* name = FfiWantAgent::FfiWantAgentGetBoundleName(cjWantAgent, errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
    EXPECT_EQ(name, NULL);
    TAG_LOGI(AAFwkTag::TEST, "FfiWantAgentGetBoundleName end");
}

/**
 * @tc.name: CjWantAgentFfiTestFfiWantAgentGetUid
 * @tc.desc: CjWantAgentFfiTest test for FfiWantAgentGetUid.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestFfiWantAgentGetUid_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "FfiWantAgentGetUid start");
    int64_t cjWantAgent = -1;
    int32_t err = 0;
    int32_t *errCode = &err;
    int32_t ret = FfiWantAgent::FfiWantAgentGetUid(cjWantAgent, errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
    EXPECT_EQ(ret, -1);
    TAG_LOGI(AAFwkTag::TEST, "FfiWantAgentGetUid end");
}

/**
 * @tc.name: CjWantAgentFfiTestFfiWantAgentCancel_0010
 * @tc.desc: CjWantAgentFfiTest test for FfiWantAgentCancel.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestFfiWantAgentCancel_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "FfiWantAgentCancel start");
    int64_t cjWantAgent = -1;
    int32_t err = 0;
    int32_t *errCode = &err;
    FfiWantAgent::FfiWantAgentCancel(cjWantAgent, errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
    TAG_LOGI(AAFwkTag::TEST, "FfiWantAgentCancel end");
}

/**
 * @tc.name: CjWantAgentFfiTestFfiWantAgentTrigger_0010
 * @tc.desc: CjWantAgentFfiTest test for FfiWantAgentTrigger.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestFfiWantAgentTrigger_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "FfiWantAgentTrigger start");
    int64_t cjWantAgent = -1;
    int32_t err = -1;
    int32_t *errCode = &err;
    void (*callback)(FfiWantAgent::CJCompleteData) = [](FfiWantAgent::CJCompleteData data){};
    FfiWantAgent::CJTriggerInfo triggerInfo{
        .code = 0,
        .extraInfos = nullptr,
        .hasWant = false,
        .permission = nullptr,
        .want = nullptr
    };
    FfiWantAgent::FfiWantAgentTrigger(cjWantAgent, triggerInfo, callback, errCode);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
    TAG_LOGI(AAFwkTag::TEST, "FfiWantAgentTrigger end");
}

/**
 * @tc.name: CjWantAgentFfiTestFfiWantAgentOnGetOperationType_0010
 * @tc.desc: CjWantAgentFfiTest test for FfiWantAgentOnGetOperationType_0010.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestFfiWantAgentOnGetOperationType_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "FfiWantAgentOnGetOperationType start");
    int64_t cjWantAgent = -1;
    int32_t err = -1;
    int32_t *errCode = &err;
    int32_t ret = FfiWantAgent::FfiWantAgentGetOperationType(cjWantAgent, errCode);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
    TAG_LOGI(AAFwkTag::TEST, "FfiWantAgentOnGetOperationType end");
}

/**
 * @tc.name: CjWantAgentFfiTestFfiWantAgentGetOperationType_0010
 * @tc.desc: CjWantAgentFfiTest test for FfiWantAgentGetOperationType.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestFfiWantAgentGetOperationType_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "FfiWantAgentGetOperationType start");
    ino64_t cjWantAgent = -1;
    int32_t err = -1;
    int32_t *errCode = &err;
    int32_t ret = FfiWantAgent::FfiWantAgentGetOperationType(cjWantAgent, errCode);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
    TAG_LOGI(AAFwkTag::TEST, "FfiWantAgentGetOperationType end");
}

/**
 * @tc.name: CjWantAgentFfiTestFfiWantAgentEqual_0010
 * @tc.desc: CjWantAgentFfiTest test for FfiWantAgentEqual.
 * @tc.type: FUNC
 */
HWTEST_F(CjWantAgentFfiTest, CjWantAgentFfiTestFfiWantAgentEqual_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "FfiTestFfiWantAgentEqual start");
    int64_t cjWantAgent = -1;
    int64_t cjWantAgent2 = -2;
    int32_t err = -1;
    int32_t *errCode = &err;
    bool ret = FfiWantAgent::FfiWantAgentEqual(cjWantAgent, cjWantAgent2, errCode);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(*errCode, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
    TAG_LOGI(AAFwkTag::TEST, "FfiTestFfiWantAgentEqual end");
}

}  // namespace AbilityRuntime
}  // namespace OHOS