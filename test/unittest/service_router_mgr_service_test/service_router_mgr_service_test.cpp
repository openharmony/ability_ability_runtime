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
#include "service_router_mgr_service.h"
#undef private

#include "hilog_tag_wrapper.h"
#include "hilog_wrapper.h"
#include "ability_manager_errors.h"
#include "accesstoken_kit.h"
#include "tokenid_kit.h"

using namespace testing;
using namespace testing::ext;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace AbilityRuntime {
namespace {
const int RESULT_CODE = 8521225;
}
class ServiceRouterMgrServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
public:
    static std::shared_ptr<ServiceRouterMgrService> serviceRouterMgrService_;
};
void ServiceRouterMgrServiceTest::SetUpTestCase(void)
{}

void ServiceRouterMgrServiceTest::TearDownTestCase(void)
{
    serviceRouterMgrService_->OnStop();
}

void ServiceRouterMgrServiceTest::SetUp()
{
    serviceRouterMgrService_->OnStart();
}

void ServiceRouterMgrServiceTest::TearDown()
{}

std::shared_ptr<ServiceRouterMgrService> ServiceRouterMgrServiceTest::serviceRouterMgrService_ =
    DelayedSingleton<ServiceRouterMgrService>::GetInstance();

/**
 * @tc.name: test StartUIExtensionAbility_001
 * @tc.desc: StartUIExtensionAbility
 */
HWTEST_F(ServiceRouterMgrServiceTest, StartUIExtensionAbility_001, Function | SmallTest | Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "StartUIExtensionAbility_001 start");
    SessionInfo sessionInfo;
    int32_t userId = 1;
    int32_t funcResult = -1;
    serviceRouterMgrService_->StartUIExtensionAbility(sessionInfo, userId, funcResult);
    EXPECT_EQ(funcResult, AAFwk::CHECK_PERMISSION_FAILED);
    TAG_LOGI(AAFwkTag::TEST, "StartUIExtensionAbility_001 result %{public}d", funcResult);
    TAG_LOGI(AAFwkTag::TEST, "StartUIExtensionAbility_001 end");
}

/**
 * @tc.name: test ConnectUIExtensionAbility_001
 * @tc.desc: ConnectUIExtensionAbility
 */
HWTEST_F(ServiceRouterMgrServiceTest, ConnectUIExtensionAbility_001, Function | SmallTest | Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ConnectUIExtensionAbility_001 start");
    Want want;
    sptr<IAbilityConnection> connect = nullptr;
    SessionInfo sessionInfo;
    int32_t userId = 1;
    int32_t funcResult = -1;
    serviceRouterMgrService_->ConnectUIExtensionAbility(want, connect, sessionInfo, userId, funcResult);
    EXPECT_EQ(funcResult, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "ConnectUIExtensionAbility_001 result %{public}d", funcResult);
    TAG_LOGI(AAFwkTag::TEST, "ConnectUIExtensionAbility_001 end");
}

/**
 * @tc.name: test QueryPurposeInfos_001
 * @tc.desc: QueryPurposeInfos
 */
HWTEST_F(ServiceRouterMgrServiceTest, QueryPurposeInfos_001, Function | SmallTest | Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "QueryPurposeInfos_001 start");
    Want want;
    int32_t funcResult = -1;
    std::vector<PurposeInfo> purposeInfos;
    serviceRouterMgrService_->QueryPurposeInfos(want, "", purposeInfos, funcResult);
    EXPECT_EQ(funcResult, RESULT_CODE);
    TAG_LOGI(AAFwkTag::TEST, "QueryPurposeInfos_001 result %{public}d", funcResult);
    TAG_LOGI(AAFwkTag::TEST, "QueryPurposeInfos_001 end");
}

/**
 * @tc.name: test QueryBusinessAbilityInfosInner_001
 * @tc.desc: QueryBusinessAbilityInfosInner
 */
HWTEST_F(ServiceRouterMgrServiceTest, QueryBusinessAbilityInfos_001, Function | SmallTest | Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "QueryBusinessAbilityInfos_001 start");
    BusinessAbilityFilter filter;
    int32_t funcResult = -1;
    filter.businessType = BusinessType::UNSPECIFIED;
    std::vector<BusinessAbilityInfo> abilityInfos;
    serviceRouterMgrService_->QueryBusinessAbilityInfosInner(filter, abilityInfos, funcResult);
    EXPECT_EQ(funcResult, RESULT_CODE);
    TAG_LOGI(AAFwkTag::TEST, "QueryBusinessAbilityInfos_001 result %{public}d", funcResult);
    TAG_LOGI(AAFwkTag::TEST, "QueryBusinessAbilityInfos_001 end");
}

/**
 * @tc.name: test VerifySystemApp_001
 * @tc.desc: VerifySystemApp
 */
HWTEST_F(ServiceRouterMgrServiceTest, VerifySystemApp_001, Function | SmallTest | Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "VerifySystemApp_001 start");
    uint32_t callerToken = 3;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    tokenType = OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE;
    auto ret = serviceRouterMgrService_->VerifySystemApp();
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "VerifySystemApp_001 end");
}

/**
 * @tc.name: test VerifyCallingPermission_001
 * @tc.desc: VerifyCallingPermission
 */
HWTEST_F(ServiceRouterMgrServiceTest, VerifyCallingPermission_001, Function | SmallTest | Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "VerifyCallingPermission_001 start");
    auto ret = serviceRouterMgrService_->VerifyCallingPermission("");
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "VerifyCallingPermission_001 end");
}
}
}
