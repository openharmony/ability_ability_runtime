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
#include <mutex>

#define private public
#include "ability_auto_startup_client.h"
#undef private

#include "refbase.h"

#include "auto_startup_info.h"
#include "if_system_ability_manager.h"
#include "oh_mock_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class AbilityAutoStartupClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AbilityAutoStartupClientTest::SetUpTestCase()
{}

void AbilityAutoStartupClientTest::TearDownTestCase()
{}

void AbilityAutoStartupClientTest::SetUp()
{}

void AbilityAutoStartupClientTest::TearDown()
{
    AAFwk::AbilityAutoStartupClient::instance_ = nullptr;
}

/**
 * @tc.name: GetInstance_001
 * @tc.desc: Verify GetInstance call
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, GetInstance_001, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
}

/**
 * @tc.name: Connect_001
 * @tc.desc: Verify Connect call when proxy is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, Connect_001, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = sptr<AAFwk::IAbilityManager>::MakeSptr();
    EXPECT_EQ(instance->Connect(), ERR_OK);
}

/**
 * @tc.name: Connect_002
 * @tc.desc: Verify Connect call when systemManager is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, Connect_002, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    //mock GetSystemAbilityManager return nullptr
    sptr<ISystemAbilityManager> mgr = nullptr;
    OH_MOCK_METHOD_EXPECT_RET({mgr}, SystemAbilityManagerClient, GetSystemAbilityManager);
    EXPECT_EQ(instance->Connect(), AAFwk::GET_ABILITY_SERVICE_FAILED);
}

/**
 * @tc.name: Connect_003
 * @tc.desc: Verify Connect call when GetSystemAbility is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, Connect_003, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    //mock GetSystemAbilityManager return valid value
    sptr<ISystemAbilityManager> mgr = sptr<ISystemAbilityManager>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({mgr}, SystemAbilityManagerClient, GetSystemAbilityManager);
    sptr<IRemoteObject> obj = nullptr;
    OH_MOCK_METHOD_EXPECT_RET({obj}, ISystemAbilityManager, GetSystemAbility, int32_t);
    EXPECT_EQ(instance->Connect(), AAFwk::GET_ABILITY_SERVICE_FAILED);
}

/**
 * @tc.name: Connect_004
 * @tc.desc: Verify Connect call when IsProxyObject return false AddDeathRecipient return true
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, Connect_004, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    //mock GetSystemAbilityManager return valid value
    sptr<ISystemAbilityManager> mgr = sptr<ISystemAbilityManager>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({mgr}, SystemAbilityManagerClient, GetSystemAbilityManager);
    // mock GetSystemAbility return valid value
    sptr<IRemoteObject> obj = sptr<IRemoteObject>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({obj}, ISystemAbilityManager, GetSystemAbility, int32_t);
    // mock IsProxyObject return false
    OH_MOCK_METHOD_EXPECT_RET({false}, IRemoteObject, IsProxyObject);
    // mock AddDeathRecipient return false
    OH_MOCK_METHOD_EXPECT_RET({true}, IRemoteObject, AddDeathRecipient, const sptr<DeathRecipient> &);
    EXPECT_EQ(instance->Connect(), ERR_OK);
}

/**
 * @tc.name: Connect_005
 * @tc.desc: Verify Connect call when IsProxyObject return false AddDeathRecipient return false
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, Connect_005, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    //mock GetSystemAbilityManager return valid value
    sptr<ISystemAbilityManager> mgr = sptr<ISystemAbilityManager>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({mgr}, SystemAbilityManagerClient, GetSystemAbilityManager);
    // mock GetSystemAbility return valid value
    sptr<IRemoteObject> obj = sptr<IRemoteObject>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({obj}, ISystemAbilityManager, GetSystemAbility, int32_t);
    // mock IsProxyObject return false
    OH_MOCK_METHOD_EXPECT_RET({false}, IRemoteObject, IsProxyObject);
    // mock AddDeathRecipient return false
    OH_MOCK_METHOD_EXPECT_RET({false}, IRemoteObject, AddDeathRecipient, const sptr<DeathRecipient> &);
    EXPECT_EQ(instance->Connect(), ERR_OK);
}

/**
 * @tc.name: Connect_006
 * @tc.desc: Verify Connect call when IsProxyObject return true AddDeathRecipient return false
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, Connect_006, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    //mock GetSystemAbilityManager return valid value
    sptr<ISystemAbilityManager> mgr = sptr<ISystemAbilityManager>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({mgr}, SystemAbilityManagerClient, GetSystemAbilityManager);
    // mock GetSystemAbility return valid value
    sptr<IRemoteObject> obj = sptr<IRemoteObject>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({obj}, ISystemAbilityManager, GetSystemAbility, int32_t);
    // mock IsProxyObject return true
    OH_MOCK_METHOD_EXPECT_RET({true}, IRemoteObject, IsProxyObject);
    // mock AddDeathRecipient return false
    OH_MOCK_METHOD_EXPECT_RET({false}, IRemoteObject, AddDeathRecipient, const sptr<DeathRecipient> &);
    EXPECT_EQ(instance->Connect(), AAFwk::GET_ABILITY_SERVICE_FAILED);
}

/**
 * @tc.name: Connect_007
 * @tc.desc: Verify Connect call when IsProxyObject return true AddDeathRecipient return true
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, Connect_007, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    //mock GetSystemAbilityManager return valid value
    sptr<ISystemAbilityManager> mgr = sptr<ISystemAbilityManager>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({mgr}, SystemAbilityManagerClient, GetSystemAbilityManager);
    // mock GetSystemAbility return valid value
    sptr<IRemoteObject> obj = sptr<IRemoteObject>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({obj}, ISystemAbilityManager, GetSystemAbility, int32_t);
    // mock IsProxyObject return false
    OH_MOCK_METHOD_EXPECT_RET({true}, IRemoteObject, IsProxyObject);
    // mock AddDeathRecipient return false
    OH_MOCK_METHOD_EXPECT_RET({true}, IRemoteObject, AddDeathRecipient, const sptr<DeathRecipient> &);
    EXPECT_EQ(instance->Connect(), ERR_OK);
}

/**
 * @tc.name: SetApplicationAutoStartupByEDM_001
 * @tc.desc: Verify SetApplicationAutoStartupByEDM call when GetAbilityManager valid
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, SetApplicationAutoStartupByEDM_001, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = sptr<AAFwk::IAbilityManager>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({0}, IAbilityManager, SetApplicationAutoStartupByEDM,
        const AbilityRuntime::AutoStartupInfo &, bool);
    AbilityRuntime::AutoStartupInfo info;
    bool flag = false;
    EXPECT_EQ(instance->SetApplicationAutoStartupByEDM(info, flag), ERR_OK);
}

/**
 * @tc.name: SetApplicationAutoStartupByEDM_002
 * @tc.desc: Verify SetApplicationAutoStartupByEDM call when GetAbilityManager nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, SetApplicationAutoStartupByEDM_002, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = nullptr;
    AbilityRuntime::AutoStartupInfo info;
    bool flag = false;
    EXPECT_EQ(instance->SetApplicationAutoStartupByEDM(info, flag), AAFwk::ABILITY_SERVICE_NOT_CONNECTED);
}

/**
 * @tc.name: CancelApplicationAutoStartupByEDM_001
 * @tc.desc: Verify SetApplicationAutoStartupByEDM call when GetAbilityManager valid
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, CancelApplicationAutoStartupByEDM_001, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = sptr<AAFwk::IAbilityManager>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({0}, IAbilityManager, CancelApplicationAutoStartupByEDM,
        const AbilityRuntime::AutoStartupInfo &, bool);
    AbilityRuntime::AutoStartupInfo info;
    bool flag = false;
    EXPECT_EQ(instance->CancelApplicationAutoStartupByEDM(info, flag), ERR_OK);
}

/**
 * @tc.name: CancelApplicationAutoStartupByEDM_002
 * @tc.desc: Verify CancelApplicationAutoStartupByEDM call when GetAbilityManager nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, CancelApplicationAutoStartupByEDM_002, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = nullptr;
    AbilityRuntime::AutoStartupInfo info;
    bool flag = false;
    EXPECT_EQ(instance->CancelApplicationAutoStartupByEDM(info, flag), AAFwk::ABILITY_SERVICE_NOT_CONNECTED);
}

/**
 * @tc.name: QueryAllAutoStartupApplications_001
 * @tc.desc: Verify QueryAllAutoStartupApplications call when GetAbilityManager valid
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, QueryAllAutoStartupApplications_001, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = sptr<AAFwk::IAbilityManager>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({0}, IAbilityManager, QueryAllAutoStartupApplications,
        const AbilityRuntime::AutoStartupInfo &, bool);
    std::vector<AbilityRuntime::AutoStartupInfo> infoList;
    EXPECT_EQ(instance->QueryAllAutoStartupApplications(infoList), ERR_OK);
}

/**
 * @tc.name: QueryAllAutoStartupApplications_002
 * @tc.desc: Verify QueryAllAutoStartupApplications call when GetAbilityManager nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, QueryAllAutoStartupApplications_002, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = nullptr;
    std::vector<AbilityRuntime::AutoStartupInfo> infoList;
    EXPECT_EQ(instance->QueryAllAutoStartupApplications(infoList), AAFwk::ABILITY_SERVICE_NOT_CONNECTED);
}

/**
 * @tc.name: GetAbilityManager_001
 * @tc.desc: Verify GetAbilityManager call when proxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, GetAbilityManager_001, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = nullptr;

    // mock connect return valid proxy
    // mock GetSystemAbilityManager return valid value
    sptr<ISystemAbilityManager> mgr = sptr<ISystemAbilityManager>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({mgr}, SystemAbilityManagerClient, GetSystemAbilityManager);
    // mock GetSystemAbility return valid value
    sptr<IRemoteObject> obj = sptr<IRemoteObject>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({obj}, ISystemAbilityManager, GetSystemAbility, int32_t);
    // mock IsProxyObject return false
    OH_MOCK_METHOD_EXPECT_RET({true}, IRemoteObject, IsProxyObject);
    // mock AddDeathRecipient return false
    OH_MOCK_METHOD_EXPECT_RET({true}, IRemoteObject, AddDeathRecipient, const sptr<DeathRecipient> &);
    // mock iface_cast return nullptr
    sptr<AAFwk::IAbilityManager> obj1 = sptr<AAFwk::IAbilityManager>::MakeSptr();
    OH_MOCK_GLOBAL_METHOD_EXPECT_RET({obj1}, iface_cast, const sptr<IRemoteObject> &);
    EXPECT_EQ(instance->Connect(), ERR_OK);

    EXPECT_EQ(instance->GetAbilityManager(), obj1);
}

/**
 * @tc.name: GetAbilityManager_002
 * @tc.desc: Verify GetAbilityManager call when proxy not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, GetAbilityManager_002, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = sptr<AAFwk::IAbilityManager>::MakeSptr();
    EXPECT_EQ(instance->GetAbilityManager(), instance->proxy_);
}

/**
 * @tc.name: ResetProxy_001
 * @tc.desc: Verify ResetProxy call when proxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, ResetProxy_001, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = nullptr;
    instance->ResetProxy(nullptr);
    EXPECT_EQ(instance->proxy_, nullptr);
}

/**
 * @tc.name: ResetProxy_002
 * @tc.desc: Verify ResetProxy call when as object is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, ResetProxy_002, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = sptr<AAFwk::IAbilityManager>::MakeSptr();
    EXPECT_NE(instance->proxy_, nullptr);
    sptr<IRemoteObject> obj = nullptr;
    OH_MOCK_METHOD_EXPECT_RET({obj}, IRemoteBroker, AsObject);
    instance->ResetProxy(nullptr);
    EXPECT_NE(instance->proxy_, nullptr);
}

/**
 * @tc.name: ResetProxy_003
 * @tc.desc: Verify ResetProxy call when serviceRemote != remote.promote()
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, ResetProxy_003, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = sptr<AAFwk::IAbilityManager>::MakeSptr();
    EXPECT_NE(instance->proxy_, nullptr);
    sptr<IRemoteObject> obj = sptr<IRemoteObject>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({obj}, IRemoteBroker, AsObject);
    instance->ResetProxy(nullptr);
    EXPECT_NE(instance->proxy_, nullptr);
}

/**
 * @tc.name: ResetProxy_004
 * @tc.desc: Verify ResetProxy call when serviceRemote != remote.promote()
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, ResetProxy_004, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = sptr<AAFwk::IAbilityManager>::MakeSptr();
    EXPECT_NE(instance->proxy_, nullptr);
    sptr<IRemoteObject> obj = nullptr;
    OH_MOCK_METHOD_EXPECT_RET({obj}, IRemoteBroker, AsObject);
    sptr<IRemoteObject> obj1 = sptr<IRemoteObject>::MakeSptr();
    wptr<IRemoteObject> remote = obj1;
    instance->ResetProxy(remote);
    EXPECT_NE(instance->proxy_, nullptr);
}

/**
 * @tc.name: ResetProxy_005
 * @tc.desc: Verify ResetProxy call when serviceRemote != remote.promote()
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, ResetProxy_005, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = sptr<AAFwk::IAbilityManager>::MakeSptr();
    EXPECT_NE(instance->proxy_, nullptr);
    sptr<IRemoteObject> obj = sptr<IRemoteObject>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({obj}, IRemoteBroker, AsObject);
    sptr<IRemoteObject> obj1 = sptr<IRemoteObject>();
    wptr<IRemoteObject> remote = obj1;
    instance->ResetProxy(remote);
    EXPECT_NE(instance->proxy_, nullptr);
}

/**
 * @tc.name: ResetProxy_006
 * @tc.desc: Verify ResetProxy call when serviceRemote == remote.promote()
 * @tc.type: FUNC
 */
HWTEST_F(AbilityAutoStartupClientTest, ResetProxy_006, TestSize.Level1)
{
    EXPECT_EQ(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    std::shared_ptr<AAFwk::AbilityAutoStartupClient> instance = AAFwk::AbilityAutoStartupClient::GetInstance();
    EXPECT_NE(AAFwk::AbilityAutoStartupClient::instance_, nullptr);
    instance->proxy_ = sptr<AAFwk::IAbilityManager>::MakeSptr();
    EXPECT_NE(instance->proxy_, nullptr);
    sptr<IRemoteObject> obj = sptr<IRemoteObject>::MakeSptr();
    OH_MOCK_METHOD_EXPECT_RET({obj}, IRemoteBroker, AsObject);
    wptr<IRemoteObject> wObj = obj;
    instance->ResetProxy(wObj);
    EXPECT_EQ(instance->proxy_, nullptr);
}
} // namespace AppExecFwk
} // namespace OHOS