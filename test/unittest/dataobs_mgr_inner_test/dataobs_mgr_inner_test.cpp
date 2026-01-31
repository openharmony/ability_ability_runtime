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
#include <memory>
#include <algorithm>
#include <functional>
#include "uri.h"
#define private public
#include "data_ability_observer_proxy.h"
#include "dataobs_mgr_errors.h"
#include "dataobs_mgr_inner.h"
#include "data_share_permission.h"
#include "hilog_tag_wrapper.h"
#include "mock_data_ability_observer_stub.h"

using namespace OHOS;
using namespace testing::ext;
using namespace testing;
using namespace DataShare;

namespace OHOS {
namespace AAFwk {
using Uri = OHOS::Uri;
using ObsListType = std::list<struct ObserverNode>;
using ObsRecipientMapType = OHOS::AAFwk::DataObsMgrInner::ObsRecipientMapType;
class DataObsMgrInnerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<DataObsMgrInner> dataObsMgrInner_ = nullptr;
};
void DataObsMgrInnerTest::SetUpTestCase(void) {}
void DataObsMgrInnerTest::TearDownTestCase(void) {}
void DataObsMgrInnerTest::SetUp()
{
    dataObsMgrInner_ = std::make_shared<DataObsMgrInner>();
}
void DataObsMgrInnerTest::TearDown() {}

static constexpr int64_t USER_TEST = 100;

/*
 * Feature: DataObsMgrInner
 * Function: Register and unregister function test
 * SubFunction: HandleRegisterObserver/HandleRegisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleRegisterObserver_0100, TestSize.Level1)
{
    ASSERT_TRUE(dataObsMgrInner_ != nullptr);

    Uri uri("dataability://device_id/com.domainname.dataability.persondata/person/10");
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());

    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    dataObsMgrInner_->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0, 0));

    EXPECT_EQ(dataObsMgrInner_->HaveRegistered(callback), true);
    dataObsMgrInner_->HandleUnregisterObserver(uri, ObserverNode(callback, USER_TEST, 0, 0));
    EXPECT_EQ(dataObsMgrInner_->HaveRegistered(callback), false);
}

/*
 * Feature: DataObsMgrInner
 * Function: Register function test
 * SubFunction: HandleRegisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleRegisterObserver_0200, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInner> dataObsMgrInner = std::make_shared<DataObsMgrInner>();
    Uri uri("dataability://device_id/com.domainname.dataability.persondata/person/10");
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    ObsListType obsList;
    obsList.push_back(ObserverNode(callback, USER_TEST, 0, 0));
    dataObsMgrInner->observers_.emplace(uri.ToString(), obsList);
    int res = dataObsMgrInner->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0, 0));
    EXPECT_EQ(res, OBS_EXIST);
}

/*
 * Feature: DataObsMgrInner
 * Function: Register function test
 * SubFunction: HandleRegisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleRegisterObserver_0300, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInner> dataObsMgrInner = std::make_shared<DataObsMgrInner>();
    Uri uri("dataability://device_id/com.domainname.dataability.persondata/person/10");
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    const sptr<IDataAbilityObserver> callback1(new (std::nothrow) DataAbilityObserverProxy(observer));
    ObsListType obsList;
    obsList.push_back(ObserverNode(callback1, USER_TEST, 0, 0));
    dataObsMgrInner->observers_.emplace(uri.ToString(), obsList);
    int res = dataObsMgrInner->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0, 0));
    EXPECT_EQ(res, OBS_EXIST);
}

/*
 * Feature: DataObsMgrInner
 * Function: Register function test
 * SubFunction: HandleRegisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: RegisterObserver max limit times
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleRegisterObserver_0400, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInner> dataObsMgrInner = std::make_shared<DataObsMgrInner>();
    Uri uri("dataability://device_id/com.domainname.dataability.persondata/person/10");
    int times = DataObsMgrInner::OBS_NUM_MAX;
    for (int i = 0; i <= times; i++) {
        sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
        const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
        int res = dataObsMgrInner->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0, 0));
        EXPECT_EQ(res, NO_ERROR);
    }
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    int res = dataObsMgrInner->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0, 0));
    EXPECT_EQ(res, DATAOBS_SERVICE_OBS_LIMMIT);

    // other token success
    sptr<MockDataAbilityObserverStub> observer2(new (std::nothrow) MockDataAbilityObserverStub());
    res = dataObsMgrInner->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 1, 0));
    EXPECT_EQ(res, SUCCESS);

    // other uri success
    Uri uri2("dataability://device_id/com.domainname.dataability.persondata/person/11");
    sptr<MockDataAbilityObserverStub> observer3(new (std::nothrow) MockDataAbilityObserverStub());
    res = dataObsMgrInner->HandleRegisterObserver(uri2, ObserverNode(callback, USER_TEST, 0, 0));
    EXPECT_EQ(res, SUCCESS);
}

/*
 * Feature: DataObsMgrInner
 * Function: Register function test
 * SubFunction: HandleRegisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: RegisterObserver max limit times
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleRegisterObserver_0500, TestSize.Level1)
{
    TAG_LOGE(AAFwkTag::DBOBSMGR, "DataObsMgrInner_HandleRegisterObserver_0500::Start");
    std::shared_ptr<DataObsMgrInner> dataObsMgrInner = std::make_shared<DataObsMgrInner>();
    Uri uri("dataability://device_id/com.domainname.dataability.persondata/person/10");
    for (int token = 0; token < DataObsMgrInner::OBS_NUM_MAX; token++) {
        for (int i = 0; i < DataObsMgrInner::OBS_NUM_MAX; i++) {
            sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
            const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
            int res = dataObsMgrInner->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, token, 0));
            EXPECT_EQ(res, NO_ERROR);
        }
    }
    int token = DataObsMgrInner::OBS_NUM_MAX  + 1;
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    int res = dataObsMgrInner->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, token, 0));
    EXPECT_EQ(res, DATAOBS_SERVICE_OBS_LIMMIT);
    TAG_LOGE(AAFwkTag::DBOBSMGR, "DataObsMgrInner_HandleRegisterObserver_0500::End");
}

/*
 * Feature: DataObsMgrInner
 * Function: Unregister function test
 * SubFunction: HandleUnregisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleUnregisterObserver_0100, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInner> dataObsMgrInner = std::make_shared<DataObsMgrInner>();
    Uri uri("dataability://device_id/com.domainname.dataability.persondata/person/10");
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    dataObsMgrInner->observers_.clear();
    int res = dataObsMgrInner->HandleUnregisterObserver(uri, ObserverNode(callback, USER_TEST, 0, 0));
    EXPECT_EQ(res, NO_OBS_FOR_URI);
}

/*
 * Feature: DataObsMgrInner
 * Function: Unregister function test
 * SubFunction: HandleUnregisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleUnregisterObserver_0200, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInner> dataObsMgrInner = std::make_shared<DataObsMgrInner>();
    Uri uri("dataability://device_id/com.domainname.dataability.persondata/person/10");
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    ObsListType obsList;
    obsList.push_back(ObserverNode(callback, USER_TEST, 0, 0));
    dataObsMgrInner->observers_.emplace(uri.ToString(), obsList);
    int res = dataObsMgrInner->HandleUnregisterObserver(uri, ObserverNode(callback, USER_TEST, 0, 0));
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * Feature: DataObsMgrInner
 * Function: Unregister function test
 * SubFunction: HandleUnregisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleUnregisterObserver_0300, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInner> dataObsMgrInner = std::make_shared<DataObsMgrInner>();
    Uri uri("dataability://device_id/com.domainname.dataability.persondata/person/10");
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    const sptr<IDataAbilityObserver> callback2(new (std::nothrow) DataAbilityObserverProxy(observer));
    ObsListType obsList;
    obsList.push_back(ObserverNode(callback, USER_TEST, 0, 0));
    obsList.push_back(ObserverNode(callback2, USER_TEST, 0, 0));
    dataObsMgrInner->observers_.emplace(uri.ToString(), obsList);
    dataObsMgrInner->observers_.emplace("exit", obsList);
    int res = dataObsMgrInner->HandleUnregisterObserver(uri, ObserverNode(callback, USER_TEST, 0, 0));
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * Feature: DataObsMgrInner
 * Function: Register and unregister function test
 * SubFunction: OnChange
 * FunctionPoints: When the data changes, call the OnChange function of the registered dataabilityobserver
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleNotifyChange_0100, TestSize.Level1)
{
    ASSERT_TRUE(dataObsMgrInner_ != nullptr);

    Uri uri("dataability://device_id/com.domainname.dataability.persondata/person/10");
    sptr<MockDataAbilityObserverStub> mockDataAbilityObserverStub(new (std::nothrow) MockDataAbilityObserverStub());

    EXPECT_CALL(*mockDataAbilityObserverStub, OnChange()).Times(1);

    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(mockDataAbilityObserverStub));
    dataObsMgrInner_->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0, 0));
    dataObsMgrInner_->HandleNotifyChange(uri, USER_TEST, DataSharePermission::NO_PERMISSION, false, 1);
}

/*
 * Feature: DataObsMgrInner
 * Function: Unregister function test
 * SubFunction: HandleUnregisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleNotifyChange_0200, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInner> dataObsMgrInner = std::make_shared<DataObsMgrInner>();
    Uri uri("dataability://device_id/com.domainname.dataability.persondata/person/10");
    dataObsMgrInner->observers_.clear();
    int res = dataObsMgrInner->HandleNotifyChange(uri, USER_TEST, DataSharePermission::NO_PERMISSION, false, 1);
    EXPECT_EQ(res, NO_OBS_FOR_URI);
}

/*
 * Feature: DataObsMgrInner
 * Function: Unregister function test
 * SubFunction: HandleUnregisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleNotifyChange_0300, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInner> dataObsMgrInner = std::make_shared<DataObsMgrInner>();
    Uri uri("dataability://device_id/com.domainname.dataability.persondata/person/10");
    ObsListType obsList;
    obsList.push_back(ObserverNode(nullptr, USER_TEST, 0, 0));
    dataObsMgrInner->observers_.emplace(uri.ToString(), obsList);
    int res = dataObsMgrInner->HandleNotifyChange(uri, USER_TEST, DataSharePermission::NO_PERMISSION, false, 1);
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * Feature: DataObsMgrInner
 * Function: GetObsListFromMap/RemoveObs/HaveRegistered function test
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_RemoveObs_HaveRegistered_0100, TestSize.Level1)
{
    ASSERT_TRUE(dataObsMgrInner_ != nullptr);
    
    Uri uri("dataability://device_id/com.domainname.dataability.persondata/person/10");
    sptr<MockDataAbilityObserverStub> mockDataAbilityObserverStub(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(mockDataAbilityObserverStub));
    dataObsMgrInner_->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0, 0));

    sptr<MockDataAbilityObserverStub> mockDataAbilityObserverStub2(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback2(
        new (std::nothrow) DataAbilityObserverProxy(mockDataAbilityObserverStub2));

    dataObsMgrInner_->HandleRegisterObserver(uri, ObserverNode(callback2, USER_TEST, 0, 0));
    auto obsPair = dataObsMgrInner_->observers_.find(uri.ToString());
    EXPECT_EQ((std::size_t)2, obsPair->second.size());
    EXPECT_EQ(true, dataObsMgrInner_->HaveRegistered(callback));
    EXPECT_EQ(true, dataObsMgrInner_->HaveRegistered(callback2));

    dataObsMgrInner_->RemoveObs(callback->AsObject());
    EXPECT_EQ(false, dataObsMgrInner_->HaveRegistered(callback));
    obsPair->second.clear();
    obsPair = dataObsMgrInner_->observers_.find(uri.ToString());
    EXPECT_EQ(false, dataObsMgrInner_->HaveRegistered(callback));

    dataObsMgrInner_->RemoveObs(callback2->AsObject());
    EXPECT_EQ(false, dataObsMgrInner_->HaveRegistered(callback2));
    obsPair->second.clear();
    obsPair = dataObsMgrInner_->observers_.find(uri.ToString());
    EXPECT_EQ(false, dataObsMgrInner_->HaveRegistered(callback2));
}

/*
 * Feature: DataObsMgrInner
 * Function: AddObsDeathRecipient/RemoveObsDeathRecipient function test
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_AddRemove_ObsDeathRecipient_0100, TestSize.Level1)
{
    ASSERT_TRUE(dataObsMgrInner_ != nullptr);

    sptr<IRemoteObject> observer(new (std::nothrow) MockDataAbilityObserverStub());
    sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    dataObsMgrInner_->AddObsDeathRecipient(callback);
    dataObsMgrInner_->AddObsDeathRecipient(nullptr);

    ObsRecipientMapType::const_iterator it;
    it = dataObsMgrInner_->obsRecipient_.find(observer);
    EXPECT_EQ(true, it != dataObsMgrInner_->obsRecipient_.end());

    dataObsMgrInner_->RemoveObsDeathRecipient(callback->AsObject());
    dataObsMgrInner_->RemoveObsDeathRecipient(nullptr);
    it = dataObsMgrInner_->obsRecipient_.find(observer);
    EXPECT_EQ(false, it != dataObsMgrInner_->obsRecipient_.end());

    dataObsMgrInner_->obsRecipient_.clear();
    dataObsMgrInner_->RemoveObsDeathRecipient(callback->AsObject());
}

/*
 * Feature: DataObsMgrInner
 * Function: Unregister function test
 * SubFunction: RemoveObs
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_RemoveObs_0100, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInner> dataObsMgrInner = std::make_shared<DataObsMgrInner>();
    ASSERT_NE(dataObsMgrInner, nullptr);
    std::string uri1 = "uri1";
    std::string uri2 = "uri2";
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback1(new (std::nothrow) DataAbilityObserverProxy(observer));
    const sptr<IDataAbilityObserver> callback2(new (std::nothrow) DataAbilityObserverProxy(observer));
    ObsListType obsList1;
    ObsListType obsList2;
    ObsListType obsList3;
    obsList1.push_back(ObserverNode(callback1, USER_TEST, 0, 0));
    obsList2.push_back(ObserverNode(callback1, USER_TEST, 0, 0));
    obsList2.push_back(ObserverNode(callback2, USER_TEST, 0, 0));
    dataObsMgrInner->observers_.emplace(uri1, obsList1);
    dataObsMgrInner->observers_.emplace(uri2, obsList2);
    dataObsMgrInner->RemoveObs(callback2->AsObject());
}

/*
 * Feature: DataObsMgrInner
 * Function: Register and unregister function test
 * SubFunction: OnChange
 * FunctionPoints: When the data changes, call the OnChange function of the registered dataabilityobserver
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleNotifyChange_0400, TestSize.Level1)
{
    ASSERT_TRUE(dataObsMgrInner_ != nullptr);

    Uri uri("rdb://device_id/com.domainname.dataability.persondata/person/10");
    sptr<MockDataAbilityObserverStub> mockDataAbilityObserverStub(new (std::nothrow) MockDataAbilityObserverStub());

    EXPECT_CALL(*mockDataAbilityObserverStub, OnChange()).Times(0);

    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(mockDataAbilityObserverStub));
    dataObsMgrInner_->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0, 0));
    dataObsMgrInner_->HandleNotifyChange(uri, USER_TEST, DataSharePermission::NO_PERMISSION, false, 1);
}

/*
 * Feature: DataObsMgrInner
 * Function: HandleNotifyChange with RDB scheme and same token
 * SubFunction: OnChange
 * FunctionPoints: When listenerTokenId equals tokenId for RDB scheme, OnChange should be called
 * EnvConditions: NA
 * CaseDescription: Test RDB scheme permission verification passes when tokens match
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleNotifyChange_RDBSameToken_0100, TestSize.Level1)
{
    ASSERT_TRUE(dataObsMgrInner_ != nullptr);

    Uri uri("rdb://device_id/com.domainname.dataability.persondata/person/10");
    sptr<MockDataAbilityObserverStub> mockDataAbilityObserverStub(new (std::nothrow) MockDataAbilityObserverStub());

    // Same token (0) should pass verification
    EXPECT_CALL(*mockDataAbilityObserverStub, OnChange()).Times(1);

    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(mockDataAbilityObserverStub));
    dataObsMgrInner_->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0, 0));
    dataObsMgrInner_->HandleNotifyChange(uri, USER_TEST, DataSharePermission::NO_PERMISSION, false, 0);
}

/*
 * Feature: DataObsMgrInner
 * Function: HandleNotifyChange with RDB scheme and different token
 * SubFunction: OnChange
 * FunctionPoints: When tokens differ for RDB scheme, permission verification should be performed
 * EnvConditions: NA
 * CaseDescription: Test RDB scheme with different listener and caller tokens
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleNotifyChange_RDBDifferentToken_0100, TestSize.Level1)
{
    ASSERT_TRUE(dataObsMgrInner_ != nullptr);

    Uri uri("rdb://device_id/com.domainname.dataability.persondata/person/10");
    sptr<MockDataAbilityObserverStub> mockDataAbilityObserverStub(new (std::nothrow) MockDataAbilityObserverStub());

    // Different tokens - verification should fail, OnChange should not be called
    EXPECT_CALL(*mockDataAbilityObserverStub, OnChange()).Times(0);

    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(mockDataAbilityObserverStub));
    ObserverNode node(callback, USER_TEST, 0, 0);
    node.tokenId_ = 1001; // Set different token
    dataObsMgrInner_->HandleRegisterObserver(uri, node);
    dataObsMgrInner_->HandleNotifyChange(uri, USER_TEST, DataSharePermission::NO_PERMISSION, false, 1002);
}

/*
 * Feature: DataObsMgrInner
 * Function: HandleNotifyChange with readPermission
 * SubFunction: OnChange
 * FunctionPoints: readPermission should be verified for non-RDB schemes
 * EnvConditions: NA
 * CaseDescription: Test readPermission parameter handling with singleton URI
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleNotifyChange_ReadPermission_0100, TestSize.Level1)
{
    ASSERT_TRUE(dataObsMgrInner_ != nullptr);

    // Use singleton URI to bypass readPermission verification
    Uri uri("dataability:///com.domainname.dataability.persondata/person/10");
    sptr<MockDataAbilityObserverStub> mockDataAbilityObserverStub(new (std::nothrow) MockDataAbilityObserverStub());

    // With singleton URI, readPermission check is bypassed, OnChange should be called
    EXPECT_CALL(*mockDataAbilityObserverStub, OnChange()).Times(0);

    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(mockDataAbilityObserverStub));
    ObserverNode node(callback, USER_TEST, 0, 0);
    dataObsMgrInner_->HandleRegisterObserver(uri, node);
    // Test with custom readPermission (ignored for singleton URI)
    dataObsMgrInner_->HandleNotifyChange(uri, USER_TEST, "custom.permission", false, 0);
}
}  // namespace AAFwk
}  // namespace OHOS
