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
#include "dataobs_mgr_inner_common.h"
#include "uri.h"
#define private public
#include "data_ability_observer_proxy.h"
#include "dataobs_mgr_errors.h"
#include "dataobs_mgr_inner_pref.h"
#include "hilog_tag_wrapper.h"
#include "mock_data_ability_observer_stub.h"

using namespace OHOS;
using namespace testing::ext;
using namespace testing;


namespace OHOS {
namespace AAFwk {
using Uri = OHOS::Uri;
using ObsListType = std::list<struct ObserverNode>;
using ObsRecipientMapType = OHOS::AAFwk::DataObsMgrInnerPref::ObsRecipientMapType;
class DataObsMgrInnerPrefTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<DataObsMgrInnerPref> dataObsMgrInnerPref_ = nullptr;
};
void DataObsMgrInnerPrefTest::SetUpTestCase(void) {}
void DataObsMgrInnerPrefTest::TearDownTestCase(void) {}
void DataObsMgrInnerPrefTest::SetUp()
{
    dataObsMgrInnerPref_ = std::make_shared<DataObsMgrInnerPref>();
}
void DataObsMgrInnerPrefTest::TearDown() {}

static constexpr int64_t USER_TEST = 100;

/*
 * Feature: DataObsMgrInnerPref
 * Function: Register and unregister function test
 * SubFunction: HandleRegisterObserver/HandleRegisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerPrefTest, DataObsMgrInnerPref_HandleRegisterObserver_0100, TestSize.Level1)
{
    ASSERT_TRUE(dataObsMgrInnerPref_ != nullptr);

    Uri uri("sharepreferences://data/preferences/preferences_test");
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());

    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    dataObsMgrInnerPref_->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0));

    EXPECT_EQ(dataObsMgrInnerPref_->HaveRegistered(callback), true);
    dataObsMgrInnerPref_->HandleUnregisterObserver(uri, ObserverNode(callback, USER_TEST, 0));
    EXPECT_EQ(dataObsMgrInnerPref_->HaveRegistered(callback), false);
}

/*
 * Feature: DataObsMgrInnerPref
 * Function: Register function test
 * SubFunction: HandleRegisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerPrefTest, DataObsMgrInnerPref_HandleRegisterObserver_0200, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerPref> dataObsMgrInner = std::make_shared<DataObsMgrInnerPref>();
    Uri uri("sharepreferences://data/preferences/preferences_test");
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    ObsListType obsList;
    obsList.push_back(ObserverNode(callback, USER_TEST, 0));
    dataObsMgrInner->observers_.emplace(uri.ToString(), obsList);
    int res = dataObsMgrInner->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0));
    EXPECT_EQ(res, OBS_EXIST);
}

/*
 * Feature: DataObsMgrInnerPref
 * Function: Register function test
 * SubFunction: HandleRegisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerPrefTest, DataObsMgrInnerPref_HandleRegisterObserver_0300, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerPref> dataObsMgrInner = std::make_shared<DataObsMgrInnerPref>();
    Uri uri("sharepreferences://data/preferences/preferences_test");
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    const sptr<IDataAbilityObserver> callback1(new (std::nothrow) DataAbilityObserverProxy(observer));
    ObsListType obsList;
    obsList.push_back(ObserverNode(callback1, USER_TEST, 0));
    dataObsMgrInner->observers_.emplace(uri.ToString(), obsList);
    int res = dataObsMgrInner->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0));
    EXPECT_EQ(res, OBS_EXIST);
}

/*
 * Feature: DataObsMgrInnerPref
 * Function: Register function test
 * SubFunction: HandleRegisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Register max observer
 */
HWTEST_F(DataObsMgrInnerPrefTest, DataObsMgrInnerPref_HandleRegisterObserver_0400, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerPref> dataObsMgrInner = std::make_shared<DataObsMgrInnerPref>();
    Uri uri("sharepreferences://data/preferences/preferences_test");
    int res = 0;

    int times = DataObsMgrInnerPref::OBS_NUM_MAX;
    for (int i = 0; i <= times; i++) {
        sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
        const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
        res = dataObsMgrInner->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0));
        EXPECT_EQ(res, NO_ERROR);
    }
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    res = dataObsMgrInner->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0));
    EXPECT_EQ(res, DATAOBS_SERVICE_OBS_LIMMIT);

    // other token success
    sptr<MockDataAbilityObserverStub> observer2(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback2(new (std::nothrow) DataAbilityObserverProxy(observer));
    res = dataObsMgrInner->HandleRegisterObserver(uri, ObserverNode(callback2, USER_TEST, 1));
    EXPECT_EQ(res, NO_ERROR);

    // other uri success
    Uri uri2("sharepreferences://data/preferences/preferences_test/2");
    sptr<MockDataAbilityObserverStub> observer3(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback3(new (std::nothrow) DataAbilityObserverProxy(observer3));
    res = dataObsMgrInner->HandleRegisterObserver(uri2, ObserverNode(callback3, USER_TEST, 0));
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * Feature: DataObsMgrInnerPref
 * Function: Register function test
 * SubFunction: HandleRegisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: RegisterObserver max limit times
 */
HWTEST_F(DataObsMgrInnerPrefTest, DataObsMgrInnerPref_HandleRegisterObserver_0500, TestSize.Level1)
{
    TAG_LOGE(AAFwkTag::DBOBSMGR, "DataObsMgrInnerPref_HandleRegisterObserver_0500::Start");
    std::shared_ptr<DataObsMgrInnerPref> dataObsMgrInner = std::make_shared<DataObsMgrInnerPref>();
    Uri uri("sharepreferences://data/preferences/preferences_test");
    for (int token = 0; token < DataObsMgrInnerPref::OBS_NUM_MAX; token++) {
        for (int i = 0; i < DataObsMgrInnerPref::OBS_NUM_MAX; i++) {
            sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
            const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
            int res = dataObsMgrInner->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, token));
            EXPECT_EQ(res, NO_ERROR);
        }
    }
    int token = DataObsMgrInnerPref::OBS_NUM_MAX  +1;
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    int res = dataObsMgrInner->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, token));
    EXPECT_EQ(res, DATAOBS_SERVICE_OBS_LIMMIT);
    TAG_LOGE(AAFwkTag::DBOBSMGR, "DataObsMgrInnerPref_HandleRegisterObserver_0500::End");
}

/*
 * Feature: DataObsMgrInnerPref
 * Function: Unregister function test
 * SubFunction: HandleUnregisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerPrefTest, DataObsMgrInnerPref_HandleUnregisterObserver_0100, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerPref> dataObsMgrInner = std::make_shared<DataObsMgrInnerPref>();
    Uri uri("sharepreferences://data/preferences/preferences_test");
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    dataObsMgrInner->observers_.clear();
    int res = dataObsMgrInner->HandleUnregisterObserver(uri, ObserverNode(callback, USER_TEST, 0));
    EXPECT_EQ(res, NO_OBS_FOR_URI);
}

/*
 * Feature: DataObsMgrInnerPref
 * Function: Unregister function test
 * SubFunction: HandleUnregisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerPrefTest, DataObsMgrInnerPref_HandleUnregisterObserver_0200, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerPref> dataObsMgrInner = std::make_shared<DataObsMgrInnerPref>();
    Uri uri("sharepreferences://data/preferences/preferences_test");
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    ObsListType obsList;
    obsList.push_back(ObserverNode(callback, USER_TEST, 0));
    dataObsMgrInner->observers_.emplace(uri.ToString(), obsList);
    int res = dataObsMgrInner->HandleUnregisterObserver(uri, ObserverNode(callback, USER_TEST, 0));
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * Feature: DataObsMgrInnerPref
 * Function: Unregister function test
 * SubFunction: HandleUnregisterObserver
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerPrefTest, DataObsMgrInnerPref_HandleUnregisterObserver_0300, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerPref> dataObsMgrInner = std::make_shared<DataObsMgrInnerPref>();
    Uri uri("sharepreferences://data/preferences/preferences_test");
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    const sptr<IDataAbilityObserver> callback2(new (std::nothrow) DataAbilityObserverProxy(observer));
    ObsListType obsList;
    obsList.push_back(ObserverNode(callback, USER_TEST, 0));
    obsList.push_back(ObserverNode(callback2, USER_TEST, 0));
    dataObsMgrInner->observers_.emplace(uri.ToString(), obsList);
    dataObsMgrInner->observers_.emplace("exit", obsList);
    int res = dataObsMgrInner->HandleUnregisterObserver(uri, ObserverNode(callback, USER_TEST, 0));
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * Feature: DataObsMgrInnerPref
 * Function: Notify function test
 * SubFunction: HandleNotifyChange
 * FunctionPoints: When the data changes, call the OnChangePreferences function of the registered dataabilityobserver
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerPrefTest, DataObsMgrInnerPref_HandleNotifyChange_0100, TestSize.Level1)
{
    ASSERT_TRUE(dataObsMgrInnerPref_ != nullptr);
    Uri uri("sharepreferences://data/preferences/preferences_test");
    sptr<MockDataAbilityObserverStub> mockDataAbilityObserverStub(new (std::nothrow) MockDataAbilityObserverStub());

    Uri notifyUri("sharepreferences://data/preferences/preferences_test?key");
    dataObsMgrInnerPref_->HandleRegisterObserver(uri, ObserverNode(mockDataAbilityObserverStub, USER_TEST, 0));
    dataObsMgrInnerPref_->HandleNotifyChange(notifyUri, USER_TEST);
    EXPECT_EQ("key", mockDataAbilityObserverStub->key_);
}

/*
 * Feature: DataObsMgrInnerPref
 * Function: Notify function test
 * SubFunction: HandleNotifyChange
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerPrefTest, DataObsMgrInnerPref_HandleNotifyChange_0200, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerPref> dataObsMgrInner = std::make_shared<DataObsMgrInnerPref>();
    Uri uri("sharepreferences://data/preferences/preferences_test?key");
    dataObsMgrInner->observers_.clear();
    int res = dataObsMgrInner->HandleNotifyChange(uri, USER_TEST);
    EXPECT_EQ(res, NO_OBS_FOR_URI);
}

/*
 * Feature: DataObsMgrInnerPref
 * Function: Notify function test
 * SubFunction: HandleNotifyChange
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerPrefTest, DataObsMgrInnerPref_HandleNotifyChange_0300, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerPref> dataObsMgrInner = std::make_shared<DataObsMgrInnerPref>();
    Uri uri("sharepreferences://data/preferences/preferences_test");
    ObsListType obsList;
    obsList.push_back(ObserverNode(nullptr, USER_TEST, 0));
    dataObsMgrInner->observers_.emplace(uri.ToString(), obsList);
    Uri notifyUri("sharepreferences://data/preferences/preferences_test?key");
    int res = dataObsMgrInner->HandleNotifyChange(notifyUri, USER_TEST);
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * Feature: DataObsMgrInnerPref
 * Function: GetObsListFromMap/RemoveObs/HaveRegistered function test
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerPrefTest, DataObsMgrInnerPref_RemoveObs_HaveRegistered_0100, TestSize.Level1)
{
    ASSERT_TRUE(dataObsMgrInnerPref_ != nullptr);
    Uri uri("sharepreferences://data/preferences/preferences_test");
    sptr<MockDataAbilityObserverStub> mockDataAbilityObserverStub(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(mockDataAbilityObserverStub));
    dataObsMgrInnerPref_->HandleRegisterObserver(uri, ObserverNode(callback, USER_TEST, 0));

    sptr<MockDataAbilityObserverStub> mockDataAbilityObserverStub2(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback2(
        new (std::nothrow) DataAbilityObserverProxy(mockDataAbilityObserverStub2));

    dataObsMgrInnerPref_->HandleRegisterObserver(uri, ObserverNode(callback2, USER_TEST, 0));
    auto obsPair = dataObsMgrInnerPref_->observers_.find(uri.ToString());
    EXPECT_EQ((std::size_t)2, obsPair->second.size());
    EXPECT_EQ(true, dataObsMgrInnerPref_->HaveRegistered(callback));
    EXPECT_EQ(true, dataObsMgrInnerPref_->HaveRegistered(callback2));

    dataObsMgrInnerPref_->RemoveObs(callback->AsObject());
    EXPECT_EQ(false, dataObsMgrInnerPref_->HaveRegistered(callback));
    obsPair->second.clear();
    obsPair = dataObsMgrInnerPref_->observers_.find(uri.ToString());
    EXPECT_EQ(false, dataObsMgrInnerPref_->HaveRegistered(callback));

    dataObsMgrInnerPref_->RemoveObs(callback2->AsObject());
    EXPECT_EQ(false, dataObsMgrInnerPref_->HaveRegistered(callback2));
    obsPair->second.clear();
    obsPair = dataObsMgrInnerPref_->observers_.find(uri.ToString());
    EXPECT_EQ(false, dataObsMgrInnerPref_->HaveRegistered(callback2));
}

/*
 * Feature: DataObsMgrInnerPref
 * Function: AddObsDeathRecipient/RemoveObsDeathRecipient function test
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerPrefTest, DataObsMgrInnerPref_AddRemove_ObsDeathRecipient_0100, TestSize.Level1)
{
    ASSERT_TRUE(dataObsMgrInnerPref_ != nullptr);

    sptr<IRemoteObject> observer(new (std::nothrow) MockDataAbilityObserverStub());
    sptr<IDataAbilityObserver> callback(new (std::nothrow) DataAbilityObserverProxy(observer));
    dataObsMgrInnerPref_->AddObsDeathRecipient(callback);
    dataObsMgrInnerPref_->AddObsDeathRecipient(nullptr);

    ObsRecipientMapType::const_iterator it;
    it = dataObsMgrInnerPref_->obsRecipient_.find(observer);
    EXPECT_EQ(true, it != dataObsMgrInnerPref_->obsRecipient_.end());

    dataObsMgrInnerPref_->RemoveObsDeathRecipient(callback->AsObject());
    dataObsMgrInnerPref_->RemoveObsDeathRecipient(nullptr);
    it = dataObsMgrInnerPref_->obsRecipient_.find(observer);
    EXPECT_EQ(false, it != dataObsMgrInnerPref_->obsRecipient_.end());

    dataObsMgrInnerPref_->obsRecipient_.clear();
    dataObsMgrInnerPref_->RemoveObsDeathRecipient(callback->AsObject());
}

/*
 * Feature: DataObsMgrInnerPref
 * Function: Unregister function test
 * SubFunction: RemoveObs
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:NA
 */
HWTEST_F(DataObsMgrInnerPrefTest, DataObsMgrInnerPref_RemoveObs_0100, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerPref> dataObsMgrInner = std::make_shared<DataObsMgrInnerPref>();
    ASSERT_NE(dataObsMgrInner, nullptr);
    std::string uri1 = "uri1";
    std::string uri2 = "uri2";
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    const sptr<IDataAbilityObserver> callback1(new (std::nothrow) DataAbilityObserverProxy(observer));
    const sptr<IDataAbilityObserver> callback2(new (std::nothrow) DataAbilityObserverProxy(observer));
    ObsListType obsList1;
    ObsListType obsList2;
    ObsListType obsList3;
    obsList1.push_back(ObserverNode(callback1, USER_TEST, 0));
    obsList2.push_back(ObserverNode(callback1, USER_TEST, 0));
    obsList2.push_back(ObserverNode(callback2, USER_TEST, 0));
    dataObsMgrInner->observers_.emplace(uri1, obsList1);
    dataObsMgrInner->observers_.emplace(uri2, obsList2);
    dataObsMgrInner->RemoveObs(callback2->AsObject());
}
}  // namespace AAFwk
}  // namespace OHOS
