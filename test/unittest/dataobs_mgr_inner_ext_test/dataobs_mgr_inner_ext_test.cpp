/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <algorithm>
#include <functional>
#include <gtest/gtest.h>
#include <memory>

#include "uri.h"
#define private public
#include "data_ability_observer_proxy.h"
#include "dataobs_mgr_inner_ext.h"
#include "dataobs_mgr_errors.h"
#include "mock.h"

using namespace OHOS;
using namespace testing::ext;
using namespace testing;

using Uri = OHOS::Uri;

namespace OHOS {
namespace DataObsMgrInnerTest {
using namespace AAFwk;
class DataObsMgrInnerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    void RegisterObserverUtil(std::shared_ptr<DataObsMgrInnerExt> &dataObsMgrInnerExt, Uri &uri,
        const sptr<IDataAbilityObserver> &callback, uint32_t times, bool isFuzzy);

    bool UrisEqual(std::list<Uri> uri1, std::list<Uri> uri2);
};

void DataObsMgrInnerTest::SetUpTestCase(void) {}
void DataObsMgrInnerTest::TearDownTestCase(void) {}
void DataObsMgrInnerTest::SetUp() {}
void DataObsMgrInnerTest::TearDown() {}

void DataObsMgrInnerTest::RegisterObserverUtil(std::shared_ptr<DataObsMgrInnerExt> &dataObsMgrInnerExt, Uri &uri,
    const sptr<IDataAbilityObserver> &callback, uint32_t times, bool isFuzzy)
{
    while (times-- > 0) {
        EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri, callback, isFuzzy), SUCCESS);
    }
}

bool DataObsMgrInnerTest::UrisEqual(std::list<Uri> uri1, std::list<Uri> uri2)
{
    if (uri1.size() != uri2.size()) {
        return false;
    }
    auto cmp = [](const Uri &first, const Uri &second) {
        return first.ToString() < second.ToString();
    };
    uri1.sort(cmp);
    uri2.sort(cmp);
    auto it1 = uri1.begin();
    auto it2 = uri2.begin();
    for (; it1 != uri1.end() && it2 != uri2.end(); it1++, it2++) {
        if (!it1->Equals(*it2)) {
            return false;
        }
    }
    return true;
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: HandleRegisterObserver test
 * SubFunction: 0100
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:Register one non-fuzzy observer one times
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleRegisterObserver_0100, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
    std::string uriBase = "dataability://Authority/com.domainname.dataability.persondata";
    Uri uri1(uriBase + "/Person");
    Uri uri2(uriBase + "/Person/2");
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());

    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri1, observer), SUCCESS);

    dataObsMgrInnerExt->HandleNotifyChange({ uri1 });
    EXPECT_TRUE(UrisEqual(observer->uris_, { uri1 }));

    observer->ReSet();
    dataObsMgrInnerExt->HandleNotifyChange({ uri1 });
    EXPECT_TRUE(UrisEqual(observer->uris_, { uri1 }));

    observer->ReSet();
    dataObsMgrInnerExt->HandleNotifyChange({ uri2 });
    EXPECT_TRUE(UrisEqual(observer->uris_, {}));
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: HandleRegisterObserver test
 * SubFunction: 0200
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:Register one non-fuzzy observer mutiple times
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleRegisterObserver_0200, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
    std::string uriBase = "dataability://Authority/com.domainname.dataability.persondata";
    Uri uri1(uriBase + "/Person");
    Uri uri2(uriBase + "/Person/2");
    Uri uri3(uriBase + "/Person/3");
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());

    RegisterObserverUtil(dataObsMgrInnerExt, uri1, observer, 1, false);
    RegisterObserverUtil(dataObsMgrInnerExt, uri2, observer, 2, false);
    RegisterObserverUtil(dataObsMgrInnerExt, uri3, observer, 3, false);

    dataObsMgrInnerExt->HandleNotifyChange({ uri1 });
    EXPECT_TRUE(UrisEqual(observer->uris_, { uri1 }));

    observer->ReSet();
    dataObsMgrInnerExt->HandleNotifyChange({ uri2 });
    EXPECT_TRUE(UrisEqual(observer->uris_, { uri2, uri2 }));

    observer->ReSet();
    dataObsMgrInnerExt->HandleNotifyChange({ uri3 });
    EXPECT_TRUE(UrisEqual(observer->uris_, { uri3, uri3, uri3 }));
}

/*
* Feature: DataObsMgrInnerExt
* Function: HandleRegisterObserver test
* SubFunction: 0300
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription:Register mutiple non-fuzzy observer mutiple times
*/
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleRegisterObserver_0300, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
    std::string uriBase = "dataability://Authority/com.domainname.dataability.persondata";
    Uri uri1(uriBase + "/Person");
    Uri uri2(uriBase + "/Person/2");
    Uri uri3(uriBase + "/Person/3");

    sptr<MockDataAbilityObserverStub> observer1(new (std::nothrow) MockDataAbilityObserverStub());
    sptr<MockDataAbilityObserverStub> observer2(new (std::nothrow) MockDataAbilityObserverStub());
    sptr<MockDataAbilityObserverStub> observer3(new (std::nothrow) MockDataAbilityObserverStub());

    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri1, observer1), SUCCESS);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri1, observer2), SUCCESS);

    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri2, observer2), SUCCESS);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri2, observer3), SUCCESS);

    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri3, observer3), SUCCESS);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri3, observer1), SUCCESS);

    dataObsMgrInnerExt->HandleNotifyChange({ uri1 });
    EXPECT_TRUE(UrisEqual(observer1->uris_, { uri1 }));
    EXPECT_TRUE(UrisEqual(observer2->uris_, { uri1 }));
    EXPECT_TRUE(UrisEqual(observer3->uris_, {}));

    observer1->ReSet();
    observer2->ReSet();
    observer3->ReSet();
    dataObsMgrInnerExt->HandleNotifyChange({ uri2, uri3 });
    EXPECT_TRUE(UrisEqual(observer1->uris_, { uri3 }));
    EXPECT_TRUE(UrisEqual(observer2->uris_, { uri2 }));
    EXPECT_TRUE(UrisEqual(observer3->uris_, { uri2, uri3 }));
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: HandleRegisterObserver test
 * SubFunction: 0400
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:Register one fuzzy observer one times
 *          Person1 <-obs
 *           2   4
 *          3
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleRegisterObserver_0400, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
    std::string uriBase = "dataability://Authority/com.domainname.dataability.persondata";

    Uri uri1(uriBase + "/Person1");
    Uri uri12(uriBase + "/Person1/2");
    Uri uri123(uriBase + "/Person1/2/3");
    Uri uri14(uriBase + "/Person1/4");
    Uri uri2(uriBase + "/Person2");

    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri1, observer, true), SUCCESS);

    dataObsMgrInnerExt->HandleNotifyChange({ uri1 });
    EXPECT_TRUE(UrisEqual(observer->uris_, { uri1 }));

    observer->ReSet();
    dataObsMgrInnerExt->HandleNotifyChange({ uri12, uri123, uri14, uri2 });
    EXPECT_TRUE(UrisEqual(observer->uris_, { uri12, uri123, uri14 }));
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: HandleRegisterObserver test
 * SubFunction: 0500
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:Register one fuzzy observer mutiple times
 *          Person1 <-obs
 *           2   4 <-2*obs
 *          3     5
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleRegisterObserver_0500, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
    std::string uriBase = "dataability://Authority/com.domainname.dataability.persondata";

    Uri uri1(uriBase + "/Person1");
    Uri uri12(uriBase + "/Person1/2");
    Uri uri123(uriBase + "/Person1/2/3");
    Uri uri14(uriBase + "/Person1/4");
    Uri uri145(uriBase + "/Person1/4/5");

    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());

    RegisterObserverUtil(dataObsMgrInnerExt, uri1, observer, 1, true);
    RegisterObserverUtil(dataObsMgrInnerExt, uri14, observer, 2, true);

    dataObsMgrInnerExt->HandleNotifyChange({ uri1 });
    EXPECT_TRUE(UrisEqual(observer->uris_, { uri1 }));

    observer->ReSet();
    dataObsMgrInnerExt->HandleNotifyChange({ uri14, uri145, uri12, uri123 });
    EXPECT_TRUE(UrisEqual(observer->uris_, { uri14, uri14, uri14, uri145, uri145, uri145, uri12, uri123 }));
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: HandleRegisterObserver test
 * SubFunction: 0600
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:Register mutiple fuzzy observer mutiple times
 *          Person1 <-obs1
 *           2   4 <-obs2
 *    obs1->3     5
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleRegisterObserver_0600, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
    std::string uriBase = "dataability://Authority/com.domainname.dataability.persondata";

    Uri uri1(uriBase + "/Person1");
    Uri uri12(uriBase + "/Person1/2");
    Uri uri123(uriBase + "/Person1/2/3");
    Uri uri14(uriBase + "/Person1/4");
    Uri uri145(uriBase + "/Person1/4/5");

    sptr<MockDataAbilityObserverStub> observer1(new (std::nothrow) MockDataAbilityObserverStub());
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri1, observer1, true), SUCCESS);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri123, observer1, true), SUCCESS);

    sptr<MockDataAbilityObserverStub> observer2(new (std::nothrow) MockDataAbilityObserverStub());
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri14, observer2, true), SUCCESS);

    dataObsMgrInnerExt->HandleNotifyChange({ uri1 });
    EXPECT_TRUE(UrisEqual(observer1->uris_, { uri1 }));
    EXPECT_TRUE(UrisEqual(observer2->uris_, {}));

    observer1->ReSet();
    observer2->ReSet();
    dataObsMgrInnerExt->HandleNotifyChange({ uri14, uri145, uri12, uri123 });
    EXPECT_TRUE(UrisEqual(observer1->uris_, { uri14, uri145, uri12, uri123, uri123 }));
    EXPECT_TRUE(UrisEqual(observer2->uris_, { uri14, uri145 }));
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: HandleRegisterObserver test
 * SubFunction: 0700
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:Register mix observer mutiple times
 *          Person1 <-obs1(fuzzy)
 *         2   4 <-obs2(fuzzy and nofuzzy)
 *        3     5
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleRegisterObserver_0700, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
    std::string uriBase = "dataability://Authority/com.domainname.dataability.persondata";

    Uri uri1(uriBase + "/Person1");
    Uri uri12(uriBase + "/Person1/2");
    Uri uri123(uriBase + "/Person1/2/3");
    Uri uri14(uriBase + "/Person1/4");
    Uri uri145(uriBase + "/Person1/4/5");

    sptr<MockDataAbilityObserverStub> observer1(new (std::nothrow) MockDataAbilityObserverStub());
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri1, observer1, true), SUCCESS);

    sptr<MockDataAbilityObserverStub> observer2(new (std::nothrow) MockDataAbilityObserverStub());
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri14, observer2, true), SUCCESS);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri14, observer2, false), SUCCESS);

    dataObsMgrInnerExt->HandleNotifyChange({ uri1 });
    EXPECT_TRUE(UrisEqual(observer1->uris_, { uri1 }));
    EXPECT_TRUE(UrisEqual(observer2->uris_, {}));

    observer1->ReSet();
    observer2->ReSet();
    dataObsMgrInnerExt->HandleNotifyChange({ uri14, uri145, uri12, uri123 });
    EXPECT_TRUE(UrisEqual(observer1->uris_, { uri14, uri145, uri12, uri123 }));
    EXPECT_TRUE(UrisEqual(observer2->uris_, { uri14, uri14, uri145 }));
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: HandleUnregisterObserver test
 * SubFunction: 0100
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:UnRegister observer
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleUnregisterObserver_0100, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
    std::string uriBase1 = "dataability://Authority1/com.domainname.dataability.persondata";
    std::string uriBase2 = "dataability://Authority2/com.domainname.dataability.persondata";

    Uri uri1(uriBase1 + "/Person1");
    Uri uri12(uriBase1 + "/Person1/2");
    Uri uri2(uriBase2 + "/Person2");

    sptr<MockDataAbilityObserverStub> observer1(new (std::nothrow) MockDataAbilityObserverStub());
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri1, observer1, true), SUCCESS);
    dataObsMgrInnerExt->HandleNotifyChange({ uri1 });
    EXPECT_TRUE(UrisEqual(observer1->uris_, { uri1 }));
    EXPECT_EQ(dataObsMgrInnerExt->obsRecipientMap_.size(), 1);
    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(uri12, observer1), NO_OBS_FOR_URI);
    EXPECT_EQ(dataObsMgrInnerExt->obsRecipientMap_.size(), 1);
    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(uri1, observer1), SUCCESS);
    EXPECT_EQ(dataObsMgrInnerExt->obsRecipientMap_.size(), 0);
    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(uri1, observer1), NO_OBS_FOR_URI);
    EXPECT_EQ(dataObsMgrInnerExt->obsRecipientMap_.size(), 0);
    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(uri2, observer1), NO_OBS_FOR_URI);
    observer1->ReSet();
    dataObsMgrInnerExt->HandleNotifyChange({ uri1 });
    EXPECT_EQ(observer1->onChangeCall_, 0);
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: HandleUnregisterObserver test
 * SubFunction: 0200
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:UnRegister one observers mutiple times
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleUnregisterObserver_0200, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
    std::string uriBase = "dataability://Authority1/com.domainname.dataability.persondata";

    Uri uri1(uriBase + "/Person1");

    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri1, observer, true), SUCCESS);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri1, observer, false), SUCCESS);
    dataObsMgrInnerExt->HandleNotifyChange({ uri1 });
    EXPECT_EQ(dataObsMgrInnerExt->obsRecipientMap_.size(), 1);
    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(uri1, observer), SUCCESS);
    EXPECT_EQ(dataObsMgrInnerExt->obsRecipientMap_.size(), 0);
    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(uri1, observer), NO_OBS_FOR_URI);
    EXPECT_EQ(dataObsMgrInnerExt->obsRecipientMap_.size(), 0);
    dataObsMgrInnerExt->HandleNotifyChange({ uri1 });
    EXPECT_EQ(observer->onChangeCall_, 2);
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: HandleUnregisterObserver test
 * SubFunction: 0300
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:UnRegister mutiple observers on mutiple uri
 *          Person1
 *           2   3<-2*obs1、obs2
 *        obs1->4 5<-obs2
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleUnregisterObserver_0300, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
    std::string uriBase = "dataability://Authority1/com.domainname.dataability.persondata";

    Uri uri1(uriBase + "/Person1");
    Uri uri12(uriBase + "/Person1/2");
    Uri uri13(uriBase + "/Person1/3");
    Uri uri134(uriBase + "/Person1/3/4");
    Uri uri135(uriBase + "/Person1/3/5");

    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri13, observer, true), SUCCESS);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri13, observer, false), SUCCESS);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri134, observer, false), SUCCESS);

    sptr<MockDataAbilityObserverStub> observer2(new (std::nothrow) MockDataAbilityObserverStub());
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri13, observer2, true), SUCCESS);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri135, observer2, true), SUCCESS);

    EXPECT_EQ(dataObsMgrInnerExt->obsRecipientMap_.size(), 2);
    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(uri135, observer), NO_OBS_FOR_URI);

    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(uri135, observer2), SUCCESS);
    dataObsMgrInnerExt->HandleNotifyChange({ uri135 });
    EXPECT_EQ(dataObsMgrInnerExt->obsRecipientMap_.size(), 2);

    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(uri13, observer2), SUCCESS);
    dataObsMgrInnerExt->HandleNotifyChange({ uri135 });
    EXPECT_EQ(dataObsMgrInnerExt->obsRecipientMap_.size(), 1);

    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(uri13, observer), SUCCESS);
    EXPECT_EQ(dataObsMgrInnerExt->obsRecipientMap_.size(),1);
    dataObsMgrInnerExt->HandleNotifyChange({ uri13 });

    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(uri134, observer), SUCCESS);
    EXPECT_EQ(dataObsMgrInnerExt->obsRecipientMap_.size(),0);
    EXPECT_TRUE(dataObsMgrInnerExt->nodes_.empty());
    EXPECT_EQ(observer->onChangeCall_, 2);
    EXPECT_EQ(observer2->onChangeCall_, 1);
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: Register and UnRegister test
 * SubFunction: 0100
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:Register and UnRegister when observers over limmit
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_RegisterAndUnRegister_0100, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
    std::string uriBase = "dataability://Authority1/com.domainname.dataability.persondata";
    Uri uri1(uriBase + "/Person1");
    Uri uri2(uriBase + "/Person2");

    sptr<MockDataAbilityObserverStub> observer1(new (std::nothrow) MockDataAbilityObserverStub());
    sptr<MockDataAbilityObserverStub> observer2(new (std::nothrow) MockDataAbilityObserverStub());

    RegisterObserverUtil(dataObsMgrInnerExt, uri1, observer1, 50, false);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri1,observer1, false),DATAOBS_SERVICE_OBS_LIMMIT);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri1,observer1, true),DATAOBS_SERVICE_OBS_LIMMIT);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri1,observer2, false),DATAOBS_SERVICE_OBS_LIMMIT);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri1,observer2, true),DATAOBS_SERVICE_OBS_LIMMIT);

    RegisterObserverUtil(dataObsMgrInnerExt, uri2, observer2, 30, false);
    RegisterObserverUtil(dataObsMgrInnerExt, uri2, observer1, 20, true);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri2,observer1, false),DATAOBS_SERVICE_OBS_LIMMIT);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri2,observer1, true),DATAOBS_SERVICE_OBS_LIMMIT);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri2,observer2, true),DATAOBS_SERVICE_OBS_LIMMIT);
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri2,observer2, false),DATAOBS_SERVICE_OBS_LIMMIT);

    dataObsMgrInnerExt->HandleNotifyChange({ uri1, uri2 });
    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(uri1,observer1),SUCCESS);
    dataObsMgrInnerExt->HandleNotifyChange({ uri1, uri2 });
    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(uri2,observer1),SUCCESS);
    dataObsMgrInnerExt->HandleNotifyChange({ uri1, uri2 });
    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(uri2,observer2),SUCCESS);
    dataObsMgrInnerExt->HandleNotifyChange({ uri1, uri2 });
    EXPECT_EQ(observer1->onChangeCall_, 90);
    EXPECT_EQ(observer2->onChangeCall_, 90);
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: HandleUnregisterObserver no uri
 * SubFunction: 0100
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:HandleUnregisterObserver one observers on all uri
 *          Person1<-5*obs1(fuzzy)+25*obs2
 *   10、20->2   3<-15*obs1+15*obs2
 *     20*obs1->4 5<-25*obs1+5*obs2
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleUnregisterObserverAll_0100, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
    std::string uriBase = "dataability://Authority1/com.domainname.dataability.persondata";

    Uri uri1(uriBase + "/Person1");
    Uri uri12(uriBase + "/Person1/2");
    Uri uri13(uriBase + "/Person1/3");
    Uri uri134(uriBase + "/Person1/3/4");
    Uri uri135(uriBase + "/Person1/3/5");

    sptr<MockDataAbilityObserverStub> observer1(new (std::nothrow) MockDataAbilityObserverStub());
    sptr<MockDataAbilityObserverStub> observer2(new (std::nothrow) MockDataAbilityObserverStub());

    RegisterObserverUtil(dataObsMgrInnerExt, uri1, observer1, 5, true);
    RegisterObserverUtil(dataObsMgrInnerExt, uri12, observer1, 10, false);
    RegisterObserverUtil(dataObsMgrInnerExt, uri13, observer1, 15, false);
    RegisterObserverUtil(dataObsMgrInnerExt, uri134, observer1, 20, false);
    RegisterObserverUtil(dataObsMgrInnerExt, uri135, observer1, 25, false);

    RegisterObserverUtil(dataObsMgrInnerExt, uri1, observer2, 25, true);
    RegisterObserverUtil(dataObsMgrInnerExt, uri12, observer2, 20, false);
    RegisterObserverUtil(dataObsMgrInnerExt, uri13, observer2, 15, true);
    RegisterObserverUtil(dataObsMgrInnerExt, uri134, observer2, 10, false);
    RegisterObserverUtil(dataObsMgrInnerExt, uri135, observer2, 5, false);

    dataObsMgrInnerExt->HandleNotifyChange({ uri1, uri12, uri13, uri134, uri135 });
    EXPECT_EQ(observer1->onChangeCall_, 95);
    EXPECT_EQ(observer2->onChangeCall_, 205);
    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(observer1), SUCCESS);
    observer1->ReSet();
    observer2->ReSet();
    dataObsMgrInnerExt->HandleNotifyChange({ uri1, uri12, uri13, uri134, uri135 });
    EXPECT_EQ(observer1->onChangeCall_, 0);
    EXPECT_EQ(observer2->onChangeCall_, 205);
    EXPECT_EQ(dataObsMgrInnerExt->HandleUnregisterObserver(observer2), SUCCESS);
    EXPECT_TRUE(dataObsMgrInnerExt->nodes_.empty());
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: DeathRecipient test
 * SubFunction: 0100
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:DeathRecipient
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_DeathRecipient_0100, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
    std::string uriBase = "dataability://Authority1/com.domainname.dataability.persondata";
    Uri uri1(uriBase + "/Person1");
    Uri uri12(uriBase + "/Person1/2");
    Uri uri13(uriBase + "/Person1/3");
    Uri uri134(uriBase + "/Person1/3/4");
    Uri uri135(uriBase + "/Person1/3/5");

    sptr<MockDataAbilityObserverStub> observer1(new (std::nothrow) MockDataAbilityObserverStub());
    sptr<MockDataAbilityObserverStub> observer2(new (std::nothrow) MockDataAbilityObserverStub());

    RegisterObserverUtil(dataObsMgrInnerExt, uri1, observer1, 5, true);
    RegisterObserverUtil(dataObsMgrInnerExt, uri12, observer1, 10, false);
    RegisterObserverUtil(dataObsMgrInnerExt, uri13, observer1, 15, false);
    RegisterObserverUtil(dataObsMgrInnerExt, uri134, observer1, 20, false);
    RegisterObserverUtil(dataObsMgrInnerExt, uri135, observer1, 25, false);

    RegisterObserverUtil(dataObsMgrInnerExt, uri1, observer2, 25, true);
    RegisterObserverUtil(dataObsMgrInnerExt, uri12, observer2, 20, false);
    RegisterObserverUtil(dataObsMgrInnerExt, uri13, observer2, 15, true);
    RegisterObserverUtil(dataObsMgrInnerExt, uri134, observer2, 10, false);
    RegisterObserverUtil(dataObsMgrInnerExt, uri135, observer2, 5, false);

    EXPECT_EQ(dataObsMgrInnerExt->obsRecipientMap_.size(), 2);
    dataObsMgrInnerExt->HandleNotifyChange({ uri1, uri12, uri13, uri134, uri135 });
    EXPECT_EQ(observer1->onChangeCall_, 95);
    EXPECT_EQ(observer2->onChangeCall_, 205);

    auto it = dataObsMgrInnerExt->obsRecipientMap_.find(observer1->AsObject());
    EXPECT_TRUE(it != dataObsMgrInnerExt->obsRecipientMap_.end() && it->second.first != nullptr);
    it->second.first->OnRemoteDied(observer1->AsObject());

    observer1->ReSet();
    observer2->ReSet();
    dataObsMgrInnerExt->HandleNotifyChange({ uri1, uri12, uri13, uri134, uri135 });
    EXPECT_EQ(observer1->onChangeCall_, 0);
    EXPECT_EQ(observer2->onChangeCall_, 205);
    dataObsMgrInnerExt->OnCallBackDied(observer2->AsObject());
    EXPECT_TRUE(dataObsMgrInnerExt->nodes_.empty());
    EXPECT_TRUE(dataObsMgrInnerExt->obsRecipientMap_.empty());
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: DeathRecipient test
 * SubFunction: 0200
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:DeathRecipient when dataObsMgrInnerExt release
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_DeathRecipient_0200, TestSize.Level1)
{
    std::string uriBase = "dataability://Authority1/com.domainname.dataability.persondata";
    Uri uri(uriBase + "/Person1");

    sptr<IRemoteObject::DeathRecipient> deathRecipient = nullptr;
    sptr<MockDataAbilityObserverStub> observer(new (std::nothrow) MockDataAbilityObserverStub());
    {
        std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
        EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri, observer, false), SUCCESS);

        auto it = dataObsMgrInnerExt->obsRecipientMap_.find(observer->AsObject());
        EXPECT_TRUE(it != dataObsMgrInnerExt->obsRecipientMap_.end() && it->second.first != nullptr);
        deathRecipient = it->second.first;
    }

    deathRecipient->OnRemoteDied(observer->AsObject());
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: AddObsDeathRecipient test
 * SubFunction: 0800
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:Add obs death recipient over max
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_AddObsDeathRecipientOverMax_0800, TestSize.Level1)
{
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();
    std::string uriBase = "dataability://Authority1/com.domainname.dataability.persondata";
    Uri uri(uriBase + "/Person1");
    auto sch = uri.GetScheme();

    sptr<MockDataAbilityObserverStub> observer = (new (std::nothrow) MockDataAbilityObserverStub());
    EXPECT_TRUE(dataObsMgrInnerExt->AddObsDeathRecipient(observer, std::numeric_limits<uint32_t>::max()));
    EXPECT_FALSE(dataObsMgrInnerExt->AddObsDeathRecipient(observer, 0));
    EXPECT_FALSE(dataObsMgrInnerExt->AddObsDeathRecipient(observer, 1));
    EXPECT_FALSE(dataObsMgrInnerExt->AddObsDeathRecipient(observer, std::numeric_limits<uint32_t>::max() - 1));
    EXPECT_FALSE(dataObsMgrInnerExt->AddObsDeathRecipient(observer, std::numeric_limits<uint32_t>::max()));
    EXPECT_EQ(dataObsMgrInnerExt->HandleRegisterObserver(uri, observer), ADD_OBS_DEATH_RECIPIENT_FAILED);
}

/*
 * Feature: DataObsMgrInnerExt
 * Function: HandleRegisterObserver test
 * SubFunction: 0800
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:HandleRegisterObserver muti threads
 */
HWTEST_F(DataObsMgrInnerTest, DataObsMgrInner_HandleRegisterObserver_0800, TestSize.Level1)
{
    std::string uriBase = "dataability://Authority1/com.domainname.dataability.persondata";
    std::vector<Uri> uris;
    uris.emplace_back(uriBase + "/1");
    uris.emplace_back(uriBase + "/2");
    uris.emplace_back(uriBase + "/1/3");
    uris.emplace_back(uriBase + "/2/4");
    std::shared_ptr<DataObsMgrInnerExt> dataObsMgrInnerExt = std::make_shared<DataObsMgrInnerExt>();

    auto func = [](std::vector<Uri> &uris, std::shared_ptr<DataObsMgrInnerExt> obsMgr,
                    sptr<MockDataAbilityObserverStub> &obs) {
        for (uint32_t i = 0; i < uris.size() * 5; ++i) {
            EXPECT_EQ(obsMgr->HandleRegisterObserver(uris[i % uris.size()], obs, false), SUCCESS);
        }
        obs->Notify();
    };

    sptr<MockDataAbilityObserverStub> observer1 = (new (std::nothrow) MockDataAbilityObserverStub());
    std::thread thread1(std::bind(func, uris, dataObsMgrInnerExt, observer1));
    thread1.detach();

    sptr<MockDataAbilityObserverStub> observer2 = (new (std::nothrow) MockDataAbilityObserverStub());
    std::thread thread2(std::bind(func, uris, dataObsMgrInnerExt, observer2));
    thread2.detach();

    observer1->Wait();
    observer2->Wait();

    EXPECT_EQ(dataObsMgrInnerExt->HandleNotifyChange({ uris[0], uris[1] }), SUCCESS);
    EXPECT_EQ(observer1->onChangeCall_, 10);
    EXPECT_EQ(observer2->onChangeCall_, 10);
    dataObsMgrInnerExt->HandleUnregisterObserver(observer1);

    observer1->ReSet();
    observer2->ReSet();
    EXPECT_EQ(dataObsMgrInnerExt->HandleNotifyChange({ uris[2], uris[3] }), SUCCESS);
    EXPECT_EQ(observer1->onChangeCall_, 0);
    EXPECT_EQ(observer2->onChangeCall_, 10);
}

} // namespace DataObsMgrInnerTest
} // namespace OHOS
