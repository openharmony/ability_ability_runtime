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
#include "ability_manager_service.h"
#include "free_install_observer_manager.h"
#include "task_handler_wrap.h"
#undef private

#include "ability_record.h"
#include "sa_mgr_client.h"
#include "hilog_tag_wrapper.h"
#include "hilog_wrapper.h"


using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace AppExecFwk {
namespace {
const int BUNDLE_MGR_SERVICE_SYS_ABILITY_ID = 401;
}
class FreeInstallObserverManagerTest : public testing::Test {
public:
    FreeInstallObserverManagerTest()
    {}
    ~FreeInstallObserverManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    sptr<Token> MockToken();
    std::shared_ptr<FreeInstallObserverManager> freeInstallObserverManager_ = nullptr;
};

void FreeInstallObserverManagerTest::SetUpTestCase(void) {}

void FreeInstallObserverManagerTest::TearDownTestCase(void) {}

void FreeInstallObserverManagerTest::SetUp(void) {}

void FreeInstallObserverManagerTest::TearDown(void)
{}

sptr<Token> FreeInstallObserverManagerTest::MockToken()
{
    sptr<Token> token = nullptr;
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.test.demo";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    if (!abilityRecord) {
        return nullptr;
    }
 
    return abilityRecord->GetToken();
}

class IFreeInstallObserverMock : public IFreeInstallObserver {
public:
    IFreeInstallObserverMock() = default;
    virtual ~IFreeInstallObserverMock() = default;
    void OnInstallFinished(const std::string &bundleName, const std::string &abilityName,
    const std::string &startTime, const int &resultCode) override {};

    void OnInstallFinishedByUrl(const std::string &startTime, const std::string &url,
        const int &resultCode) override {};
    sptr<IRemoteObject> AsObject() override {return nullptr;};
};
/**
 * @tc.number: AddObserver_001
 * @tc.name: AddObserver
 * @tc.desc: Test AddObserver when callback is success.
 */
HWTEST_F(FreeInstallObserverManagerTest, AddObserver_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AddObserver_001 is start");
    auto info = std::make_shared<FreeInstallObserverManager>();
    int32_t recordId = 0;
    sptr<AbilityRuntime::IFreeInstallObserver> observer;
    int32_t res = info->AddObserver(recordId, observer);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AddObserver_001 is end");
}

/**
 * @tc.number: AddObserver_002
 * @tc.name: AddObserver
 * @tc.desc: Test AddObserver when callback is success.
 */
HWTEST_F(FreeInstallObserverManagerTest, AddObserver_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AddObserver_002 is start");
    freeInstallObserverManager_ = std::make_shared<FreeInstallObserverManager>();
    int32_t recordId = 0;
    sptr<AbilityRuntime::IFreeInstallObserver> observer = new IFreeInstallObserverMock();
    int32_t res = freeInstallObserverManager_->AddObserver(recordId, observer);
    freeInstallObserverManager_->deathRecipient_ = nullptr;
    EXPECT_EQ(res, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AddObserver_002 is end");
}

/**
 * @tc.number: RemoveObserver_001
 * @tc.name: RemoveObserver
 * @tc.desc: Test RemoveObserver when callback is success.
 */
HWTEST_F(FreeInstallObserverManagerTest, RemoveObserver_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "RemoveObserver_001 is start");
    freeInstallObserverManager_ = std::make_shared<FreeInstallObserverManager>();
    sptr<AbilityRuntime::IFreeInstallObserver> observer;
    int32_t res = freeInstallObserverManager_->RemoveObserver(observer);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "RemoveObserver_001 is end");
}

/**
 * @tc.number: RemoveObserver_002
 * @tc.name: RemoveObserver
 * @tc.desc: Test RemoveObserver when callback is success.
 */
HWTEST_F(FreeInstallObserverManagerTest, RemoveObserver_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "RemoveObserver_002 is start");
    freeInstallObserverManager_ = std::make_shared<FreeInstallObserverManager>();
    sptr<AbilityRuntime::IFreeInstallObserver> observer = new IFreeInstallObserverMock();
    int32_t res = freeInstallObserverManager_->RemoveObserver(observer);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "RemoveObserver_002 is end");
}

/**
 * @tc.number: RemoveObserver_003
 * @tc.name: RemoveObserver
 * @tc.desc: Test RemoveObserver when callback is success.
 */
HWTEST_F(FreeInstallObserverManagerTest, RemoveObserver_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "RemoveObserver_003 is start");
    freeInstallObserverManager_ = std::make_shared<FreeInstallObserverManager>();
    sptr<AbilityRuntime::IFreeInstallObserver> observer = new IFreeInstallObserverMock();
    freeInstallObserverManager_->observerMap_[0] = observer;
    freeInstallObserverManager_->observerMap_[1] = observer;
    int32_t res = freeInstallObserverManager_->RemoveObserver(observer);
    EXPECT_EQ(res, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "RemoveObserver_003 is end");
}

/**
 * @tc.number: OnInstallFinished_001
 * @tc.name: OnInstallFinished
 * @tc.desc: Test OnInstallFinished when callback is success.
 */
HWTEST_F(FreeInstallObserverManagerTest, OnInstallFinished_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnInstallFinished_001 is start");
    freeInstallObserverManager_ = std::make_shared<FreeInstallObserverManager>();
    std::string bundleName = "FreeInstallObserverManagerTest";
    std::string abilityName = "OnInstallFinished";
    std::string startTime = "2024-07-17 00:00:00";
    freeInstallObserverManager_->OnInstallFinished(0, bundleName, abilityName, startTime, 0);
    EXPECT_EQ(bundleName, "FreeInstallObserverManagerTest");
    TAG_LOGI(AAFwkTag::TEST, "OnInstallFinished_001 is end");
}

/**
 * @tc.number: OnInstallFinishedByUrl_001
 * @tc.name: OnInstallFinishedByUrl
 * @tc.desc: Test OnInstallFinishedByUrl when callback is success.
 */
HWTEST_F(FreeInstallObserverManagerTest, OnInstallFinishedByUrl_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnInstallFinishedByUrl_001 is start");
    freeInstallObserverManager_ = std::make_shared<FreeInstallObserverManager>();
    const std::string url = "FreeInstallObserverManagerTest";
    std::string startTime = "2024-07-17 00:00:00";
    freeInstallObserverManager_->OnInstallFinishedByUrl(0, startTime, url, 0);
    EXPECT_EQ(url, "FreeInstallObserverManagerTest");
    TAG_LOGI(AAFwkTag::TEST, "OnInstallFinishedByUrl_001 is end");
}

/**
 * @tc.number: HandleOnInstallFinished_001
 * @tc.name: HandleOnInstallFinished
 * @tc.desc: Test HandleOnInstallFinished when callback is success.
 */
HWTEST_F(FreeInstallObserverManagerTest, HandleOnInstallFinished_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleOnInstallFinished_001 is start");
    freeInstallObserverManager_ = std::make_shared<FreeInstallObserverManager>();
    std::string bundleName = "FreeInstallObserverManagerTest";
    std::string abilityName = "OnInstallFinished";
    std::string startTime = "2024-07-17 00:00:00";
    sptr<AbilityRuntime::IFreeInstallObserver> observer = new IFreeInstallObserverMock();
    freeInstallObserverManager_->observerMap_[0] = observer;
    freeInstallObserverManager_->HandleOnInstallFinished(0, bundleName, abilityName, startTime, 0);
    EXPECT_EQ(bundleName, "FreeInstallObserverManagerTest");
    TAG_LOGI(AAFwkTag::TEST, "HandleOnInstallFinished_001 is end");
}

/**
 * @tc.number: HandleOnInstallFinishedByUrl_001
 * @tc.name: HandleOnInstallFinishedByUrl
 * @tc.desc: Test HandleOnInstallFinishedByUrl when callback is success.
 */
HWTEST_F(FreeInstallObserverManagerTest, HandleOnInstallFinishedByUrl_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleOnInstallFinishedByUrl_001 is start");
    freeInstallObserverManager_ = std::make_shared<FreeInstallObserverManager>();
    const std::string url = "FreeInstallObserverManagerTest";
    std::string startTime = "2024-07-17 00:00:00";
    sptr<AbilityRuntime::IFreeInstallObserver> observer = new IFreeInstallObserverMock();
    freeInstallObserverManager_->observerMap_[0] = observer;
    freeInstallObserverManager_->HandleOnInstallFinishedByUrl(0, startTime, url, 0);
    EXPECT_EQ(url, "FreeInstallObserverManagerTest");
    TAG_LOGI(AAFwkTag::TEST, "HandleOnInstallFinishedByUrl_001 is end");
}

/**
 * @tc.number: OnObserverDied_001
 * @tc.name: OnObserverDied
 * @tc.desc: Test OnObserverDied when callback is success.
 */
HWTEST_F(FreeInstallObserverManagerTest, OnObserverDied_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnObserverDied_001 is start");
    freeInstallObserverManager_ = std::make_shared<FreeInstallObserverManager>();
    wptr<IRemoteObject> remote = nullptr;
    freeInstallObserverManager_->OnObserverDied(remote);
    EXPECT_EQ(remote, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "OnObserverDied_001 is end");
}

/**
 * @tc.number: OnObserverDied_002
 * @tc.name: OnObserverDied
 * @tc.desc: Test OnObserverDied when callback is success.
 */
HWTEST_F(FreeInstallObserverManagerTest, OnObserverDied_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "OnObserverDied_002 is start");
    freeInstallObserverManager_ = std::make_shared<FreeInstallObserverManager>();
    sptr<AbilityRuntime::IFreeInstallObserver> observer = new IFreeInstallObserverMock();
    freeInstallObserverManager_->observerMap_[0] = observer;
    freeInstallObserverManager_->deathRecipient_ = nullptr;
    sptr<Token> remoteObject = MockToken();
    wptr<IRemoteObject> remote(remoteObject);
    freeInstallObserverManager_->OnObserverDied(remote);
    EXPECT_NE(remote, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "OnObserverDied_002 is end");
}
}  // namespace AppExecFwk
}  // namespace OHOS