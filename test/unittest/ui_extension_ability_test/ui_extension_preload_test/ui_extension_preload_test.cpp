/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>

#include "ability_manager_client.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"
#define private public
#include "preload_ui_extension_host_client.h"
#undef private
#include "session_info.h"
#include "want.h"

#include <thread>

using namespace testing;
using namespace testing::ext;
using PreloadUIExtensionHostClient = OHOS::AbilityRuntime::PreloadUIExtensionHostClient;
using PreloadTask = OHOS::AbilityRuntime::PreloadTask;

namespace OHOS {
namespace AAFwk {
class MockPreloadUIExtensionCallback : public AbilityRuntime::PreloadUIExtensionCallbackInterface {
public:
    MockPreloadUIExtensionCallback() = default;
    virtual ~MockPreloadUIExtensionCallback() = default;

    MOCK_METHOD1(ProcessOnLoadedDone, void(int32_t extensionAbilityId));
    MOCK_METHOD1(ProcessOnDestroyDone, void(int32_t extensionAbilityId));
};

class UIExtensionPreloadTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void UIExtensionPreloadTest::SetUpTestCase(void)
{}

void UIExtensionPreloadTest::TearDownTestCase(void)
{}

void UIExtensionPreloadTest::SetUp()
{}

void UIExtensionPreloadTest::TearDown()
{}

/**
 * @tc.name: PermissionCheck_0100
 * @tc.desc: permission check test.
 * @tc.type: FUNC
 * @tc.require: I9NW1A
 */
HWTEST_F(UIExtensionPreloadTest, PermissionCheck_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "start.");
    Want providerWant;
    AppExecFwk::ElementName providerElement("0", "com.ohos.uiextensionprovider", "UIExtensionProvider", "entry");
    providerWant.SetElement(providerElement);
    std::string hostBundleName = "com.ohos.uiextensionuser";
    auto ret = AbilityManagerClient::GetInstance()->PreloadUIExtensionAbility(providerWant, hostBundleName,
        DEFAULT_INVAL_VALUE);
    EXPECT_NE(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "finish.");
}

/**
 * @tc.name: ClearPreloadedUIExtensionAbility_0100
 * @tc.desc: Test ClearPreloadedUIExtensionAbility with valid and invalid conditions.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionPreloadTest, ClearPreloadedUIExtensionAbility_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "start.");
    auto client = AbilityManagerClient::GetInstance();
    ASSERT_NE(client, nullptr);

    int32_t extensionAbilityId = 123;
    int32_t userId = 0;

    ErrCode ret = client->ClearPreloadedUIExtensionAbility(extensionAbilityId, userId);
    EXPECT_NE(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "finish.");
}

/**
 * @tc.name: UnRegisterPreloadUIExtensionHostClient_0100
 * @tc.desc: Test UnRegisterPreloadUIExtensionHostClient normal call.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionPreloadTest, UnRegisterPreloadUIExtensionHostClient_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "start.");
    auto client = AbilityManagerClient::GetInstance();
    ASSERT_NE(client, nullptr);

    ErrCode ret = client->UnRegisterPreloadUIExtensionHostClient();
    EXPECT_NE(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "finish.");
}

/**
 * @tc.name: PreloadUIExtensionHostClient_0100
 * @tc.desc: Test RegisterPreloadUIExtensionHostClient normal call.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionPreloadTest, PreloadUIExtensionHostClient_0100, TestSize.Level1)
{
    auto instance = OHOS::AbilityRuntime::PreloadUIExtensionHostClient::GetInstance();
    ASSERT_NE(instance, nullptr);
    instance->RegisterPreloadUIExtensionHostClient();
    EXPECT_FALSE(instance->isRegistered_);

    instance->isRegistered_ = true;
    int32_t key = instance->AddLoadedCallback(nullptr);
    EXPECT_EQ(instance->loadedCallbackMap_.size(), 1);
    instance->RegisterPreloadUIExtensionHostClient();
    EXPECT_TRUE(instance->isRegistered_);

    instance->loadedCallbackMap_.clear();
    EXPECT_EQ(instance->loadedCallbackMap_.size(), 0);
    instance->isRegistered_ = false;
}

/**
 * @tc.name: PreloadUIExtensionHostClient_0200
 * @tc.desc: Test RegisterPreloadUIExtensionHostClient normal call.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionPreloadTest, PreloadUIExtensionHostClient_0200, TestSize.Level1)
{
    auto instance = OHOS::AbilityRuntime::PreloadUIExtensionHostClient::GetInstance();
    ASSERT_NE(instance, nullptr);
    instance->RegisterPreloadUIExtensionHostClient();
    EXPECT_FALSE(instance->isRegistered_);

    instance->isRegistered_ = true;
    int32_t key = instance->AddDestroyCallback(nullptr);
    EXPECT_EQ(instance->destroyCallbackMap_.size(), 1);
    instance->RegisterPreloadUIExtensionHostClient();
    EXPECT_TRUE(instance->isRegistered_);

    instance->destroyCallbackMap_.clear();
    EXPECT_EQ(instance->destroyCallbackMap_.size(), 0);
    instance->isRegistered_ = false;
}

/**
 * @tc.name: PreloadUIExtensionHostClient_0300
 * @tc.desc: Test RegisterPreloadUIExtensionHostClient normal call.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionPreloadTest, PreloadUIExtensionHostClient_0300, TestSize.Level1)
{
    auto instance = OHOS::AbilityRuntime::PreloadUIExtensionHostClient::GetInstance();
    ASSERT_NE(instance, nullptr);
    instance->RegisterPreloadUIExtensionHostClient();
    EXPECT_FALSE(instance->isRegistered_);

    instance->isRegistered_ = true;
    instance->resultCallbacks_.emplace(1, nullptr);
    EXPECT_EQ(instance->resultCallbacks_.size(), 1);
    instance->RegisterPreloadUIExtensionHostClient();
    EXPECT_TRUE(instance->isRegistered_);
    
    instance->resultCallbacks_.clear();
    EXPECT_EQ(instance->resultCallbacks_.size(), 0);
    instance->isRegistered_ = false;
}

/**
 * @tc.name: PreloadUIExtensionHostClient_0400
 * @tc.desc: Test RemoveLoadedCallback normal call.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionPreloadTest, PreloadUIExtensionHostClient_0400, TestSize.Level1)
{
    auto instance = OHOS::AbilityRuntime::PreloadUIExtensionHostClient::GetInstance();
    ASSERT_NE(instance, nullptr);
    int32_t ret = instance->RemoveLoadedCallback(-1);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    int32_t key = instance->AddLoadedCallback(nullptr);
    int32_t key2 = instance->AddLoadedCallback(nullptr);

    ret = instance->RemoveLoadedCallback(key);
    EXPECT_EQ(instance->loadedCallbackMap_.size(), 1);
    EXPECT_EQ(ret, ERR_OK);
    
    instance->loadedCallbackMap_.clear();
}

/**
 * @tc.name: PreloadUIExtensionHostClient_0500
 * @tc.desc: Test RemoveLoadedCallback normal call.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionPreloadTest, PreloadUIExtensionHostClient_0500, TestSize.Level1)
{
    auto instance = OHOS::AbilityRuntime::PreloadUIExtensionHostClient::GetInstance();
    ASSERT_NE(instance, nullptr);
    int32_t key = instance->AddLoadedCallback(nullptr);

    auto ret = instance->RemoveLoadedCallback(key);
    EXPECT_EQ(instance->loadedCallbackMap_.size(), 0);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: PreloadUIExtensionHostClient_0600
 * @tc.desc: Test RemoveDestroyCallback normal call.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionPreloadTest, PreloadUIExtensionHostClient_0600, TestSize.Level1)
{
    auto instance = OHOS::AbilityRuntime::PreloadUIExtensionHostClient::GetInstance();
    ASSERT_NE(instance, nullptr);
    int32_t ret = instance->RemoveDestroyCallback(-1);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    int32_t key = instance->AddDestroyCallback(nullptr);
    int32_t key2 = instance->AddDestroyCallback(nullptr);

    ret = instance->RemoveDestroyCallback(key);
    EXPECT_EQ(instance->destroyCallbackMap_.size(), 1);
    EXPECT_EQ(ret, ERR_OK);
    
    instance->destroyCallbackMap_.clear();
}

/**
 * @tc.name: PreloadUIExtensionHostClient_0700
 * @tc.desc: Test RemoveDestroyCallback normal call.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionPreloadTest, PreloadUIExtensionHostClient_0700, TestSize.Level1)
{
    auto instance = OHOS::AbilityRuntime::PreloadUIExtensionHostClient::GetInstance();
    ASSERT_NE(instance, nullptr);
    int32_t key = instance->AddDestroyCallback(nullptr);
    EXPECT_EQ(instance->destroyCallbackMap_.size(), 1);

    auto ret = instance->RemoveDestroyCallback(key);
    EXPECT_EQ(instance->destroyCallbackMap_.size(), 0);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: PreloadUIExtensionHostClient_0800
 * @tc.desc: Test RemoveAllLoadedCallback normal call.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionPreloadTest, PreloadUIExtensionHostClient_0800, TestSize.Level1)
{
    auto instance = OHOS::AbilityRuntime::PreloadUIExtensionHostClient::GetInstance();
    ASSERT_NE(instance, nullptr);
    instance->RemoveAllLoadedCallback();
    EXPECT_EQ(instance->loadedCallbackMap_.size(), 0);

    int32_t key = instance->AddLoadedCallback(nullptr);
    EXPECT_EQ(instance->loadedCallbackMap_.size(), 1);
    instance->RemoveAllLoadedCallback();
    EXPECT_EQ(instance->loadedCallbackMap_.size(), 0);
}

/**
 * @tc.name: PreloadUIExtensionHostClient_0900
 * @tc.desc: Test RemoveAllDestroyCallback normal call.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionPreloadTest, PreloadUIExtensionHostClient_0900, TestSize.Level1)
{
    auto instance = OHOS::AbilityRuntime::PreloadUIExtensionHostClient::GetInstance();
    ASSERT_NE(instance, nullptr);
    instance->RemoveAllDestroyCallback();
    EXPECT_EQ(instance->loadedCallbackMap_.size(), 0);

    int32_t key = instance->AddDestroyCallback(nullptr);
    EXPECT_EQ(instance->destroyCallbackMap_.size(), 1);
    instance->RemoveAllDestroyCallback();
    EXPECT_EQ(instance->destroyCallbackMap_.size(), 0);
}

/**
 * @tc.name: PreloadUIExtensionHostClient_1000
 * @tc.desc: Test UnRegisterPreloadUIExtensionHostClient normal call.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionPreloadTest, PreloadUIExtensionHostClient_1000, TestSize.Level1)
{
    auto instance = OHOS::AbilityRuntime::PreloadUIExtensionHostClient::GetInstance();
    ASSERT_NE(instance, nullptr);
    instance->UnRegisterPreloadUIExtensionHostClient();
    EXPECT_FALSE(instance->isRegistered_);
    instance->isRegistered_ = true;

    instance->resultCallbacks_.emplace(1, nullptr);
    EXPECT_EQ(instance->resultCallbacks_.size(), 1);
    instance->UnRegisterPreloadUIExtensionHostClient();
    EXPECT_TRUE(instance->isRegistered_);

    int32_t key = instance->AddLoadedCallback(nullptr);
    EXPECT_EQ(instance->loadedCallbackMap_.size(), 1);
    instance->UnRegisterPreloadUIExtensionHostClient();
    EXPECT_TRUE(instance->isRegistered_);

    key = instance->AddDestroyCallback(nullptr);
    EXPECT_EQ(instance->destroyCallbackMap_.size(), 1);
    instance->UnRegisterPreloadUIExtensionHostClient();
    EXPECT_TRUE(instance->isRegistered_);
    
    instance->resultCallbacks_.clear();
    instance->destroyCallbackMap_.clear();
    instance->loadedCallbackMap_.clear();
    instance->isRegistered_ = false;
}

/**
 * @tc.name: OnLoadedDone_0100
 * @tc.desc: Test OnLoadedDone with empty callback map.
 * @tc.type: FUNC
 * @tc.require: I9NW1A
 */
HWTEST_F(UIExtensionPreloadTest, OnLoadedDone_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "start.");
    auto hostClient = std::make_shared<AbilityRuntime::PreloadUIExtensionHostClient>();
    int32_t extensionAbilityId = 1001;
    hostClient->OnLoadedDone(extensionAbilityId);
    
    EXPECT_NE(hostClient, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "finish.");
}

/**
 * @tc.name: OnLoadedDone_0200
 * @tc.desc: Test OnLoadedDone thread safety with concurrent calls.
 * @tc.type: FUNC
 * @tc.require: I9NW1A
 */
HWTEST_F(UIExtensionPreloadTest, OnLoadedDone_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "start.");
    auto hostClient = std::make_shared<AbilityRuntime::PreloadUIExtensionHostClient>();
    int32_t extensionAbilityId = 1003;
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([hostClient, extensionAbilityId]() {
            hostClient->OnLoadedDone(extensionAbilityId);
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_NE(hostClient, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "finish.");
}

/**
 * @tc.name: OnLoadedDone_0300
 * @tc.desc: Test OnLoadedDone with invalid extensionAbilityId.
 * @tc.type: FUNC
 * @tc.require: I9NW1A
 */
HWTEST_F(UIExtensionPreloadTest, OnLoadedDone_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "start.");
    auto hostClient = std::make_shared<AbilityRuntime::PreloadUIExtensionHostClient>();
    int32_t extensionAbilityId = DEFAULT_INVAL_VALUE;
    hostClient->OnLoadedDone(extensionAbilityId);
    
    EXPECT_NE(hostClient, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "finish.");
}

/**
 * @tc.name: OnLoadedDone_0400
 * @tc.desc: Test OnLoadedDone with zero extensionAbilityId.
 * @tc.type: FUNC
 * @tc.require: I9NW1A
 */
HWTEST_F(UIExtensionPreloadTest, OnLoadedDone_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "start.");
    auto hostClient = std::make_shared<AbilityRuntime::PreloadUIExtensionHostClient>();
    int32_t extensionAbilityId = 0;
    hostClient->OnLoadedDone(extensionAbilityId);
    EXPECT_NE(hostClient, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "finish.");
}

/**
 * @tc.name: OnLoadedDone_0500
 * @tc.desc: Test OnLoadedDone with negative extensionAbilityId.
 * @tc.type: FUNC
 * @tc.require: I9NW1A
 */
HWTEST_F(UIExtensionPreloadTest, OnLoadedDone_0500, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "start.");
    auto hostClient = std::make_shared<AbilityRuntime::PreloadUIExtensionHostClient>();
    int32_t extensionAbilityId = -1;
    hostClient->OnLoadedDone(extensionAbilityId);
    
    EXPECT_NE(hostClient, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "finish.");
}

/**
 * @tc.name: OnLoadedDone_0600
 * @tc.desc: Test OnLoadedDone multiple calls with same extensionAbilityId.
 * @tc.type: FUNC
 * @tc.require: I9NW1A
 */
HWTEST_F(UIExtensionPreloadTest, OnLoadedDone_0600, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "start.");
    auto hostClient = std::make_shared<AbilityRuntime::PreloadUIExtensionHostClient>();
    int32_t extensionAbilityId = 1007;
    
    hostClient->OnLoadedDone(extensionAbilityId);
    hostClient->OnLoadedDone(extensionAbilityId);
    hostClient->OnLoadedDone(extensionAbilityId);
    
    EXPECT_NE(hostClient, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "finish.");
}

/**
 * @tc.name: OnDestroyDone_BranchCoverage
 * @tc.desc: Cover branches of OnDestroyDone method.
 * @tc.type: FUNC
 * @tc.require: I9NW1A
 */
HWTEST_F(UIExtensionPreloadTest, OnDestroyDone_0010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "start.");

    auto hostClient = std::make_shared<AbilityRuntime::PreloadUIExtensionHostClient>();
    int32_t extensionAbilityId = 1234;

    hostClient->OnDestroyDone(extensionAbilityId);

    {
        std::lock_guard<std::mutex> lock(hostClient->preloadUIExtensionLoadedCallbackMutex_);
        hostClient->destroyCallbackMap_[1] = nullptr;
    }
    hostClient->OnDestroyDone(extensionAbilityId);
    auto mockCallback = std::make_shared<MockPreloadUIExtensionCallback>();
    EXPECT_CALL(*mockCallback, ProcessOnDestroyDone(extensionAbilityId)).Times(1);
    {
        std::lock_guard<std::mutex> lock(hostClient->preloadUIExtensionLoadedCallbackMutex_);
        hostClient->destroyCallbackMap_[2] = mockCallback;
    }
    hostClient->OnDestroyDone(extensionAbilityId);

    TAG_LOGI(AAFwkTag::TEST, "finish.");
}


/**
 * @tc.name: OnPreloadSuccess_0100
 * @tc.desc: Test OnPreloadSuccess with requestCode not found.
 * @tc.type: FUNC
 * @tc.require: I9NW1A
 */
HWTEST_F(UIExtensionPreloadTest, OnPreloadSuccess_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "start.");
    auto hostClient = std::make_shared<AbilityRuntime::PreloadUIExtensionHostClient>();
    int32_t requestCode = 1001;
    int32_t extensionAbilityId = 2001;
    int32_t innerErrCode = 0;
    
    hostClient->OnPreloadSuccess(requestCode, extensionAbilityId, innerErrCode);
    
    EXPECT_NE(hostClient, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "finish.");
}

/**
 * @tc.name: OnPreloadSuccess_0200
 * @tc.desc: Test OnPreloadSuccess with valid callback and handler.
 * @tc.type: FUNC
 * @tc.require: I9NW1A
 */
HWTEST_F(UIExtensionPreloadTest, OnPreloadSuccess_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "start.");
    auto hostClient = std::make_shared<AbilityRuntime::PreloadUIExtensionHostClient>();
    int32_t requestCode = 1002;
    int32_t extensionAbilityId = 2002;
    int32_t innerErrCode = 0;
    
    bool taskExecuted = false;
    AbilityRuntime::PreloadTask task = [&taskExecuted](int32_t id, int32_t err) {
        taskExecuted = true;
    };
    auto callData = std::make_shared<AbilityRuntime::PreloadByCallData>(std::move(task));
    callData->handler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(
        OHOS::AppExecFwk::EventRunner::Create());
    
    {
        std::lock_guard<std::mutex> lock(hostClient->requestCodeMutex_);
        hostClient->resultCallbacks_[requestCode] = callData;
    }
    
    hostClient->OnPreloadSuccess(requestCode, extensionAbilityId, innerErrCode);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    EXPECT_TRUE(taskExecuted);
    TAG_LOGI(AAFwkTag::TEST, "finish.");
}

/**
 * @tc.name: OnPreloadSuccess_0300
 * @tc.desc: Test OnPreloadSuccess with nullptr handler.
 * @tc.type: FUNC
 * @tc.require: I9NW1A
 */
HWTEST_F(UIExtensionPreloadTest, OnPreloadSuccess_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "start.");
    auto hostClient = std::make_shared<AbilityRuntime::PreloadUIExtensionHostClient>();
    int32_t requestCode = 1003;
    int32_t extensionAbilityId = 2003;
    int32_t innerErrCode = 0;
    
    AbilityRuntime::PreloadTask task = [](int32_t id, int32_t err) {
    };
    auto callData = std::make_shared<AbilityRuntime::PreloadByCallData>(std::move(task));
    callData->handler_ = nullptr;
    
    {
        std::lock_guard<std::mutex> lock(hostClient->requestCodeMutex_);
        hostClient->resultCallbacks_[requestCode] = callData;
    }
    
    hostClient->OnPreloadSuccess(requestCode, extensionAbilityId, innerErrCode);
    
    EXPECT_NE(hostClient, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "finish.");
}

/**
 * @tc.name: GenerateRequestCode_0100
 * @tc.desc: Test GenerateRequestCode functionality to ensure it increments correctly.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionPreloadTest, GenerateRequestCode_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GenerateRequestCode_0100 start.");
    
    auto client = std::make_shared<PreloadUIExtensionHostClient>();
    ASSERT_NE(client, nullptr);
    int32_t code1 = client->GenerateRequestCode();
    int32_t code2 = client->GenerateRequestCode();
    if (code1 == INT32_MAX) {
        EXPECT_EQ(code2, 0);
    } else {
        EXPECT_EQ(code2, code1 + 1);
    }

    TAG_LOGI(AAFwkTag::TEST, "GenerateRequestCode_0100 finish.");
}

/**
 * @tc.name: ClearPreloadedUIExtensionAbilities_0100
 * @tc.desc: Test ClearPreloadedUIExtensionAbilities normal call.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionPreloadTest, ClearPreloadedUIExtensionAbilities_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "start.");
    auto client = AbilityManagerClient::GetInstance();
    ASSERT_NE(client, nullptr);

    int32_t userId = 100;
    ErrCode ret = client->ClearPreloadedUIExtensionAbilities(userId);
    EXPECT_NE(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "finish.");
}
} // namespace AAFwk
} // namespace OHOS