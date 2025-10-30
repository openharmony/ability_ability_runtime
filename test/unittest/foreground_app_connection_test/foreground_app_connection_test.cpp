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
#include <gmock/gmock.h>

#define private public
#define protected public

#include "ability_manager_errors.h"
#include "foreground_app_connection_data.h"
#include "foreground_app_connection_client.h"
#include "foreground_app_connection_client_impl.h"
#include "foreground_app_connection_stub_impl.h"
#include "hilog_tag_wrapper.h"
#include "mock_native_token.h"
#include "parcel.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace AbilityRuntime {
namespace {
const int32_t TEST_TARGET_PID = 10001;
const int32_t TEST_TARGET_UID = 10002;
const std::string TEST_TARGET_BUNDLE_NAME = "com.ohos.connectionTarget.test";
const int32_t TEST_CALLER_PID = 10003;
const int32_t TEST_CALLER_UID = 10004;
const std::string TEST_CALLER_BUNDLE_NAME = "com.ohos.connnectionCaller.test";

class MyConnectionObserver : public ForegroundAppConnection {
public:
    MyConnectionObserver() {}
    ~MyConnectionObserver() {}

    void OnForegroundAppConnected(const ForegroundAppConnectionData &data)
    {
        isForegroundAppConnected_ = true;
    }

    void OnForegroundAppDisconnected(const ForegroundAppConnectionData &data)
    {
        isForegroundAppDisconnected_ = true;
    }

    void OnForegroundAppCallerStarted(int32_t callerPid, int32_t callerUid, const std::string &bundleName)
    {
        isForegroundAppCallerStarted_ = true;
    }

    void OnServiceDied()
    {
        isServiceDied_ = true;
    }

    bool IsForegroundAppConnected()
    {
        return isForegroundAppConnected_;
    }

    bool IsForegroundAppDisconnected()
    {
        return isForegroundAppDisconnected_;
    }

    bool IsForegroundAppCallerStarted()
    {
        return isForegroundAppCallerStarted_;
    }

    bool IsServiceDied()
    {
        return isServiceDied_;
    }

private:
    bool isForegroundAppConnected_ = false;
    bool isForegroundAppDisconnected_ = false;
    bool isForegroundAppCallerStarted_ = false;
    bool isServiceDied_ = false;
};
}

class ForegroundAppConnectionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ForegroundAppConnectionTest::SetUpTestCase(void) {}

void ForegroundAppConnectionTest::TearDownTestCase(void) {}

void ForegroundAppConnectionTest::SetUp(void) {}

void ForegroundAppConnectionTest::TearDown(void) {}

/**
 * @tc.name: ForegroundAppConnectionData_0100
 * @tc.desc: ForegroundAppConnectionData test.
 * @tc.type: FUNC
 */
HWTEST_F(ForegroundAppConnectionTest, ForegroundAppConnectionData_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ForegroundAppConnectionData_0100 start");

    ForegroundAppConnectionData connectionData;
    connectionData.targetPid_ = TEST_TARGET_PID;
    connectionData.targetUid_ = TEST_TARGET_UID;
    connectionData.targetBundleName_ = TEST_TARGET_BUNDLE_NAME;
    connectionData.callerPid_ = TEST_CALLER_PID;
    connectionData.callerUid_ = TEST_CALLER_UID;
    connectionData.callerBundleName_ = TEST_CALLER_BUNDLE_NAME;

    Parcel data;
    EXPECT_TRUE(connectionData.Marshalling(data));

    std::shared_ptr<ForegroundAppConnectionData> readedData(ForegroundAppConnectionData::Unmarshalling(data));
    EXPECT_TRUE(readedData);

    EXPECT_EQ(connectionData.targetPid_, readedData->targetPid_);
    EXPECT_EQ(connectionData.targetUid_, readedData->targetUid_);
    EXPECT_EQ(connectionData.targetBundleName_, readedData->targetBundleName_);
    EXPECT_EQ(connectionData.callerPid_, readedData->callerPid_);
    EXPECT_EQ(connectionData.callerUid_, readedData->callerUid_);
    EXPECT_EQ(connectionData.callerBundleName_, readedData->callerBundleName_);

    TAG_LOGI(AAFwkTag::TEST, "ForegroundAppConnectionData_0100 end");
}

/**
 * @tc.name: ForegroundAppConnection_0100
 * @tc.desc: test observer callback.
 * @tc.type: FUNC
 */
HWTEST_F(ForegroundAppConnectionTest, ForegroundAppConnection_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ForegroundAppConnection_0100 start");

    auto clientImpl = ForegroundAppConnectionClient::GetInstance().clientImpl_;
    EXPECT_TRUE(clientImpl);

    std::shared_ptr<MyConnectionObserver> myObserver = std::make_shared<MyConnectionObserver>();
    clientImpl->userObservers_.emplace(myObserver);
    ForegroundAppConnectionClient::GetInstance().RegisterObserver(myObserver);

    ForegroundAppConnectionData connectionData;
    clientImpl->HandleOnForegroundAppConnected(connectionData);
    EXPECT_TRUE(myObserver->IsForegroundAppConnected());

    clientImpl->HandleOnForegroundAppDisconnected(connectionData);
    EXPECT_TRUE(myObserver->IsForegroundAppDisconnected());

    clientImpl->HandleOnForegroundAppCallerStarted(TEST_TARGET_PID, TEST_TARGET_UID,
        TEST_TARGET_BUNDLE_NAME);
    EXPECT_TRUE(myObserver->IsForegroundAppCallerStarted());

    myObserver->OnServiceDied();
    ForegroundAppConnectionClient::GetInstance().UnregisterObserver(myObserver);

    TAG_LOGI(AAFwkTag::TEST, "ForegroundAppConnection_0100 end");
}

/**
 * @tc.name: ForegroundAppConnection_0200
 * @tc.desc: test observer callback.
 * @tc.type: FUNC
 */
HWTEST_F(ForegroundAppConnectionTest, ForegroundAppConnection_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ForegroundAppConnection_0200 start");

    auto clientImpl = ForegroundAppConnectionClient::GetInstance().clientImpl_;
    EXPECT_TRUE(clientImpl);
    ForegroundAppConnectionStubImpl foregroundAppConnectionStubImpl(clientImpl);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    foregroundAppConnectionStubImpl.OnRemoteRequest(
        IForegroundAppConnection::ON_FOREGROUND_APP_CONNECTED, data, reply, option);
    foregroundAppConnectionStubImpl.OnRemoteRequest(
        IForegroundAppConnection::ON_FOREGROUND_APP_DISCONNECTED, data, reply, option);
    foregroundAppConnectionStubImpl.OnRemoteRequest(
        IForegroundAppConnection::ON_FOREGROUND_APP_CALLER_STARTED, data, reply, option);

    ForegroundAppConnectionData connectionData;
    connectionData.targetPid_ = TEST_TARGET_PID;
    connectionData.targetUid_ = TEST_TARGET_UID;
    connectionData.targetBundleName_ = TEST_TARGET_BUNDLE_NAME;
    connectionData.callerPid_ = TEST_CALLER_PID;
    connectionData.callerUid_ = TEST_CALLER_UID;
    connectionData.callerBundleName_ = TEST_CALLER_BUNDLE_NAME;

    EXPECT_TRUE(connectionData.Marshalling(data));
    foregroundAppConnectionStubImpl.OnRemoteRequest(
        IForegroundAppConnection::ON_FOREGROUND_APP_CONNECTED, data, reply, option);
    foregroundAppConnectionStubImpl.OnRemoteRequest(
        IForegroundAppConnection::ON_FOREGROUND_APP_DISCONNECTED, data, reply, option);
    foregroundAppConnectionStubImpl.OnRemoteRequest(
        IForegroundAppConnection::ON_FOREGROUND_APP_CALLER_STARTED, data, reply, option);

    TAG_LOGI(AAFwkTag::TEST, "ForegroundAppConnection_0200 end");
}

/**
 * @tc.name: ForegroundAppConnection_0300
 * @tc.desc: test observer callback.
 * @tc.type: FUNC
 * @tc.require: issueI58213
 */
HWTEST_F(ForegroundAppConnectionTest, ForegroundAppConnection_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ForegroundAppConnection_0300 start");

    auto clientImpl = ForegroundAppConnectionClient::GetInstance().clientImpl_;
    EXPECT_TRUE(clientImpl);
    ForegroundAppConnectionStubImpl foregroundAppConnectionStubImpl(nullptr);

    ForegroundAppConnectionData connectionData;
    foregroundAppConnectionStubImpl.OnForegroundAppConnected(connectionData);
    foregroundAppConnectionStubImpl.OnForegroundAppDisconnected(connectionData);
    foregroundAppConnectionStubImpl.OnForegroundAppCallerStarted(TEST_TARGET_PID, TEST_TARGET_UID,
        TEST_TARGET_BUNDLE_NAME);

    TAG_LOGI(AAFwkTag::TEST, "ForegroundAppConnection_0300 end");
}
}  // namespace AbilityRuntime
}  // namespace OHOS
