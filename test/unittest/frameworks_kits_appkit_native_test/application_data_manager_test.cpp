/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "application_data_manager.h"
#undef private
#undef protected
#include "ierror_observer.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
class ApplicationDataManagerTest : public testing::Test {
public:
    ApplicationDataManagerTest()
    {}
    ~ApplicationDataManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static bool Flag;
    void SetUp();
    void TearDown();
};

class MyObserver : public IErrorObserver {
    void OnUnhandledException(std::string errMsg) override;
    void OnExceptionObject(const AppExecFwk::ErrorObject &errorObj) override;
};

bool ApplicationDataManagerTest::Flag = false;

void ApplicationDataManagerTest::SetUpTestCase(void)
{}

void ApplicationDataManagerTest::TearDownTestCase(void)
{}

void ApplicationDataManagerTest::SetUp(void)
{
}

void ApplicationDataManagerTest::TearDown(void)
{}

void MyObserver::OnUnhandledException(std::string errMsg)
{
    GTEST_LOG_(INFO) << "OnUnhandledException come, errMsg is" << errMsg;
    ApplicationDataManagerTest::Flag = true;
}

void MyObserver::OnExceptionObject(const AppExecFwk::ErrorObject &errorObj)
{
    GTEST_LOG_(INFO) << "OnExceptionObject come, errorObj.name is " << errorObj.name <<
                        " errorObj.message is " << errorObj.message << " errorObj.stack is " << errorObj.stack;
    EXPECT_STREQ("errorName", errorObj.name.c_str());
    EXPECT_STREQ("errorMessage", errorObj.message.c_str());
    EXPECT_STREQ("errorStack", errorObj.stack.c_str());
}

/**
 * @tc.number: ApplicationDataManager_AddErrorObservers_001
 * @tc.name: RegisterAbilityLifecycleCallbacks
 * @tc.desc: Test whether registerabilitylifecyclecallbacks and are called normally.
 */
HWTEST_F(ApplicationDataManagerTest, ApplicationDataManager_AddErrorObservers_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "ApplicationDataManager_AddErrorObservers_001 start";

    std::shared_ptr<MyObserver> observer = std::make_shared<MyObserver>();
    ApplicationDataManager::GetInstance().AddErrorObserver(observer);
    ApplicationDataManager::GetInstance().NotifyUnhandledException("test");
    EXPECT_EQ(true, ApplicationDataManagerTest::Flag);
    GTEST_LOG_(INFO) << "ApplicationDataManager_AddErrorObservers_001 end";
}

/**
 * @tc.number: ApplicationDataManager_RemoveErrorObserver_001
 * @tc.name: ApplicationDataManager RemoveErrorObserver
 * @tc.desc: Test whether remove Registerabilitylifecyclecallbacks and are called normally.
 */
HWTEST_F(ApplicationDataManagerTest, ApplicationDataManager_RemoveErrorObserver_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "ApplicationDataManager_RemoveErrorObserver_001 start";
    std::shared_ptr<MyObserver> observer = std::make_shared<MyObserver>();
    ApplicationDataManager::GetInstance().AddErrorObserver(observer);
    ApplicationDataManager::GetInstance().NotifyUnhandledException("test");
    EXPECT_EQ(true, ApplicationDataManagerTest::Flag);
    ApplicationDataManager::GetInstance().RemoveErrorObserver();
    EXPECT_EQ(nullptr, ApplicationDataManager::GetInstance().errorObserver_);
    GTEST_LOG_(INFO) << "ApplicationDataManager_RemoveErrorObserver_001 end";
}

/**
 * @tc.number: ApplicationDataManager_RemoveErrorObserver_002
 * @tc.name: ApplicationDataManager RemoveErrorObserver
 * @tc.desc: Test whether remove Registerabilitylifecyclecallbacks and are called normally.
 */
HWTEST_F(ApplicationDataManagerTest, ApplicationDataManager_RemoveErrorObserver_002, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "ApplicationDataManager_RemoveErrorObserver_002 start";
    std::shared_ptr<MyObserver> observer = std::make_shared<MyObserver>();
    ApplicationDataManager::GetInstance().AddErrorObserver(observer);
    ApplicationDataManager::GetInstance().NotifyETSUnhandledException("test");
    EXPECT_EQ(true, ApplicationDataManagerTest::Flag);
    ApplicationDataManager::GetInstance().RemoveErrorObserver();
    EXPECT_EQ(nullptr, ApplicationDataManager::GetInstance().errorObserver_);
    GTEST_LOG_(INFO) << "ApplicationDataManager_RemoveErrorObserver_002 end";
}

/**
 * @tc.number: ApplicationDataManager_NotifyExceptionObject_001
 * @tc.name: ApplicationDataManager NotifyExceptionObject
 * @tc.desc: Test whether NotifyExceptionObject are called normally.
 */
HWTEST_F(ApplicationDataManagerTest, ApplicationDataManager_NotifyExceptionObject_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "ApplicationDataManager_NotifyExceptionObject_001 start";
    AppExecFwk::ErrorObject errorObj;
    errorObj.name = "errorName";
    errorObj.message = "errorMessage";
    errorObj.stack = "errorStack";
    std::shared_ptr<MyObserver> observer = std::make_shared<MyObserver>();
    ApplicationDataManager::GetInstance().AddErrorObserver(observer);
    EXPECT_NE(nullptr, ApplicationDataManager::GetInstance().errorObserver_);
    EXPECT_TRUE(ApplicationDataManager::GetInstance().NotifyExceptionObject(errorObj));
    ApplicationDataManager::GetInstance().RemoveErrorObserver();
    EXPECT_EQ(nullptr, ApplicationDataManager::GetInstance().errorObserver_);
    GTEST_LOG_(INFO) << "ApplicationDataManager_NotifyExceptionObject_001 end";
}

/**
 * @tc.number: ApplicationDataManager_NotifyExceptionObject_002
 * @tc.name: ApplicationDataManager NotifyExceptionObject
 * @tc.desc: Test whether NotifyExceptionObject are called normally.
 */
HWTEST_F(ApplicationDataManagerTest, ApplicationDataManager_NotifyExceptionObject_002, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "ApplicationDataManager_NotifyExceptionObject_002 start";
    AppExecFwk::ErrorObject errorObj;
    errorObj.name = "errorName";
    errorObj.message = "errorMessage";
    errorObj.stack = "errorStack";
    ApplicationDataManager::GetInstance().RemoveErrorObserver();
    EXPECT_EQ(nullptr, ApplicationDataManager::GetInstance().errorObserver_);
    EXPECT_FALSE(ApplicationDataManager::GetInstance().NotifyExceptionObject(errorObj));
    GTEST_LOG_(INFO) << "ApplicationDataManager_NotifyExceptionObject_002 end";
}

/**
 * @tc.number: ApplicationDataManager_NotifyETSExceptionObject_001
 * @tc.name: ApplicationDataManager NotifyExceptionObject
 * @tc.desc: Test whether NotifyETSExceptionObject are called normally.
 */
HWTEST_F(ApplicationDataManagerTest,
    ApplicationDataManager_NotifyETSExceptionObject_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "ApplicationDataManager_NotifyETSExceptionObject_001 start";
    AppExecFwk::ErrorObject errorObj;
    errorObj.name = "errorName";
    errorObj.message = "errorMessage";
    errorObj.stack = "errorStack";
    ApplicationDataManager::GetInstance().RemoveErrorObserver();
    EXPECT_EQ(nullptr, ApplicationDataManager::GetInstance().errorObserver_);
    EXPECT_FALSE(ApplicationDataManager::GetInstance().NotifyETSExceptionObject(errorObj));
    GTEST_LOG_(INFO) << "ApplicationDataManager_NotifyETSExceptionObject_001 end";
}

/**
 * @tc.number: ApplicationDataManager_NotifyETSErrorObject_001
 * @tc.name: ApplicationDataManager NotifyExceptionObject
 * @tc.desc: Test whether NotifyETSErrorObject are called normally.
 */
HWTEST_F(ApplicationDataManagerTest,
    ApplicationDataManager_NotifyETSErrorObject_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "ApplicationDataManager_NotifyETSErrorObject_001 start";
    AppExecFwk::ErrorObject errorObj;
    ApplicationDataManager::GetInstance().NotifyETSErrorObject(errorObj);
    errorObj.name = "errorName";
    errorObj.message = "errorMessage";
    errorObj.stack = "errorStack";
    EXPECT_EQ(nullptr, ApplicationDataManager::GetInstance().errorCallback_);
    ApplicationDataManager::GetInstance().NotifyETSErrorObject(errorObj);
    auto errorCallback = [](const AppExecFwk::ErrorObject &errorObj) {
        printf("test\n");
    };
    ApplicationDataManager::GetInstance().SetErrorHandlerCallback(errorCallback);
    EXPECT_NE(nullptr, ApplicationDataManager::GetInstance().errorCallback_);
    ApplicationDataManager::GetInstance().NotifyETSErrorObject(errorObj);
    GTEST_LOG_(INFO) << "ApplicationDataManager_NotifyETSErrorObject_001 end";
}
 
/**
 * @tc.number: ApplicationDataManager_IsUncatchable_001
 * @tc.name: ApplicationDataManager IsUncatchable
 * @tc.desc: Test whether IsUncatchable are called normally.
 */
HWTEST_F(ApplicationDataManagerTest, ApplicationDataManager_IsUncatchable_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "ApplicationDataManager_IsUncatchable_001 start";
    ApplicationDataManager::GetInstance().SetIsUncatchable(true);
    EXPECT_TRUE(ApplicationDataManager::GetInstance().GetIsUncatchable());
    ApplicationDataManager::GetInstance().SetIsUncatchable(false);
    EXPECT_TRUE(!ApplicationDataManager::GetInstance().GetIsUncatchable());
    GTEST_LOG_(INFO) << "ApplicationDataManager_IsUncatchable_001 end";
}

/**
 * @tc.number: ApplicationDataManager_NotifyLeakObject_001
 * @tc.name: ApplicationDataManager NotifyLeakObject
 * @tc.desc: Test whether NotifyLeakObject returns false when no leak observer is set.
 */
HWTEST_F(ApplicationDataManagerTest, ApplicationDataManager_NotifyLeakObject_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "ApplicationDataManager_NotifyLeakObject_001 start";
    LeakObject testObj{
        .leakType = LeakType::PSS_MEMORY,
        .leakSize = 1024 * 1024,  // 1MB
        .detailInfo = {
            .arktsSize = 512 * 1024,
            .nativeSize = 512 * 1024,
            .ionSize = 0,
            .gpuSize = 0,
            .ashmemSize = 0,
            .otherSize = 0
        }
    };
    bool result = ApplicationDataManager::GetInstance().NotifyLeakObject(testObj);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "ApplicationDataManager_NotifyLeakObject_001 end";
}

/**
 * @tc.number: ApplicationDataManager_NotifyLeakObject_002
 * @tc.name: ApplicationDataManager NotifyLeakObject WithObserver
 * @tc.desc: Test whether NotifyLeakObject executes callback normally
 */
HWTEST_F(ApplicationDataManagerTest, ApplicationDataManager_NotifyLeakObject_002, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "ApplicationDataManager_NotifyLeakObject_002 start";
    LeakObject testObj{
        .leakType = LeakType::ION_MEMORY,
        .leakSize = 2048 * 1024,  // 2MB
        .detailInfo = {
            .arktsSize = 0,
            .nativeSize = 0,
            .ionSize = 2048 * 1024,
            .gpuSize = 0,
            .ashmemSize = 0,
            .otherSize = 0
        }
    };
    bool callbackExecuted = false;
    const bool expectedCallbackResult = true;
    auto testCallback = [&callbackExecuted, expectedCallbackResult](const LeakObject &obj) -> bool {
        callbackExecuted = true;
        EXPECT_EQ(obj.leakType, LeakType::ION_MEMORY);
        EXPECT_EQ(obj.leakSize, 2048 * 1024);
        EXPECT_EQ(obj.detailInfo.arktsSize, 0);
        EXPECT_EQ(obj.detailInfo.nativeSize, 0);
        EXPECT_EQ(obj.detailInfo.ionSize, 2048 * 1024);
        EXPECT_EQ(obj.detailInfo.gpuSize, 0);
        EXPECT_EQ(obj.detailInfo.ashmemSize, 0);
        EXPECT_EQ(obj.detailInfo.otherSize, 0);
        return expectedCallbackResult;
    };
    ApplicationDataManager::GetInstance().SetLeakObserver(testCallback);
    bool result = ApplicationDataManager::GetInstance().NotifyLeakObject(testObj);
    EXPECT_TRUE(callbackExecuted);
    EXPECT_EQ(result, expectedCallbackResult);
    GTEST_LOG_(INFO) << "ApplicationDataManager_NotifyLeakObject_002 end";
}
}  // namespace AppExecFwk
}  // namespace OHOS
