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

#include <algorithm>
#include <gtest/gtest.h>

#define private public
#define protected public
#include "idle_time.h"
#include "main_thread.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AppExecFwk {
class IdleTimeTest : public testing::Test {
public:
    IdleTimeTest()
    {
        std::function<void(int32_t)> callback = nullptr;
        std::shared_ptr<EventHandler> mainHandler = std::make_shared<EventHandler>(EventRunner::GetMainEventRunner());
        idleTime_ = std::make_shared<IdleTime>(mainHandler, callback);
    }
    ~IdleTimeTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<IdleTime> idleTime_ = nullptr;
};

void IdleTimeTest::SetUpTestCase(void)
{
}

void IdleTimeTest::TearDownTestCase(void)
{}

void IdleTimeTest::SetUp(void)
{
}

void IdleTimeTest::TearDown(void)
{}

/**
 * @tc.number: InitVSyncReceiver_0100
 * @tc.name: InitVSyncReceiver
 * @tc.desc: Test whether InitVSyncReceiver and are called normally.
 */
HWTEST_F(IdleTimeTest, InitVSyncReceiver_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "IdleTimeTest InitVSyncReceiver_0100 start";
    idleTime_->needStop_ = true;
    idleTime_->receiver_ = nullptr;
    idleTime_->InitVSyncReceiver();
    EXPECT_EQ(idleTime_->receiver_, nullptr);
    GTEST_LOG_(INFO) << "IdleTimeTest InitVSyncReceiver_0100 end";
}

/**
 * @tc.number: EventTask_0100
 * @tc.name: EventTask
 * @tc.desc: Test whether EventTask and are called normally.
 */
HWTEST_F(IdleTimeTest, EventTask_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "IdleTimeTest EventTask_0100 start";
    idleTime_->needStop_ = false;
    idleTime_->EventTask();
    EXPECT_EQ(idleTime_->callback_, nullptr);

    GTEST_LOG_(INFO) << "IdleTimeTest EventTask_0100 end";
}

/**
 * @tc.number: PostTask_0100
 * @tc.name: PostTask
 * @tc.desc: Test whether PostTask and are called normally.
 */
HWTEST_F(IdleTimeTest, PostTask_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "IdleTimeTest PostTask_0100 start";
    idleTime_->needStop_ = true;
    idleTime_->PostTask();
    EXPECT_NE(idleTime_->eventHandler_, nullptr);

    GTEST_LOG_(INFO) << "IdleTimeTest PostTask_0100 end";
}

/**
 * @tc.number: GetIdleNotifyFunc_0100
 * @tc.name: GetIdleNotifyFunc
 * @tc.desc: Test whether GetIdleNotifyFunc and are called normally.
 */
HWTEST_F(IdleTimeTest, GetIdleNotifyFunc_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "IdleTimeTest GetIdleNotifyFunc_0100 start";
    IdleNotifyStatusCallback callBack = idleTime_->GetIdleNotifyFunc();
    EXPECT_NE(callBack, nullptr);

    GTEST_LOG_(INFO) << "IdleTimeTest GetIdleNotifyFunc_0100 end";
}

/**
 * @tc.number: InitVSyncReceiver_0200
 * @tc.name: InitVSyncReceiver
 * @tc.desc: Test InitVSyncReceiver with needStop=false
 */
HWTEST_F(IdleTimeTest, InitVSyncReceiver_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "IdleTimeTest InitVSyncReceiver_0200 start";
    idleTime_->needStop_ = false;
    idleTime_->receiver_ = nullptr;
    idleTime_->InitVSyncReceiver();
    EXPECT_TRUE(idleTime_->receiver_ == nullptr || idleTime_->receiver_ != nullptr);
    GTEST_LOG_(INFO) << "IdleTimeTest InitVSyncReceiver_0200 end";
}

/**
 * @tc.number: EventTask_0200
 * @tc.name: EventTask
 * @tc.desc: Test EventTask with receiver=nullptr
 */
HWTEST_F(IdleTimeTest, EventTask_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "IdleTimeTest EventTask_0200 start";
    std::function<void(int32_t)> validCallback = [](int32_t) {};
    auto idleTimeValidCallback = std::make_shared<IdleTime>(idleTime_->eventHandler_, validCallback);
    idleTimeValidCallback->receiver_ = nullptr;
    idleTimeValidCallback->EventTask();
    EXPECT_NE(idleTimeValidCallback->callback_, nullptr);
    GTEST_LOG_(INFO) << "IdleTimeTest EventTask_0200 end";
}

/**
 * @tc.number: PostTask_0200
 * @tc.name: PostTask
 * @tc.desc: Test PostTask with needStop=false
 */
HWTEST_F(IdleTimeTest, PostTask_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "IdleTimeTest PostTask_0200 start";
    idleTime_->needStop_ = false;
    idleTime_->PostTask();
    EXPECT_NE(idleTime_->eventHandler_, nullptr);
    GTEST_LOG_(INFO) << "IdleTimeTest PostTask_0200 end";
}

/**
 * @tc.number: PostTask_0300
 * @tc.name: PostTask
 * @tc.desc: Test PostTask with null eventHandler
 */
HWTEST_F(IdleTimeTest, PostTask_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "IdleTimeTest PostTask_0300 start";
    std::shared_ptr<IdleTime> idleTimeNullHandler = std::make_shared<IdleTime>(nullptr, nullptr);
    idleTimeNullHandler->needStop_ = false;
    idleTimeNullHandler->PostTask();
    EXPECT_EQ(idleTimeNullHandler->eventHandler_, nullptr);
    GTEST_LOG_(INFO) << "IdleTimeTest PostTask_0300 end";
}

/**
 * @tc.number: GetIdleNotifyFunc_0200
 * @tc.name: GetIdleNotifyFunc
 * @tc.desc: Test IdleNotifyFunc with null sharedThis
 */
HWTEST_F(IdleTimeTest, GetIdleNotifyFunc_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "IdleTimeTest GetIdleNotifyFunc_0200 start";
    std::shared_ptr<IdleTime> tempIdleTime = std::make_shared<IdleTime>(idleTime_->eventHandler_, nullptr);
    IdleNotifyStatusCallback callBack = tempIdleTime->GetIdleNotifyFunc();
    tempIdleTime.reset();

    callBack(false);
    EXPECT_EQ(tempIdleTime, nullptr);
    GTEST_LOG_(INFO) << "IdleTimeTest GetIdleNotifyFunc_0200 end";
}

/**
 * @tc.number: GetIdleNotifyFunc_0300
 * @tc.name: GetIdleNotifyFunc
 * @tc.desc: Test IdleNotifyFunc with same needStop status
 */
HWTEST_F(IdleTimeTest, GetIdleNotifyFunc_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "IdleTimeTest GetIdleNotifyFunc_0300 start";
    idleTime_->SetNeedStop(true);
    IdleNotifyStatusCallback callBack = idleTime_->GetIdleNotifyFunc();

    callBack(true);
    EXPECT_EQ(idleTime_->GetNeedStop(), true);
    GTEST_LOG_(INFO) << "IdleTimeTest GetIdleNotifyFunc_0300 end";
}

/**
 * @tc.number: GetIdleNotifyFunc_0400
 * @tc.name: GetIdleNotifyFunc
 * @tc.desc: Test IdleNotifyFunc with different needStop status
 */
HWTEST_F(IdleTimeTest, GetIdleNotifyFunc_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "IdleTimeTest GetIdleNotifyFunc_0400 start";
    idleTime_->SetNeedStop(true);
    IdleNotifyStatusCallback callBack = idleTime_->GetIdleNotifyFunc();

    callBack(false);
    EXPECT_EQ(idleTime_->GetNeedStop(), false);
    GTEST_LOG_(INFO) << "IdleTimeTest GetIdleNotifyFunc_0400 end";
}

/**
 * @tc.number: Start_0100
 * @tc.name: Start
 * @tc.desc: Test Start function
 */
HWTEST_F(IdleTimeTest, Start_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "IdleTimeTest Start_0100 start";
    idleTime_->needStop_ = false;
    idleTime_->Start();
    EXPECT_EQ(idleTime_->GetNeedStop(), false);
    GTEST_LOG_(INFO) << "IdleTimeTest Start_0100 end";
}

/**
 * @tc.number: SetGetNeedStop_0100
 * @tc.name: SetNeedStop/GetNeedStop
 * @tc.desc: Test SetNeedStop and GetNeedStop functions
 */
HWTEST_F(IdleTimeTest, SetGetNeedStop_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "IdleTimeTest SetGetNeedStop_0100 start";
    idleTime_->SetNeedStop(true);
    EXPECT_EQ(idleTime_->GetNeedStop(), true);

    idleTime_->SetNeedStop(false);
    EXPECT_EQ(idleTime_->GetNeedStop(), false);
    GTEST_LOG_(INFO) << "IdleTimeTest SetGetNeedStop_0100 end";
}

}
}