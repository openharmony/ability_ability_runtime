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

#include "freeze_util.h"
#include "hilog_tag_wrapper.h"
#include "ipc_object_stub.h"
#include "time_util.h"
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class FreezeUtilTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void FreezeUtilTest::SetUpTestCase(void)
{}

void FreezeUtilTest::TearDownTestCase(void)
{}

void FreezeUtilTest::SetUp()
{}

void FreezeUtilTest::TearDown()
{}

/*
 * @tc.number    : FreezeUtilTest_001
 * @tc.name      : FreezeUtilTest
 * @tc.desc      : Test Function FreezeUtil::GetInstance() and AddLifecycleEvent() and GetLifecycleEvent()
 */
HWTEST_F(FreezeUtilTest, FreezeUtilTest_001, TestSize.Level1)
{
    sptr<IPCObjectStub> token(new IPCObjectStub(u"testStub"));
    EXPECT_EQ(FreezeUtil::GetInstance().GetLifecycleEvent(token), "");
    FreezeUtil::GetInstance().AddLifecycleEvent(token, "firstEntry");
    EXPECT_EQ(FreezeUtil::GetInstance().GetLifecycleEvent(token),
        TimeUtil::DefaultCurrentTimeStr() + "; " + "firstEntry");

    FreezeUtil::GetInstance().AddLifecycleEvent(token, "secondEntry");
    EXPECT_EQ(FreezeUtil::GetInstance().GetLifecycleEvent(token), TimeUtil::DefaultCurrentTimeStr() + "; " +
        "firstEntry\n" + TimeUtil::DefaultCurrentTimeStr() + "; " + "secondEntry");
    TAG_LOGI(AAFwkTag::TEST, "FreezeUtilTest_001 is end");
}

/*
 * @tc.number    : FreezeUtilTest_002
 * @tc.name      : FreezeUtilTest
 * @tc.desc      : Test Function FreezeUtil::GetInstance() and DeleteLifecycleEvent() and GetLifecycleEvent()
 */
HWTEST_F(FreezeUtilTest, FreezeUtilTest_002, TestSize.Level1)
{
    sptr<IPCObjectStub> token(new IPCObjectStub(u"testStub"));
    FreezeUtil::GetInstance().AddLifecycleEvent(token, "testDeleteEntry");
    EXPECT_EQ(FreezeUtil::GetInstance().GetLifecycleEvent(token),
        TimeUtil::DefaultCurrentTimeStr() + "; " + "testDeleteEntry");
    FreezeUtil::GetInstance().DeleteLifecycleEvent(token);
    EXPECT_EQ(FreezeUtil::GetInstance().GetLifecycleEvent(token), "");
    TAG_LOGI(AAFwkTag::TEST, "FreezeUtilTest_002 is end");
}

/*
 * @tc.number    : FreezeUtilTest_003
 * @tc.name      : FreezeUtilTest
 * @tc.desc      : Test Function DeleteLifecycleEvent() and DeleteLifecycleEventInner()
 */
HWTEST_F(FreezeUtilTest, FreezeUtilTest_003, TestSize.Level1)
{
    sptr<IRemoteObject> token1(new IPCObjectStub());
    FreezeUtil::GetInstance().AddLifecycleEvent(token1, "testDeleteLifecyleEventForground");
    EXPECT_EQ(FreezeUtil::GetInstance().GetLifecycleEvent(token1),
        TimeUtil::DefaultCurrentTimeStr() + "; " + "testDeleteLifecyleEventForground");

    sptr<IRemoteObject> token2(new IPCObjectStub());
    FreezeUtil::GetInstance().AddLifecycleEvent(token2, "testDeleteLifecyleEventBackground");
    EXPECT_EQ(FreezeUtil::GetInstance().GetLifecycleEvent(token2),
        TimeUtil::DefaultCurrentTimeStr() + "; " + "testDeleteLifecyleEventBackground");

    FreezeUtil::GetInstance().DeleteLifecycleEvent(token1);
    EXPECT_EQ(FreezeUtil::GetInstance().GetLifecycleEvent(token1), "");
    FreezeUtil::GetInstance().DeleteLifecycleEvent(token2);
    EXPECT_EQ(FreezeUtil::GetInstance().GetLifecycleEvent(token2), "");

    TAG_LOGI(AAFwkTag::TEST, "FreezeUtilTest_003 is end");
}
}
}
