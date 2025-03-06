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
#include "mock_mission_listener_stub.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace AAFwk {
class MissionListenerStubSecondTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void WriteInterfaceToken(MessageParcel& data);
    sptr<MockMissionListenerStub> stub_{ nullptr };
};

void MissionListenerStubSecondTest::SetUpTestCase(void)
{}
void MissionListenerStubSecondTest::TearDownTestCase(void)
{}
void MissionListenerStubSecondTest::SetUp()
{
    stub_ = new MockMissionListenerStub();
}
void MissionListenerStubSecondTest::TearDown()
{}

void MissionListenerStubSecondTest::WriteInterfaceToken(MessageParcel& data)
{
    data.WriteInterfaceToken(MockMissionListenerStub::GetDescriptor());
}

/*
 * Feature: OnRemoteRequest_001
 * Function: OnRemoteRequest
 * SubFunction: NA
 */
HWTEST_F(MissionListenerStubSecondTest, OnRemoteRequest_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    WriteInterfaceToken(data);
    int res = stub_->OnRemoteRequest(IMissionListener::ON_MISSION_DESTROYED, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * Feature: OnRemoteRequest_002
 * Function: OnRemoteRequest
 * SubFunction: NA
 */
HWTEST_F(MissionListenerStubSecondTest, OnRemoteRequest_002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    WriteInterfaceToken(data);
    int res = stub_->OnRemoteRequest(IMissionListener::ON_MISSION_SNAPSHOT_CHANGED, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * Feature: OnRemoteRequest_003
 * Function: OnRemoteRequest
 * SubFunction: NA
 */
HWTEST_F(MissionListenerStubSecondTest, OnRemoteRequest_003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    WriteInterfaceToken(data);
    int res = stub_->OnRemoteRequest(IMissionListener::ON_MISSION_MOVED_TO_FRONT, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * Feature: OnRemoteRequest_004
 * Function: OnRemoteRequest
 * SubFunction: NA
 */
HWTEST_F(MissionListenerStubSecondTest, OnRemoteRequest_004, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    WriteInterfaceToken(data);
    int res = stub_->OnRemoteRequest(IMissionListener::ON_MISSION_ICON_UPDATED, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * Feature: OnRemoteRequest_005
 * Function: OnRemoteRequest
 * SubFunction: NA
 */
HWTEST_F(MissionListenerStubSecondTest, OnRemoteRequest_005, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    WriteInterfaceToken(data);
    int res = stub_->OnRemoteRequest(IMissionListener::ON_MISSION_CLOSED, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * Feature: OnRemoteRequest_006
 * Function: OnRemoteRequest
 * SubFunction: NA
 */
HWTEST_F(MissionListenerStubSecondTest, OnRemoteRequest_006, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    WriteInterfaceToken(data);
    int res = stub_->OnRemoteRequest(IMissionListener::ON_MISSION_LABEL_UPDATED, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * Feature: OnRemoteRequest_007
 * Function: OnRemoteRequest
 * SubFunction: NA
 */
HWTEST_F(MissionListenerStubSecondTest, OnRemoteRequest_007, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    WriteInterfaceToken(data);
    int res = stub_->OnRemoteRequest(IMissionListener::ON_MISSION_FOCUSED, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/*
 * Feature: OnRemoteRequest_008
 * Function: OnRemoteRequest
 * SubFunction: NA
 */
HWTEST_F(MissionListenerStubSecondTest, OnRemoteRequest_008, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    WriteInterfaceToken(data);
    int res = stub_->OnRemoteRequest(IMissionListener::ON_MISSION_UNFOCUSED, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}
}  // namespace AAFwk
}  // namespace OHOS
