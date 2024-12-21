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
#include "app_spawn_client.h"
#undef private
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class AppSpawnClientSecondTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AppSpawnClientSecondTest::SetUpTestCase(void)
{}

void AppSpawnClientSecondTest::TearDownTestCase(void)
{}

void AppSpawnClientSecondTest::SetUp()
{}

void AppSpawnClientSecondTest::TearDown()
{}

// Scenario1: Test when startMsg.flags is 0 and all other flags are false.
HWTEST_F(AppSpawnClientSecondTest, SetStartFlags_001, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.flags = 0;
    startMsg.atomicServiceFlag = false;
    startMsg.strictMode = false;
    startMsg.isolatedExtension = false;
#ifdef SUPPORT_CHILD_PROCESS
    startMsg.childProcessType = 0;
#endif // SUPPORT_CHILD_PROCESS
    AppSpawnReqMsgHandle reqHandle = nullptr;
    EXPECT_NE(appSpawnClient.SetStartFlags(startMsg, reqHandle), 0);
}

// Scenario2: Test when startMsg.flags is START_FLAG_TEST_NUM and all other flags are false.
HWTEST_F(AppSpawnClientSecondTest, SetStartFlags_002, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.flags = 1;
    startMsg.atomicServiceFlag = false;
    startMsg.strictMode = false;
    startMsg.isolatedExtension = false;
#ifdef SUPPORT_CHILD_PROCESS
    startMsg.childProcessType = 0;
#endif // SUPPORT_CHILD_PROCESS
    AppSpawnReqMsgHandle reqHandle = nullptr;
    EXPECT_NE(appSpawnClient.SetStartFlags(startMsg, reqHandle), 0);
}

// Scenario3: Test when startMsg.atomicServiceFlag is true and all other flags are false.
HWTEST_F(AppSpawnClientSecondTest, SetStartFlags_003, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.flags = 0;
    startMsg.atomicServiceFlag = true;
    startMsg.strictMode = false;
    startMsg.isolatedExtension = false;
#ifdef SUPPORT_CHILD_PROCESS
    startMsg.childProcessType = 0;
#endif // SUPPORT_CHILD_PROCESS
    AppSpawnReqMsgHandle reqHandle = nullptr;
    EXPECT_NE(appSpawnClient.SetStartFlags(startMsg, reqHandle), 0);
}

// Scenario4: Test when startMsg.strictMode is true and all other flags are false.
HWTEST_F(AppSpawnClientSecondTest, SetStartFlags_004, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.flags = 0;
    startMsg.atomicServiceFlag = false;
    startMsg.strictMode = true;
    startMsg.isolatedExtension = false;
#ifdef SUPPORT_CHILD_PROCESS
    startMsg.childProcessType = 0;
#endif // SUPPORT_CHILD_PROCESS
    AppSpawnReqMsgHandle reqHandle = nullptr;
    EXPECT_NE(appSpawnClient.SetStartFlags(startMsg, reqHandle), 0);
}

// Scenario5: Test when startMsg.isolatedExtension is true and all other flags are false.
HWTEST_F(AppSpawnClientSecondTest, SetStartFlags_005, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.flags = 0;
    startMsg.atomicServiceFlag = false;
    startMsg.strictMode = false;
    startMsg.isolatedExtension = true;
#ifdef SUPPORT_CHILD_PROCESS
    startMsg.childProcessType = 0;
#endif // SUPPORT_CHILD_PROCESS
    AppSpawnReqMsgHandle reqHandle = nullptr;
    EXPECT_NE(appSpawnClient.SetStartFlags(startMsg, reqHandle), 0);
}

// Scenario6: Test when startMsg.childProcessType is not 0 and all other flags are false.
HWTEST_F(AppSpawnClientSecondTest, SetStartFlags_006, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.flags = 0;
    startMsg.atomicServiceFlag = false;
    startMsg.strictMode = false;
    startMsg.isolatedExtension = false;
#ifdef SUPPORT_CHILD_PROCESS
    startMsg.childProcessType = 1;
#endif // SUPPORT_CHILD_PROCESS
    AppSpawnReqMsgHandle reqHandle = nullptr;
    EXPECT_NE(appSpawnClient.SetStartFlags(startMsg, reqHandle), 0);
}

// Scenario7: Test when startMsg.flags is START_FLAG_TEST_NUM and all other flags are true.
HWTEST_F(AppSpawnClientSecondTest, SetStartFlags_007, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.flags = 1;
    startMsg.atomicServiceFlag = true;
    startMsg.strictMode = true;
    startMsg.isolatedExtension = true;
#ifdef SUPPORT_CHILD_PROCESS
    startMsg.childProcessType = 1;
#endif // SUPPORT_CHILD_PROCESS
    AppSpawnReqMsgHandle reqHandle = nullptr;
    EXPECT_NE(appSpawnClient.SetStartFlags(startMsg, reqHandle), 0);
}

// Scenario1: Test when provisionType is empty then function returns 0.
HWTEST_F(AppSpawnClientSecondTest, AppspawnSetExtMsgMore_001, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "testProcName";
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(startMsg.code), startMsg.procName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = appSpawnClient.AppspawnSetExtMsgMore(startMsg, reqHandle);
    ASSERT_EQ(ret, 0);
}

// Scenario2: Test when provisionType is not empty then function returns 0.
HWTEST_F(AppSpawnClientSecondTest, AppspawnSetExtMsgMore_002, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.provisionType = "test";
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "testProcName";
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(startMsg.code), startMsg.procName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = appSpawnClient.AppspawnSetExtMsgMore(startMsg, reqHandle);
    ASSERT_EQ(ret, 0);
}

// Scenario3: Test when extensionSandboxPath is empty then function returns 0.
HWTEST_F(AppSpawnClientSecondTest, AppspawnSetExtMsgMore_003, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "testProcName";
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(startMsg.code), startMsg.procName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = appSpawnClient.AppspawnSetExtMsgMore(startMsg, reqHandle);
    ASSERT_EQ(ret, 0);
}

// Scenario4: Test when extensionSandboxPath is not empty then function returns 0.
HWTEST_F(AppSpawnClientSecondTest, AppspawnSetExtMsgMore_004, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.extensionSandboxPath = "test";
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "testProcName";
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(startMsg.code), startMsg.procName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = appSpawnClient.AppspawnSetExtMsgMore(startMsg, reqHandle);
    ASSERT_EQ(ret, 0);
}

// Scenario5: Test when processType is empty then function returns 0.
HWTEST_F(AppSpawnClientSecondTest, AppspawnSetExtMsgMore_005, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "testProcName";
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(startMsg.code), startMsg.procName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = appSpawnClient.AppspawnSetExtMsgMore(startMsg, reqHandle);
    ASSERT_EQ(ret, 0);
}

// Scenario6: Test when processType is not empty then function returns 0.
HWTEST_F(AppSpawnClientSecondTest, AppspawnSetExtMsgMore_006, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.processType = "test";
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "testProcName";
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(startMsg.code), startMsg.procName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = appSpawnClient.AppspawnSetExtMsgMore(startMsg, reqHandle);
    ASSERT_EQ(ret, 0);
}

#ifdef SUPPORT_CHILD_PROCESS
// Scenario7: Test when maxChildProcess is 0 then function returns 0.
HWTEST_F(AppSpawnClientSecondTest, AppspawnSetExtMsgMore_007, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.maxChildProcess = 0;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "testProcName";
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(startMsg.code), startMsg.procName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = appSpawnClient.AppspawnSetExtMsgMore(startMsg, reqHandle);
    ASSERT_EQ(ret, 0);
}

// Scenario8: Test when maxChildProcess is not 0 then function returns 0.
HWTEST_F(AppSpawnClientSecondTest, AppspawnSetExtMsgMore_008, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.maxChildProcess = 1;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "testProcName";
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(startMsg.code), startMsg.procName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = appSpawnClient.AppspawnSetExtMsgMore(startMsg, reqHandle);
    ASSERT_EQ(ret, 0);
}
#endif // SUPPORT_CHILD_PROCESS

// Scenario9: Test when fds is empty then function returns 0.
HWTEST_F(AppSpawnClientSecondTest, AppspawnSetExtMsgMore_009, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "testProcName";
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(startMsg.code), startMsg.procName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = appSpawnClient.AppspawnSetExtMsgMore(startMsg, reqHandle);
    ASSERT_EQ(ret, 0);
}

// Scenario10: Test when fds is not empty then function returns 0.
HWTEST_F(AppSpawnClientSecondTest, AppspawnSetExtMsgMore_010, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.fds["fds"] = 1;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "testProcName";
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(startMsg.code), startMsg.procName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = appSpawnClient.AppspawnSetExtMsgMore(startMsg, reqHandle);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: AppspawnSetExtMsg_001
 * @tc.desc: AppspawnSetExtMsg.
 * @tc.type: FUNC
 */
HWTEST_F(AppSpawnClientSecondTest, AppspawnSetExtMsg_001, TestSize.Level0)
{
    auto asc = std::make_shared<AppSpawnClient>(true);
    AppSpawnStartMsg startMsg;
    startMsg.renderParam = "test";
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "testProcName";
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(startMsg.code), startMsg.procName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = asc->AppspawnSetExtMsg(startMsg, reqHandle);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AppspawnSetExtMsg_002
 * @tc.desc: AppspawnSetExtMsg.
 * @tc.type: FUNC
 */
HWTEST_F(AppSpawnClientSecondTest, AppspawnSetExtMsg_002, TestSize.Level0)
{
    auto asc = std::make_shared<AppSpawnClient>(true);
    AppSpawnStartMsg startMsg;
    startMsg.renderParam = "test";
    BaseSharedBundleInfo bsbi;
    startMsg.hspList.push_back(bsbi);
    DataGroupInfo dgi;
    startMsg.dataGroupInfoList.push_back(dgi);
    startMsg.overlayInfo = "testOverlayinfo";
    startMsg.appEnv["one"] = "testAppEnv";
    startMsg.atomicAccount = "testAtomicAccount";
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "testProcName";
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(startMsg.code), startMsg.procName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = asc->AppspawnSetExtMsg(startMsg, reqHandle);
    EXPECT_EQ(ret, ERR_OK);
}

// Scenario1: Test when reqHandle is nullptr.
HWTEST_F(AppSpawnClientSecondTest, AppspawnCreateDefaultMsg_001, TestSize.Level0)
{
    auto asc = std::make_shared<AppSpawnClient>(true);
    AppSpawnReqMsgHandle reqHandle = nullptr;
    AppSpawnStartMsg startMsg;
    int ret = asc->AppspawnCreateDefaultMsg(startMsg, reqHandle);
    EXPECT_NE(ret, ERR_OK);
}

// Scenario1: Test when reqHandle is not nullptr.
HWTEST_F(AppSpawnClientSecondTest, AppspawnCreateDefaultMsg_002, TestSize.Level0)
{
    auto asc = std::make_shared<AppSpawnClient>(true);
    AppSpawnStartMsg startMsg;
    startMsg.uid = 1;
    startMsg.gid = 1;
    startMsg.gids.push_back(1);
    DataGroupInfo dgi;
    startMsg.dataGroupInfoList.push_back(dgi);
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "testProcName";
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(startMsg.code), startMsg.procName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = asc->AppspawnCreateDefaultMsg(startMsg, reqHandle);
    EXPECT_NE(ret, ERR_OK);
}

// Scenario1: Test when startMsg.code is MSG_APP_SPAWN and uid is negative.
HWTEST_F(AppSpawnClientSecondTest, VerifyMsg_ShouldReturnFalse_WhenUidIsNegative, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.uid = -1;
    EXPECT_FALSE(appSpawnClient.VerifyMsg(startMsg));
}

// Scenario2: Test when startMsg.code is MSG_APP_SPAWN and gid is negative.
HWTEST_F(AppSpawnClientSecondTest, VerifyMsg_ShouldReturnFalse_WhenGidIsNegative, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.gid = -1;
    EXPECT_FALSE(appSpawnClient.VerifyMsg(startMsg));
}

// Scenario3: Test when startMsg.code is MSG_APP_SPAWN and gids size is more than APP_MAX_GIDS.
HWTEST_F(AppSpawnClientSecondTest, VerifyMsg_ShouldReturnFalse_WhenGidsSizeIsMoreThanMax, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.gids.push_back(1);
    startMsg.gids.push_back(2);
    startMsg.gids.push_back(3);
    startMsg.gids.push_back(4);
    startMsg.gids.push_back(5);
    startMsg.gids.push_back(6);
    EXPECT_FALSE(appSpawnClient.VerifyMsg(startMsg));
}

// Scenario4: Test when startMsg.code is MSG_APP_SPAWN and gids array contains negative value.
HWTEST_F(AppSpawnClientSecondTest, VerifyMsg_ShouldReturnFalse_WhenGidsArrayContainsNegative, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.gids.push_back(1);
    startMsg.gids.push_back(-2);
    EXPECT_FALSE(appSpawnClient.VerifyMsg(startMsg));
}

// Scenario5: Test when startMsg.code is MSG_APP_SPAWN and procName is empty.
HWTEST_F(AppSpawnClientSecondTest, VerifyMsg_ShouldReturnFalse_WhenProcNameIsEmpty, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "";
    EXPECT_FALSE(appSpawnClient.VerifyMsg(startMsg));
}

// Scenario6: Test when startMsg.code is MSG_APP_SPAWN and procName size is more than MAX_PROC_NAME_LEN.
HWTEST_F(AppSpawnClientSecondTest, VerifyMsg_ShouldReturnFalse_WhenProcNameSizeIsMoreThanMax, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "a";
    startMsg.procName.append(MAX_PROC_NAME_LEN, 'a');
    EXPECT_FALSE(appSpawnClient.VerifyMsg(startMsg));
}

// Scenario7: Test when startMsg.code is MSG_GET_RENDER_TERMINATION_STATUS and pid is negative.
HWTEST_F(AppSpawnClientSecondTest, VerifyMsg_ShouldReturnFalse_WhenPidIsNegative, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.code = MSG_GET_RENDER_TERMINATION_STATUS;
    startMsg.pid = -1;
    EXPECT_FALSE(appSpawnClient.VerifyMsg(startMsg));
}

// Scenario8: Test when startMsg.code is not MSG_APP_SPAWN and not MSG_GET_RENDER_TERMINATION_STATUS.
HWTEST_F(AppSpawnClientSecondTest, VerifyMsg_ShouldReturnFalse_WhenCodeIsInvalid, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.code = 9999;
    EXPECT_FALSE(appSpawnClient.VerifyMsg(startMsg));
}

// Scenario9: Test when startMsg.code is MSG_APP_SPAWN and all conditions are valid.
HWTEST_F(AppSpawnClientSecondTest, VerifyMsg_ShouldReturnTrue_WhenAllConditionsAreValid, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.uid = 1;
    startMsg.gid = 1;
    startMsg.procName = "test";
    EXPECT_TRUE(appSpawnClient.VerifyMsg(startMsg));
}

// Scenario10: Test when startMsg.code is MSG_GET_RENDER_TERMINATION_STATUS and pid is valid.
HWTEST_F(AppSpawnClientSecondTest, VerifyMsg_ShouldReturnTrue_WhenPidIsValid, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    startMsg.code = MSG_GET_RENDER_TERMINATION_STATUS;
    startMsg.pid = 1;
    EXPECT_TRUE(appSpawnClient.VerifyMsg(startMsg));
}


// Scenario1: Test when VerifyMsg returns false then StartProcess returns ERR_INVALID_VALUE.
HWTEST_F(AppSpawnClientSecondTest, StartProcess_001, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnStartMsg startMsg;
    pid_t pid;
    EXPECT_EQ(appSpawnClient.StartProcess(startMsg, pid), ERR_INVALID_VALUE);
}

// Scenario2: Test when startMsg.procName is null returns false.
HWTEST_F(AppSpawnClientSecondTest, StartProcess_002, TestSize.Level0)
{
    auto asc = std::make_shared<AppSpawnClient>(true);
    AppSpawnStartMsg startMsg;
    pid_t pid;
    startMsg.uid = 0;
    startMsg.gids.push_back(1);
    startMsg.procName = "";
    int ret = asc->StartProcess(startMsg, pid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    
    startMsg.uid = 0;
    startMsg.gids.push_back(1);
    startMsg.procName = "testProcName";
    ret = asc->StartProcess(startMsg, pid);
    EXPECT_NE(ret, ERR_OK);
}

// Scenario1: Test when reqHandle is nullptr returns ERR_OK
HWTEST_F(AppSpawnClientSecondTest, SetIsolationModeFlag_001, TestSize.Level0)
{
    auto asc = std::make_shared<AppSpawnClient>(true);
    AppSpawnReqMsgHandle reqHandle = nullptr;
    AppSpawnStartMsg startMsg;
    startMsg.isolationMode = false;
    int ret = asc->SetIsolationModeFlag(startMsg, reqHandle);
    EXPECT_EQ(ret, ERR_OK);
}

// Scenario2: Test when startMsg.isolationMode is true returns ERR_OK
HWTEST_F(AppSpawnClientSecondTest, SetIsolationModeFlag_002, TestSize.Level0)
{
    auto asc = std::make_shared<AppSpawnClient>(true);
    AppSpawnStartMsg startMsg;
    startMsg.isolationMode = true;
    startMsg.code = MSG_APP_SPAWN;
    startMsg.procName = "testProcName";
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(startMsg.code), startMsg.procName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = asc->SetIsolationModeFlag(startMsg, reqHandle);
    EXPECT_EQ(ret, ERR_OK);
}

// Scenario1: Test when AppSpawnReqMsgAddFd returns ERR_OK for all items in fds.
HWTEST_F(AppSpawnClientSecondTest, SetExtMsgFds_ShouldReturnErrOk_WhenAllItemsInFdsReturnOk, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(MSG_APP_SPAWN), "testProcName", &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    std::map<std::string, int32_t> fds = {{"fd1", 1}, {"fd2", 2}};
    ret = appSpawnClient.SetExtMsgFds(reqHandle, fds);
    ASSERT_EQ(ret, ERR_OK);
}

// Scenario2: Test when AppSpawnReqMsgAddFd returns ERR_NO_PERMISSION for some items in fds.
HWTEST_F(AppSpawnClientSecondTest,
    SetExtMsgFds_ShouldReturnErrNoPermission_WhenSomeItemsInFdsReturnNoPermission, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(MSG_APP_SPAWN), "testProcName", &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    std::map<std::string, int32_t> fds = {{"fd1", 1}, {"fd2", -1}};
    ret = appSpawnClient.SetExtMsgFds(reqHandle, fds);
    EXPECT_NE(ret, ERR_OK);
}

// Scenario3: Test when AppSpawnReqMsgAddFd returns ERR_INVALID_ARGS for some items in fds.
HWTEST_F(AppSpawnClientSecondTest,
    SetExtMsgFds_ShouldReturnErrInvalidArgs_WhenSomeItemsInFdsReturnInvalidArgs, TestSize.Level0)
{
    AppSpawnClient appSpawnClient;
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(MSG_APP_SPAWN), "testProcName", &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    std::map<std::string, int32_t> fds = {{"fd1", -1}, {"fd2", -1}};
    ret = appSpawnClient.SetExtMsgFds(reqHandle, fds);
    EXPECT_NE(ret, ERR_OK);
}

#ifdef SUPPORT_CHILD_PROCESS
// Scenario1: Test when childProcessType is CHILD_PROCESS_TYPE_NOT_CHILD then AppSpawnReqMsgSetAppFlag is called.
HWTEST_F(AppSpawnClientSecondTest, SetChildProcessTypeStartFlag_001, TestSize.Level0)
{
    auto asc = std::make_shared<AppSpawnClient>(true);
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(MSG_APP_SPAWN), "testProcName", &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    int32_t childProcessType = CHILD_PROCESS_TYPE_NOT_CHILD;
    ret = asc->SetChildProcessTypeStartFlag(reqHandle, childProcessType);
    EXPECT_EQ(ret, ERR_OK);
}

// Scenario2: Test when childProcessType is CHILD_PROCESS_TYPE_JS then AppSpawnReqMsgSetAppFlag is called.
HWTEST_F(AppSpawnClientSecondTest, SetChildProcessTypeStartFlag_002, TestSize.Level0)
{
    auto asc = std::make_shared<AppSpawnClient>(true);
    AppSpawnReqMsgHandle reqHandle = nullptr;
    int ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(MSG_APP_SPAWN), "testProcName", &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    int32_t childProcessType = CHILD_PROCESS_TYPE_JS;
    ret = asc->SetChildProcessTypeStartFlag(reqHandle, childProcessType);
    EXPECT_EQ(ret, ERR_OK);
}
#endif // SUPPORT_CHILD_PROCESS

// Scenario1: Test when startMsg.procName is null return ERR_INVALID_VALUE.
HWTEST_F(AppSpawnClientSecondTest, GetRenderProcessTerminationStatus_001, TestSize.Level0)
{
    auto asc = std::make_shared<AppSpawnClient>(true);
    AppSpawnStartMsg startMsg;
    int status;
    startMsg.uid = 0;
    startMsg.gids.push_back(1);
    startMsg.procName = "";
    int ret = asc->GetRenderProcessTerminationStatus(startMsg, status);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

// Scenario2:  Test when startMsg.procName is not null return ERR_OK.
HWTEST_F(AppSpawnClientSecondTest, GetRenderProcessTerminationStatus_002, TestSize.Level0)
{
    auto asc = std::make_shared<AppSpawnClient>(true);
    AppSpawnStartMsg startMsg;
    int status;
    startMsg.uid = 0;
    startMsg.gids.push_back(1);
    startMsg.procName = "testProcName";
    int ret = asc->GetRenderProcessTerminationStatus(startMsg, status);
    EXPECT_EQ(ret, ERR_OK);
}
} // namespace AppExecFwk
} // namespace OHOS
