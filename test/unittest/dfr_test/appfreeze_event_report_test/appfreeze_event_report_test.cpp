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

#include "appfreeze_event_report.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
class AppfreezeEventReportTest : public testing::Test {
public:
    AppfreezeEventReportTest()
    {}
    ~AppfreezeEventReportTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AppfreezeEventReportTest::SetUpTestCase(void)
{}

void AppfreezeEventReportTest::TearDownTestCase(void)
{}

void AppfreezeEventReportTest::SetUp(void)
{}

void AppfreezeEventReportTest::TearDown(void)
{}

/**
 * @tc.number: SendAppfreezeEvent_Test_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeEventReportTest, SendAppfreezeEvent_Test_001, TestSize.Level1)
{
    std::string eventName = "THREAD_BLOCK_3S";
    std::string testName = "SendAppfreezeEvent_Test_001";
    int tid = static_cast<int>(gettid());
    int pid = static_cast<int>(getpid());
    int uid = static_cast<int>(getuid());
    AppfreezeEventInfo eventInfo;
    eventInfo.tid = tid;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    eventInfo.eventId = -1; // test value
    eventInfo.bundleName = testName;
    eventInfo.processName = testName;
    eventInfo.binderInfo = "PeerBinder: test binder info \\n";
    eventInfo.freezeMemory = "memory info test";
    eventInfo.appRunningUniqueId = "id: 1234";
    eventInfo.errorStack = "SendAppfreezeEvent_Test_001: error stack";
    eventInfo.errorName = eventName;
    eventInfo.errorMessage = "SendAppfreezeEvent_Test_001: error message";
    eventInfo.freezeInfoFile = "SendAppfreezeEvent_Test_001: freezeInfoFile";
    eventInfo.hitraceInfo = "hitraceInfo: 1234";
    eventInfo.foregroundState = false;
    int ret = AppfreezeEventReport::SendAppfreezeEvent(eventName,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, eventInfo);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: SendAppfreezeEvent_Test_002
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeEventReportTest, SendAppfreezeEvent_Test_002, TestSize.Level1)
{
    std::string eventName = "THREAD_BLOCK_6S";
    std::string testName = "SendAppfreezeEvent_Test_002";
    int tid = static_cast<int>(gettid());
    int pid = static_cast<int>(getpid());
    int uid = static_cast<int>(getuid());
    AppfreezeEventInfo eventInfo;
    eventInfo.tid = tid;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    eventInfo.eventId = -1; // test value
    eventInfo.bundleName = testName;
    eventInfo.processName = testName;
    eventInfo.binderInfo = "PeerBinder: test binder info \\n";
    eventInfo.freezeMemory = "memory info test";
    eventInfo.appRunningUniqueId = "id: 1234";
    eventInfo.errorStack = "SendAppfreezeEvent_Test_002: error stack";
    eventInfo.errorName = eventName;
    eventInfo.errorMessage = "SendAppfreezeEvent_Test_002: error message";
    eventInfo.freezeInfoFile = "SendAppfreezeEvent_Test_002: freezeInfoFile";
    eventInfo.hitraceInfo = "hitraceInfo: 1234";
    eventInfo.foregroundState = false;
    int ret = AppfreezeEventReport::SendAppfreezeEvent(eventName,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, eventInfo);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: SendAppfreezeEvent_Test_003
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeEventReportTest, SendAppfreezeEvent_Test_003, TestSize.Level1)
{
    std::string eventName = "LIFECYCLE_HALF_TIMEOUT";
    std::string testName = "SendAppfreezeEvent_Test_003";
    int tid = static_cast<int>(gettid());
    int pid = static_cast<int>(getpid());
    int uid = static_cast<int>(getuid());
    AppfreezeEventInfo eventInfo;
    eventInfo.tid = tid;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    eventInfo.eventId = -1; // test value
    eventInfo.bundleName = testName;
    eventInfo.processName = testName;
    eventInfo.binderInfo = "PeerBinder: test binder info \\n";
    eventInfo.freezeMemory = "memory info test";
    eventInfo.appRunningUniqueId = "id: 1234";
    eventInfo.errorStack = "SendAppfreezeEvent_Test_003: error stack";
    eventInfo.errorName = eventName;
    eventInfo.errorMessage = "SendAppfreezeEvent_Test_003: error message";
    eventInfo.freezeInfoFile = "SendAppfreezeEvent_Test_003: freezeInfoFile";
    eventInfo.hitraceInfo = "hitraceInfo: 1234";
    eventInfo.foregroundState = false;
    int ret = AppfreezeEventReport::SendAppfreezeEvent(eventName,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, eventInfo);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: SendAppfreezeEvent_Test_004
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeEventReportTest, SendAppfreezeEvent_Test_004, TestSize.Level1)
{
    std::string eventName = "LIFECYCLE_HALF_TIMEOUT_WARNING";
    std::string testName = "SendAppfreezeEvent_Test_004";
    int tid = static_cast<int>(gettid());
    int pid = static_cast<int>(getpid());
    int uid = static_cast<int>(getuid());
    AppfreezeEventInfo eventInfo;
    eventInfo.tid = tid;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    eventInfo.eventId = -1; // test value
    eventInfo.bundleName = testName;
    eventInfo.processName = testName;
    eventInfo.binderInfo = "PeerBinder: test binder info \\n";
    eventInfo.freezeMemory = "memory info test";
    eventInfo.appRunningUniqueId = "id: 1234";
    eventInfo.errorStack = "SendAppfreezeEvent_Test_004: error stack";
    eventInfo.errorName = eventName;
    eventInfo.errorMessage = "SendAppfreezeEvent_Test_004: error message";
    eventInfo.freezeInfoFile = "SendAppfreezeEvent_Test_004: freezeInfoFile";
    eventInfo.hitraceInfo = "hitraceInfo: 1234";
    eventInfo.foregroundState = false;
    int ret = AppfreezeEventReport::SendAppfreezeEvent(eventName,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, eventInfo);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: SendAppfreezeEvent_Test_005
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeEventReportTest, SendAppfreezeEvent_Test_005, TestSize.Level1)
{
    std::string eventName = "LIFECYCLE_TIMEOUT";
    std::string testName = "SendAppfreezeEvent_Test_005";
    int tid = static_cast<int>(gettid());
    int pid = static_cast<int>(getpid());
    int uid = static_cast<int>(getuid());
    AppfreezeEventInfo eventInfo;
    eventInfo.tid = tid;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    eventInfo.eventId = -1; // test value
    eventInfo.bundleName = testName;
    eventInfo.processName = testName;
    eventInfo.binderInfo = "PeerBinder: test binder info \\n";
    eventInfo.freezeMemory = "memory info test";
    eventInfo.appRunningUniqueId = "id: 1234";
    eventInfo.errorStack = "SendAppfreezeEvent_Test_005: error stack";
    eventInfo.errorName = eventName;
    eventInfo.errorMessage = "SendAppfreezeEvent_Test_005: error message";
    eventInfo.freezeInfoFile = "SendAppfreezeEvent_Test_005: freezeInfoFile";
    eventInfo.hitraceInfo = "hitraceInfo: 1234";
    eventInfo.foregroundState = false;
    int ret = AppfreezeEventReport::SendAppfreezeEvent(eventName,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, eventInfo);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: SendAppfreezeEvent_Test_006
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeEventReportTest, SendAppfreezeEvent_Test_006, TestSize.Level1)
{
    std::string eventName = "LIFECYCLE_TIMEOUT_WARNING";
    std::string testName = "SendAppfreezeEvent_Test_006";
    int tid = static_cast<int>(gettid());
    int pid = static_cast<int>(getpid());
    int uid = static_cast<int>(getuid());
    AppfreezeEventInfo eventInfo;
    eventInfo.tid = tid;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    eventInfo.eventId = -1; // test value
    eventInfo.bundleName = testName;
    eventInfo.processName = testName;
    eventInfo.binderInfo = "PeerBinder: test binder info \\n";
    eventInfo.freezeMemory = "memory info test";
    eventInfo.appRunningUniqueId = "id: 1234";
    eventInfo.errorStack = "SendAppfreezeEvent_Test_006: error stack";
    eventInfo.errorName = eventName;
    eventInfo.errorMessage = "SendAppfreezeEvent_Test_006: error message";
    eventInfo.freezeInfoFile = "SendAppfreezeEvent_Test_006: freezeInfoFile";
    eventInfo.hitraceInfo = "hitraceInfo: 1234";
    eventInfo.foregroundState = true;
    int ret = AppfreezeEventReport::SendAppfreezeEvent(eventName,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, eventInfo);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: SendAppfreezeEvent_Test_007
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeEventReportTest, SendAppfreezeEvent_Test_007, TestSize.Level1)
{
    std::string eventName = "APP_LIFECYCLE_TIMEOUT";
    std::string testName = "SendAppfreezeEvent_Test_007";
    int tid = static_cast<int>(gettid());
    int pid = static_cast<int>(getpid());
    int uid = static_cast<int>(getuid());
    AppfreezeEventInfo eventInfo;
    eventInfo.tid = tid;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    eventInfo.eventId = -1; // test value
    eventInfo.bundleName = testName;
    eventInfo.processName = testName;
    eventInfo.binderInfo = "PeerBinder: test binder info \\n";
    eventInfo.freezeMemory = "memory info test";
    eventInfo.appRunningUniqueId = "id: 1234";
    eventInfo.errorStack = "SendAppfreezeEvent_Test_007: error stack";
    eventInfo.errorName = eventName;
    eventInfo.errorMessage = "SendAppfreezeEvent_Test_007: error message";
    eventInfo.freezeInfoFile = "SendAppfreezeEvent_Test_007: freezeInfoFile";
    eventInfo.hitraceInfo = "hitraceInfo: 1234";
    eventInfo.foregroundState = true;
    int ret = AppfreezeEventReport::SendAppfreezeEvent(eventName,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, eventInfo);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: SendAppfreezeEvent_Test_008
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeEventReportTest, SendAppfreezeEvent_Test_008, TestSize.Level1)
{
    std::string eventName = "APP_INPUT_BLOCK";
    std::string testName = "SendAppfreezeEvent_Test_008";
    int tid = static_cast<int>(gettid());
    int pid = static_cast<int>(getpid());
    int uid = static_cast<int>(getuid());
    AppfreezeEventInfo eventInfo;
    eventInfo.tid = tid;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    eventInfo.eventId = -1; // test value
    eventInfo.bundleName = testName;
    eventInfo.processName = testName;
    eventInfo.binderInfo = "PeerBinder: test binder info \\n";
    eventInfo.freezeMemory = "memory info test";
    eventInfo.appRunningUniqueId = "id: 1234";
    eventInfo.errorStack = "SendAppfreezeEvent_Test_008: error stack";
    eventInfo.errorName = eventName;
    eventInfo.errorMessage = "SendAppfreezeEvent_Test_008: error message";
    eventInfo.freezeInfoFile = "SendAppfreezeEvent_Test_008: freezeInfoFile";
    eventInfo.hitraceInfo = "hitraceInfo: 1234";
    eventInfo.foregroundState = true;
    int ret = AppfreezeEventReport::SendAppfreezeEvent(eventName,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, eventInfo);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: SendAppfreezeEvent_Test_009
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeEventReportTest, SendAppfreezeEvent_Test_009, TestSize.Level1)
{
    std::string eventName = "BUSSINESS_THREAD_BLOCK_3S";
    std::string testName = "SendAppfreezeEvent_Test_009";
    int tid = static_cast<int>(gettid());
    int pid = static_cast<int>(getpid());
    int uid = static_cast<int>(getuid());
    AppfreezeEventInfo eventInfo;
    eventInfo.tid = tid;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    eventInfo.eventId = -1; // test value
    eventInfo.bundleName = testName;
    eventInfo.processName = testName;
    eventInfo.binderInfo = "PeerBinder: test binder info \\n";
    eventInfo.freezeMemory = "memory info test";
    eventInfo.appRunningUniqueId = "id: 1234";
    eventInfo.errorStack = "SendAppfreezeEvent_Test_009: error stack";
    eventInfo.errorName = eventName;
    eventInfo.errorMessage = "SendAppfreezeEvent_Test_009: error message";
    eventInfo.freezeInfoFile = "SendAppfreezeEvent_Test_009: freezeInfoFile";
    eventInfo.hitraceInfo = "hitraceInfo: 1234";
    eventInfo.foregroundState = false;
    int ret = AppfreezeEventReport::SendAppfreezeEvent(eventName,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, eventInfo);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: SendAppfreezeEvent_Test_010
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeEventReportTest, SendAppfreezeEvent_Test_010, TestSize.Level1)
{
    std::string eventName = "BUSSINESS_THREAD_BLOCK_6S";
    std::string testName = "SendAppfreezeEvent_Test_010";
    int tid = static_cast<int>(gettid());
    int pid = static_cast<int>(getpid());
    int uid = static_cast<int>(getuid());
    AppfreezeEventInfo eventInfo;
    eventInfo.tid = tid;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    eventInfo.eventId = -1; // test value
    eventInfo.bundleName = testName;
    eventInfo.processName = testName;
    eventInfo.binderInfo = "PeerBinder: test binder info \\n";
    eventInfo.freezeMemory = "memory info test";
    eventInfo.appRunningUniqueId = "id: 1234";
    eventInfo.errorStack = "SendAppfreezeEvent_Test_010: error stack";
    eventInfo.errorName = eventName;
    eventInfo.errorMessage = "SendAppfreezeEvent_Test_010: error message";
    eventInfo.freezeInfoFile = "SendAppfreezeEvent_Test_010: freezeInfoFile";
    eventInfo.hitraceInfo = "hitraceInfo: 1234";
    eventInfo.foregroundState = false;
    int ret = AppfreezeEventReport::SendAppfreezeEvent(eventName,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, eventInfo);
    EXPECT_EQ(ret, 0);
}
}  // namespace AppExecFwk
}  // namespace OHOS
