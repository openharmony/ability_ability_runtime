/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "mock_ipc_skeleton.h"

#define private public
#include "app_mgr_service.h"
#undef private
#include "hilog_tag_wrapper.h"
#include "mock_app_mgr_service_inner.h"
#include "app_mgr_service_dump_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t HIDUMPER_SERVICE_UID = 1212;
const int32_t RANDOM_SERVICE_UID = 1500;
const int32_t NUMBER_VALID_PID_1 = 2000;
const int32_t NUMBER_VALID_PID_2 = 2001;
const int32_t NUMBER_VALID_PID_3 = 2002;
const std::string STRING_OPTION_WEB = "--web";
} // namespace

class AppMgrServiceDumpArkWebTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AppMgrServiceDumpArkWebTest::SetUpTestCase(void)
{}

void AppMgrServiceDumpArkWebTest::TearDownTestCase(void)
{}

void AppMgrServiceDumpArkWebTest::SetUp()
{}

void AppMgrServiceDumpArkWebTest::TearDown()
{}

/*
 * @tc.number    : AppMgrServiceDumpArkWeb_0100
 * @tc.name      : AppMgrService dump
 * @tc.desc      : 1.Test with args --web
 */
HWTEST_F(AppMgrServiceDumpArkWebTest, AppMgrServiceDumpArkWeb_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceDumpArkWeb_0100 start");

    auto appMgrService = std::make_shared<AppMgrService>();
    EXPECT_NE(appMgrService, nullptr);
    appMgrService->taskHandler_ = AAFwk::TaskHandlerWrap::CreateQueueHandler(Constants::APP_MGR_SERVICE_NAME);
    EXPECT_NE(appMgrService->taskHandler_, nullptr);
    auto mockAppMgrServiceInner = std::make_shared<MockAppMgrServiceInner>();
    EXPECT_NE(mockAppMgrServiceInner, nullptr);
    appMgrService->SetInnerService(mockAppMgrServiceInner);
    EXPECT_NE(appMgrService->appMgrServiceInner_, nullptr);
    appMgrService->eventHandler_ = std::make_shared<AMSEventHandler>(
        appMgrService->taskHandler_, appMgrService->appMgrServiceInner_);
    EXPECT_NE(appMgrService->eventHandler_, nullptr);

    IPCSkeleton::SetCallingUid(HIDUMPER_SERVICE_UID);
    EXPECT_TRUE((IPCSkeleton::GetCallingUid() == HIDUMPER_SERVICE_UID));

    constexpr int fd(1);
    std::vector<std::u16string> args;
    auto arg0 = Str8ToStr16(STRING_OPTION_WEB);
    args.emplace_back(arg0);
    auto result = appMgrService->Dump(fd, args);
    EXPECT_EQ(result, DumpErrorCode::ERR_INVALID_NUM_ARGS_ERROR);

    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceDumpArkWeb_0100 end");
}

/*
 * @tc.number    : AppMgrServiceDumpArkWeb_0200
 * @tc.name      : AppMgrService dump
 * @tc.desc      : 1.Test with args --web <valid pid> without correct permission
 */
HWTEST_F(AppMgrServiceDumpArkWebTest, AppMgrServiceDumpArkWeb_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceDumpArkWeb_0200 start");

    auto appMgrService = std::make_shared<AppMgrService>();
    EXPECT_NE(appMgrService, nullptr);
    appMgrService->taskHandler_ = AAFwk::TaskHandlerWrap::CreateQueueHandler(Constants::APP_MGR_SERVICE_NAME);
    EXPECT_NE(appMgrService->taskHandler_, nullptr);
    auto mockAppMgrServiceInner = std::make_shared<MockAppMgrServiceInner>();
    EXPECT_NE(mockAppMgrServiceInner, nullptr);
    appMgrService->SetInnerService(mockAppMgrServiceInner);
    EXPECT_NE(appMgrService->appMgrServiceInner_, nullptr);
    appMgrService->eventHandler_ = std::make_shared<AMSEventHandler>(
        appMgrService->taskHandler_, appMgrService->appMgrServiceInner_);
    EXPECT_NE(appMgrService->eventHandler_, nullptr);

    IPCSkeleton::SetCallingUid(RANDOM_SERVICE_UID);
    EXPECT_FALSE((IPCSkeleton::GetCallingUid() == HIDUMPER_SERVICE_UID));

    constexpr int fd(1);
    std::vector<std::u16string> args;
    auto arg0 = Str8ToStr16(STRING_OPTION_WEB);
    args.emplace_back(arg0);
    auto arg1 = Str8ToStr16(std::to_string(NUMBER_VALID_PID_1));
    args.emplace_back(arg1);
    auto arg2 = Str8ToStr16(std::string("customArgs"));
    args.emplace_back(arg2);
    auto result = appMgrService->Dump(fd, args);
    EXPECT_EQ(result, DumpErrorCode::ERR_PERMISSION_DENY_ERROR);

    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceDumpArkWeb_0200 end");
}

/*
 * @tc.number    : AppMgrServiceDumpArkWeb_0300
 * @tc.name      : AppMgrService dump
 * @tc.desc      : 1.Test with args --web pid1|pid2|pid3
 */
HWTEST_F(AppMgrServiceDumpArkWebTest, AppMgrServiceDumpArkWeb_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceDumpArkWeb_0300 start");

    auto appMgrService = std::make_shared<AppMgrService>();
    EXPECT_NE(appMgrService, nullptr);
    appMgrService->taskHandler_ = AAFwk::TaskHandlerWrap::CreateQueueHandler(Constants::APP_MGR_SERVICE_NAME);
    EXPECT_NE(appMgrService->taskHandler_, nullptr);
    auto mockAppMgrServiceInner = std::make_shared<MockAppMgrServiceInner>();
    EXPECT_NE(mockAppMgrServiceInner, nullptr);
    appMgrService->SetInnerService(mockAppMgrServiceInner);
    EXPECT_NE(appMgrService->appMgrServiceInner_, nullptr);
    appMgrService->eventHandler_ = std::make_shared<AMSEventHandler>(
        appMgrService->taskHandler_, appMgrService->appMgrServiceInner_);
    EXPECT_NE(appMgrService->eventHandler_, nullptr);

    // IsHidumperServiceCall
    IPCSkeleton::SetCallingUid(HIDUMPER_SERVICE_UID);
    EXPECT_TRUE((IPCSkeleton::GetCallingUid() == HIDUMPER_SERVICE_UID));

    constexpr int fd(1);
    std::vector<std::u16string> args;
    auto arg0 = Str8ToStr16(STRING_OPTION_WEB);
    args.emplace_back(arg0);
    std::string pids;
    pids.append(std::to_string(NUMBER_VALID_PID_1))
        .append("|")
        .append(std::to_string(NUMBER_VALID_PID_2))
        .append("|")
        .append(std::to_string(NUMBER_VALID_PID_3));
    auto arg1 = Str8ToStr16(pids);
    args.emplace_back(arg1);
    auto result = appMgrService->Dump(fd, args);
    EXPECT_EQ(result, DumpErrorCode::ERR_INVALID_PID_ERROR);

    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceDumpArkWeb_0300 end");
}

/*
 * @tc.number    : AppMgrServiceDumpArkWeb_0400
 * @tc.name      : AppMgrService dump
 * @tc.desc      : 1.Test with args --web pid1,pid2,pid3
 */
HWTEST_F(AppMgrServiceDumpArkWebTest, AppMgrServiceDumpArkWeb_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceDumpArkWeb_0400 start");

    auto appMgrService = std::make_shared<AppMgrService>();
    EXPECT_NE(appMgrService, nullptr);
    appMgrService->taskHandler_ = AAFwk::TaskHandlerWrap::CreateQueueHandler(Constants::APP_MGR_SERVICE_NAME);
    EXPECT_NE(appMgrService->taskHandler_, nullptr);
    auto mockAppMgrServiceInner = std::make_shared<MockAppMgrServiceInner>();
    EXPECT_NE(mockAppMgrServiceInner, nullptr);
    appMgrService->SetInnerService(mockAppMgrServiceInner);
    EXPECT_NE(appMgrService->appMgrServiceInner_, nullptr);
    appMgrService->eventHandler_ = std::make_shared<AMSEventHandler>(
        appMgrService->taskHandler_, appMgrService->appMgrServiceInner_);
    EXPECT_NE(appMgrService->eventHandler_, nullptr);

    // IsHidumperServiceCall
    IPCSkeleton::SetCallingUid(HIDUMPER_SERVICE_UID);
    EXPECT_TRUE((IPCSkeleton::GetCallingUid() == HIDUMPER_SERVICE_UID));

    constexpr int fd(1);
    std::vector<std::u16string> args;
    auto arg0 = Str8ToStr16(STRING_OPTION_WEB);
    args.emplace_back(arg0);
    std::string pids;
    pids.append(std::to_string(NUMBER_VALID_PID_1))
        .append(",")
        .append(std::to_string(NUMBER_VALID_PID_2))
        .append(",")
        .append(std::to_string(NUMBER_VALID_PID_3));
    auto arg1 = Str8ToStr16(pids);
    args.emplace_back(arg1);
    auto arg2 = Str8ToStr16(std::string("customArgs"));
    args.emplace_back(arg2);
    EXPECT_CALL(*mockAppMgrServiceInner, DumpArkWeb(_, _, _))
        .Times(1)
        .WillOnce(Return(DumpErrorCode::ERR_OK));
    auto result = appMgrService->Dump(fd, args);
    EXPECT_EQ(result, DumpErrorCode::ERR_OK);

    TAG_LOGI(AAFwkTag::TEST, "AppMgrServiceDumpArkWeb_0400 end");
}
}  // namespace AppExecFwk
}  // namespace OHOS
