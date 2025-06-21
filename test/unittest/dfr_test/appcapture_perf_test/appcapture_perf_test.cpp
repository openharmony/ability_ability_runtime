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

#define private public
#include "appcapture_perf.h"
#undef private
#include "cpp/mutex.h"
 
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
 
namespace OHOS {
namespace AppExecFwk {
class AppCapturePerfTest : public testing::Test {
public:
    AppCapturePerfTest()
    {}
    ~AppCapturePerfTest()
    {}
    std::shared_ptr<AppCapturePerf> appCapturePerf = nullptr;
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
 
void AppCapturePerfTest::SetUpTestCase(void)
{}
 
void AppCapturePerfTest::TearDownTestCase(void)
{}
 
void AppCapturePerfTest::SetUp(void)
{
    appCapturePerf = AppCapturePerf::GetInstance();
}
 
void AppCapturePerfTest::TearDown(void)
{
    AppCapturePerf::DestroyInstance();
}
 
/**
 * @tc.number: AppCapturePerfTest001
 * @tc.desc: add testcase codecoverage
 * @tc.type: FUNC
 */
HWTEST_F(AppCapturePerfTest, AppCapturePerfTest001, TestSize.Level0)
{
    ASSERT_TRUE(appCapturePerf != nullptr);
    GTEST_LOG_(INFO) << "test AppCapturePerfTest001 Data.\n";
    FaultData faultData;
    faultData.errorObject.name = "testapp";
    faultData.errorObject.message = "test";
    faultData.errorObject.stack = "";
    int32_t ret = appCapturePerf->CapturePerf(faultData);
    EXPECT_EQ(ret, 0);
}
 
/**
 * @tc.number: AppCapturePerfTest002
 * @tc.desc: add testcase codecoverage
 * @tc.type: FUNC
 */
HWTEST_F(AppCapturePerfTest, AppCapturePerfTest002, TestSize.Level0)
{
    ASSERT_TRUE(appCapturePerf != nullptr);
    GTEST_LOG_(INFO) << "test AppCapturePerfTest002 Data.\n";
    FaultData faultData;
    faultData.errorObject.name = "testapp";
    faultData.errorObject.message = "test";
    faultData.errorObject.stack = "123,,1478";
    int32_t ret = appCapturePerf->CapturePerf(faultData);
    EXPECT_EQ(ret, 0);
}
}  // namespace AppExecFwk
}  // namespace OHOS