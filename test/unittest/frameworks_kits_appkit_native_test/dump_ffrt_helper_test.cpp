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
#include <singleton.h>
#include <cstdint>
#include <cstring>

#define private public
#define protected public
#include "dump_ffrt_helper.h"
#include "ffrt_inner.h"
#undef private
#undef protected

namespace OHOS {
namespace AppExecFwk {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

class DumpFfrtHelperTest : public testing::Test {
public:
    DumpFfrtHelperTest()
    {}
    ~DumpFfrtHelperTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DumpFfrtHelperTest::SetUpTestCase(void)
{}

void DumpFfrtHelperTest::TearDownTestCase(void)
{}

void DumpFfrtHelperTest::SetUp(void)
{}

void DumpFfrtHelperTest::TearDown(void)
{}

/**
 * @tc.number: DumpFfrtHelperTest_001
 * @tc.name: DumpFfrt
 * @tc.desc: Test whether GetBundleName is called normally.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(DumpFfrtHelperTest, DumpFfrtHelperTest_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "DumpFfrtHelperTest_001 start";
    std::string result = "DumpFfrtHelperTest";
    int temp = OHOS::AppExecFwk::DumpFfrtHelper::DumpFfrt(result);
    EXPECT_EQ(temp, 0);
    GTEST_LOG_(INFO) << "DumpFfrtHelperTest_001 end";
}
}
}