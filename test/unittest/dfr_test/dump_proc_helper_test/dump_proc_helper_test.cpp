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

#include "dump_process_helper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
class DumpProcHelperTest : public testing::Test {
public:
    DumpProcHelperTest()
    {}
    ~DumpProcHelperTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DumpProcHelperTest::SetUpTestCase(void)
{}

void DumpProcHelperTest::TearDownTestCase(void)
{}

void DumpProcHelperTest::SetUp(void)
{}

void DumpProcHelperTest::TearDown(void)
{}

/**
 * @tc.number: DumpProcHelperTest001
 * @tc.name: DumpProcHelperTest001
 * @tc.desc: test GetProcRssMemInfo.
 */
HWTEST_F(DumpProcHelperTest, DumpProcHelperTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpProcHelperTest001 start";
    EXPECT_TRUE(DumpProcessHelper::GetProcRssMemInfo() != 0);
    GTEST_LOG_(INFO) << "DumpProcHelperTest001 end";
}
}  // namespace AppExecFwk
}  // namespace OHOS
