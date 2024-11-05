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
#include "dump_runtime_helper.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class DumpRuntimeHelperTest : public testing::Test {
public:
    DumpRuntimeHelperTest()
    {}
    ~DumpRuntimeHelperTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DumpRuntimeHelperTest::SetUpTestCase(void)
{}

void DumpRuntimeHelperTest::TearDownTestCase(void)
{}

void DumpRuntimeHelperTest::SetUp(void)
{}

void DumpRuntimeHelperTest::TearDown(void)
{}

/**
 * @tc.number: DumpJsHeap_0100
 * @tc.name: DumpJsHeap
 * @tc.desc: Test whether DumpJsHeap and are called normally.
 */
HWTEST_F(DumpRuntimeHelperTest, DumpJsHeap_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "DumpRuntimeHelperTest DumpJsHeap_0100 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    OHOS::AppExecFwk::JsHeapDumpInfo info;
    info.pid = 1;
    info.tid = 1;
    info.needGc = false;
    info.needSnapshot = true;
    info.needLeakobj = false;
    auto helper = std::make_shared<DumpRuntimeHelper>(application);
    helper->DumpJsHeap(info);
    EXPECT_NE(application, nullptr);
    GTEST_LOG_(INFO) << "DumpRuntimeHelperTest DumpJsHeap_0100 end";
}
} // namespace AppExecFwk
} // namespace OHOS