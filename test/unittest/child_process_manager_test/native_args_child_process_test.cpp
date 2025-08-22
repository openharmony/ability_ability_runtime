/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define protected public
#include "native_args_child_process.h"
#undef protected
#undef private

#include "hilog_tag_wrapper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
using namespace AAFwk;
using namespace AppExecFwk;
class NativeArgsChildProcessTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void NativeArgsChildProcessTest::SetUpTestCase()
{}

void NativeArgsChildProcessTest::TearDownTestCase()
{}

void NativeArgsChildProcessTest::SetUp()
{}

void NativeArgsChildProcessTest::TearDown()
{}

/**
 * @tc.number: NativeArgsChildProcess_0100
 * @tc.desc: Test NativeArgsChildProcess Create works
 * @tc.type: FUNC
 */
HWTEST_F(NativeArgsChildProcessTest, NativeArgsChildProcess_0100, TestSize.Level2)
{
    TAG_LOGD(AAFwkTag::TEST, "NativeArgsChildProcess_0100 called.");
    auto process = NativeArgsChildProcess::Create();
    EXPECT_TRUE(process != nullptr);
}

/**
 * @tc.number: NativeArgsChildProcess_0200
 * @tc.desc: Test NativeArgsChildProcess Init works
 * @tc.type: FUNC
 */
HWTEST_F(NativeArgsChildProcessTest, NativeArgsChildProcess_0200, TestSize.Level2)
{
    TAG_LOGD(AAFwkTag::TEST, "NativeArgsChildProcess_0200 called.");
    auto process = NativeArgsChildProcess::Create();
    EXPECT_TRUE(process != nullptr);

    std::shared_ptr<ChildProcessStartInfo> info = std::make_shared<ChildProcessStartInfo>();
    info->name = "AProcess";
    info->srcEntry = "libentry.so:Main";
    info->moduleName = "entry";

    process->Init(info);
    EXPECT_TRUE(process->processStartInfo_ != nullptr);
}

/**
 * @tc.number: NativeArgsChildProcess_0300
 * @tc.desc: Test NativeArgsChildProcess Init works
 * @tc.type: FUNC
 */
HWTEST_F(NativeArgsChildProcessTest, NativeArgsChildProcess_0300, TestSize.Level2)
{
    TAG_LOGD(AAFwkTag::TEST, "NativeArgsChildProcess_0300 called.");
    auto process = NativeArgsChildProcess::Create();
    EXPECT_TRUE(process != nullptr);

    auto ret = process->Init(nullptr);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: NativeArgsChildProcess_0400
 * @tc.desc: Test NativeArgsChildProcess OnStart works
 * @tc.type: FUNC
 */
HWTEST_F(NativeArgsChildProcessTest, NativeArgsChildProcess_0400, TestSize.Level2)
{
    TAG_LOGD(AAFwkTag::TEST, "NativeArgsChildProcess_0400 called.");
    auto process = NativeArgsChildProcess::Create();
    EXPECT_TRUE(process != nullptr);

    std::shared_ptr<ChildProcessStartInfo> info = std::make_shared<ChildProcessStartInfo>();
    info->name = "AProcess";
    info->srcEntry = "entry/./ets/process/AProcess.ts";
    info->moduleName = "entry";

    process->Init(info);
    process->OnStart();
    EXPECT_TRUE(process->processStartInfo_ != nullptr);
}

/**
 * @tc.number: NativeArgsChildProcess_0500
 * @tc.desc: Test NativeArgsChildProcess OnStart works
 * @tc.type: FUNC
 */
HWTEST_F(NativeArgsChildProcessTest, NativeArgsChildProcess_0500, TestSize.Level2)
{
    TAG_LOGD(AAFwkTag::TEST, "NativeArgsChildProcess_0500 called.");
    auto process = NativeArgsChildProcess::Create();
    EXPECT_TRUE(process != nullptr);

    std::shared_ptr<ChildProcessStartInfo> info = std::make_shared<ChildProcessStartInfo>();
    info->name = "AProcess";
    info->srcEntry = "entry/./ets/process/AProcess.ts";
    info->moduleName = "entry";
    std::shared_ptr<ChildProcessArgs> args = std::make_shared<ChildProcessArgs>();
    process->Init(info);
    process->OnStart(args);
    EXPECT_TRUE(process->processStartInfo_ != nullptr);
}

/**
 * @tc.number: NativeArgsChildProcess_0600
 * @tc.desc: Test NativeArgsChildProcess LoadNativeLib works
 * @tc.type: FUNC
 */
HWTEST_F(NativeArgsChildProcessTest, NativeArgsChildProcess_0600, TestSize.Level2)
{
    TAG_LOGD(AAFwkTag::TEST, "NativeArgsChildProcess_0600 called.");
    auto process = std::make_shared<NativeArgsChildProcess>();
    EXPECT_TRUE(process != nullptr);

    auto ret = process->LoadNativeLib(nullptr);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: NativeArgsChildProcess_0700
 * @tc.desc: Test NativeArgsChildProcess LoadNativeLib works
 * @tc.type: FUNC
 */
HWTEST_F(NativeArgsChildProcessTest, NativeArgsChildProcess_0700, TestSize.Level2)
{
    TAG_LOGD(AAFwkTag::TEST, "NativeArgsChildProcess_0700 called.");
    auto process = std::make_shared<NativeArgsChildProcess>();
    EXPECT_TRUE(process != nullptr);

    std::shared_ptr<ChildProcessStartInfo> info = std::make_shared<ChildProcessStartInfo>();
    info->name = "AProcess";
    info->srcEntry = "entry/./ets/process/AProcess.ts";
    info->moduleName = "entry";

    auto ret = process->LoadNativeLib(info);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: NativeArgsChildProcess_0800
 * @tc.desc: Test NativeArgsChildProcess LoadNativeLib works
 * @tc.type: FUNC
 */
HWTEST_F(NativeArgsChildProcessTest, NativeArgsChildProcess_0800, TestSize.Level2) {
    TAG_LOGD(AAFwkTag::TEST, "NativeArgsChildProcess_0800 called.");
    auto process = std::make_shared<NativeArgsChildProcess>();
    EXPECT_TRUE(process != nullptr);
    
    std::shared_ptr<ChildProcessStartInfo> info = std::make_shared<ChildProcessStartInfo>();
    info->name = "AProcess";
    info->srcEntry = "entry/./ets/process/AProcess.ts";
    info->moduleName = "";
    
    auto ret = process->LoadNativeLib(info);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: NativeArgsChildProcess_0900
 * @tc.desc: Test NativeArgsChildProcess LoadNativeLib works
 * @tc.type: FUNC
 */
HWTEST_F(NativeArgsChildProcessTest, NativeArgsChildProcess_0900, TestSize.Level2) {
    TAG_LOGD(AAFwkTag::TEST, "NativeArgsChildProcess_0900 called.");
    auto process = std::make_shared<NativeArgsChildProcess>();
    EXPECT_TRUE(process != nullptr);
    
    std::shared_ptr<ChildProcessStartInfo> info = std::make_shared<ChildProcessStartInfo>();
    info->moduleName = "";
    
    bool ret = process->LoadNativeLib(info);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: NativeArgsChildProcess_1000
 * @tc.desc: Test NativeArgsChildProcess LoadNativeLib works
 * @tc.type: FUNC
 */
HWTEST_F(NativeArgsChildProcessTest, NativeArgsChildProcess_1000, TestSize.Level2) {
    TAG_LOGD(AAFwkTag::TEST, "NativeArgsChildProcess_1000 called.");
    auto process = std::make_shared<NativeArgsChildProcess>();
    EXPECT_TRUE(process != nullptr);

    std::shared_ptr<ChildProcessStartInfo> info = std::make_shared<ChildProcessStartInfo>();
    info->srcEntry = "";
    
    bool ret = process->LoadNativeLib(info);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: NativeArgsChildProcess_1100
 * @tc.desc: Test NativeArgsChildProcess LoadNativeLib works
 * @tc.type: FUNC
 */
HWTEST_F(NativeArgsChildProcessTest, NativeArgsChildProcess_1100, TestSize.Level2) {
    TAG_LOGD(AAFwkTag::TEST, "NativeArgsChildProcess_1000 called.");
    auto process = std::make_shared<NativeArgsChildProcess>();
    auto info = std::make_shared<ChildProcessStartInfo>();
    info->moduleName = "entry";
    info->entryFunc = "";
    
    bool ret = process->LoadNativeLib(info);
    EXPECT_FALSE(ret);
}
}  // namespace AbilityRuntime
}  // namespace OHOS