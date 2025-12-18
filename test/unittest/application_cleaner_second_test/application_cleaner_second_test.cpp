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

#include <algorithm>
#include <gtest/gtest.h>

#define private public
#define protected public
#include "application_cleaner.h"
#include "context_impl.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AppExecFwk {
class ApplicationCleanerSecondTest : public testing::Test {
public:
    ApplicationCleanerSecondTest()
    {}
    ~ApplicationCleanerSecondTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ApplicationCleanerSecondTest::SetUpTestCase(void)
{}

void ApplicationCleanerSecondTest::TearDownTestCase(void)
{}

void ApplicationCleanerSecondTest::SetUp(void)
{}

void ApplicationCleanerSecondTest::TearDown(void)
{}

/**
 * @tc.number: CheckFileSize_0100
 * @tc.name: CheckFileSize
 * @tc.desc: Test whether CheckFileSize and are called normally.
 */
HWTEST_F(ApplicationCleanerSecondTest, CheckFileSize_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "CheckFileSize_0100 start";
    auto cleaner = ApplicationCleaner::GetInstance();
    std::vector<std::string> bundlePath{};
    std::string pathStr = "https://cn.bing.com/searchsearchsearchsearchsearch";
    bundlePath.clear();
    bundlePath.push_back(pathStr);
    bool ret = cleaner->CheckFileSize(bundlePath);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "CheckFileSize_0100 end";
}

/**
 * @tc.number: CheckFileSize_0200
 * @tc.name: CheckFileSize
 * @tc.desc: Test whether CheckFileSize and are called normally.
 */
HWTEST_F(ApplicationCleanerSecondTest, CheckFileSize_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "CheckFileSize_0200 start";
    auto cleaner = ApplicationCleaner::GetInstance();
    std::vector<std::string> bundlePath{};
    std::string pathStr = "https://cn.bing.com/searchsearchsearchsearchsearch";
    bundlePath.clear();
    for (int i = 0; i < 20000; i++) {
        bundlePath.push_back(pathStr);
    }
    bool ret = cleaner->CheckFileSize(bundlePath);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "CheckFileSize_0200 end";
}

/**
 * @tc.number: ClearTempData_0100
 * @tc.name: ClearTempData
 * @tc.desc: Test whether ClearTempData and are called normally.
 */
HWTEST_F(ApplicationCleanerSecondTest, ClearTempData_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "ClearTempData_0100 start";
    auto cleaner = ApplicationCleaner::GetInstance();
    EXPECT_NE(cleaner, nullptr);
    cleaner->ClearTempData();
    GTEST_LOG_(INFO) << "ClearTempData_0100 end";
}

/**
 * @tc.number: GetObsoleteBundleTempPath_0100
 * @tc.name: GetObsoleteBundleTempPath
 * @tc.desc: Test whether GetObsoleteBundleTempPath and are called normally.
 */
HWTEST_F(ApplicationCleanerSecondTest, GetObsoleteBundleTempPath_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "GetObsoleteBundleTempPath_0100 start";
    auto cleaner = ApplicationCleaner::GetInstance();
    std::string path = "https://cn.bing.com/searchsearchsearchsearchsearch";
    std::vector<std::string> rootPath{};
    rootPath.push_back(path);
    std::vector<std::string> tempPath{};
    int res = cleaner->GetObsoleteBundleTempPath(rootPath, tempPath);
    EXPECT_EQ(res, 0);
    GTEST_LOG_(INFO) << "GetObsoleteBundleTempPath_0100 end";
}

/**
 * @tc.number: GetObsoleteBundleTempPath_0200
 * @tc.name: GetObsoleteBundleTempPath
 * @tc.desc: Test whether GetObsoleteBundleTempPath and are called normally.
 */
HWTEST_F(ApplicationCleanerSecondTest, GetObsoleteBundleTempPath_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "GetObsoleteBundleTempPath_0200 start";
    auto cleaner = ApplicationCleaner::GetInstance();
    std::vector<std::string> tempPath{};
    std::vector<std::string> rootPath{};
    int res = cleaner->GetObsoleteBundleTempPath(rootPath, tempPath);
    EXPECT_EQ(res, -1);
    GTEST_LOG_(INFO) << "GetObsoleteBundleTempPath_0200 end";
}

/**
 * @tc.number: RemoveDir_0100
 * @tc.name: RemoveDir
 * @tc.desc: Test whether RemoveDir and are called normally.
 */
HWTEST_F(ApplicationCleanerSecondTest, RemoveDir_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "RemoveDir_0100 start";
    auto cleaner = ApplicationCleaner::GetInstance();
    std::string currentPath = "https://cn.bing.com/searchsearchsearchsearchsearch";
    bool res = cleaner->RemoveDir(currentPath);
    EXPECT_EQ(res, false);
    GTEST_LOG_(INFO) << "RemoveDir_0100 end";
}

/**
 * @tc.number: RemoveDir_0200
 * @tc.name: RemoveDir
 * @tc.desc: Test whether RemoveDir and are called normally.
 */
HWTEST_F(ApplicationCleanerSecondTest, RemoveDir_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "RemoveDir_0200 start";
    auto cleaner = ApplicationCleaner::GetInstance();
    std::string currentPath = "";
    bool res = cleaner->RemoveDir(currentPath);
    EXPECT_FALSE(res);
    GTEST_LOG_(INFO) << "RemoveDir_0200 end";
}

/**
 * @tc.number: GetRootPath_0100
 * @tc.name: GetRootPath
 * @tc.desc: Test whether GetRootPath and are called normally.
 */
HWTEST_F(ApplicationCleanerSecondTest, GetRootPath_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "GetRootPath_0100 start";
    auto cleaner = ApplicationCleaner::GetInstance();
    std::shared_ptr<AbilityRuntime::ApplicationContext> abilityRuntimeContext = nullptr;
    std::vector<std::string> bundlePath{};
    std::string pathStr = "https://cn.bing.com/searchsearchsearchsearchsearch";
    bundlePath.clear();
    bundlePath.push_back(pathStr);
    cleaner->SetRuntimeContext(abilityRuntimeContext);
    int ret = cleaner->GetRootPath(bundlePath);
    EXPECT_EQ(ret, -1);
    GTEST_LOG_(INFO) << "GetRootPath_0100 end";
}
}
}