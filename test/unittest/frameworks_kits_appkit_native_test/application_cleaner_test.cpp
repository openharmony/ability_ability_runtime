/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

#define private public
#define protected public
#include "application_cleaner.h"
#undef private
#undef protected
#include "hilog_tag_wrapper.h"
#include "mock_my_status.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t RESULT_ERR = -1;
}
class ApplicationCleanerTest : public testing::Test {
public:
    ApplicationCleanerTest()
    {}
    ~ApplicationCleanerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ApplicationCleanerTest::SetUpTestCase(void)
{}

void ApplicationCleanerTest::TearDownTestCase(void)
{}

void ApplicationCleanerTest::SetUp(void)
{}

void ApplicationCleanerTest::TearDown(void)
{}

/**
 * @tc.number: ClearTempData_0100
 * @tc.name: ClearTempData
 * @tc.desc: Test whether ClearTempData and are called normally.
 */
HWTEST_F(ApplicationCleanerTest, ClearTempData_0100, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::APPKIT, "ClearTempData_0100 start");
    ApplicationCleaner cleaner;
    cleaner.hasCleaned_ = false;
    cleaner.ClearTempData();
    EXPECT_TRUE(cleaner.hasCleaned_);

    TAG_LOGI(AAFwkTag::APPKIT, "ClearTempData_0100 end");
}

/**
 * @tc.number: ClearTempData_0200
 * @tc.name: ClearTempData
 * @tc.desc: Test repeat call fail.
 */
HWTEST_F(ApplicationCleanerTest, ClearTempData_0200, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::APPKIT, "ClearTempData_0200 start");
    ApplicationCleaner cleaner;
    cleaner.hasCleaned_ = true;
    cleaner.ClearTempData();
    EXPECT_TRUE(cleaner.hasCleaned_);

    TAG_LOGI(AAFwkTag::APPKIT, "ClearTempData_0200 end");
}

/**
 * @tc.number: ClearTempData_0300
 * @tc.name: ClearTempData
 * @tc.desc: Test ClearTempData empty dir.
 */
HWTEST_F(ApplicationCleanerTest, ClearTempData_0300, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::APPKIT, "ClearTempData_0300 start");
    auto cleaner = std::make_shared<ApplicationCleaner>();
    cleaner->context_ = AbilityRuntime::ApplicationContext::GetInstance();
    cleaner->ClearTempData();
    EXPECT_TRUE(cleaner->hasCleaned_);

    TAG_LOGI(AAFwkTag::APPKIT, "ClearTempData_0300 end");
}

/**
 * @tc.number: ClearTempData_0400
 * @tc.name: ClearTempData
 * @tc.desc: Test ClearTempData success.
 */
HWTEST_F(ApplicationCleanerTest, ClearTempData_0400, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::APPKIT, "ClearTempData_0400 start");
    auto cleaner = std::make_shared<ApplicationCleaner>();
    cleaner->context_ = AbilityRuntime::ApplicationContext::GetInstance();
    std::string fileName("testdir");
    MyStatus::GetInstance().tmpDir_ = fileName;
    std::filesystem::create_directory(fileName);
    auto uselessDir = fileName + "/temp_useless_1";
    std::filesystem::create_directory(uselessDir);
    EXPECT_TRUE(std::filesystem::exists(uselessDir));
    cleaner->ClearTempData();
    EXPECT_TRUE(cleaner->hasCleaned_);
    EXPECT_FALSE(std::filesystem::exists(uselessDir));
    std::filesystem::remove(fileName);
    MyStatus::GetInstance().tmpDir_.clear();

    TAG_LOGI(AAFwkTag::APPKIT, "ClearTempData_0400 end");
}

/**
 * @tc.number: RenameTempData_0100
 * @tc.name: RenameTempData
 * @tc.desc: Test whether RenameTempData and are called normally.
 */
HWTEST_F(ApplicationCleanerTest, RenameTempData_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "RenameTempData_0100 start";
    auto cleaner = ApplicationCleaner::GetInstance();

    std::vector<std::string> tempDir1{};
    cleaner->context_ = AbilityRuntime::ApplicationContext::GetInstance();
    cleaner->context_->GetAllTempDir(tempDir1);
    cleaner->RenameTempData();

    std::vector<std::string> tempDir2{};
    cleaner->context_->GetAllTempDir(tempDir2);
    bool res = std::equal(tempDir1.begin(), tempDir1.end(), tempDir2.begin());
    EXPECT_EQ(res, true);
    GTEST_LOG_(INFO) << "RenameTempData_0100 end";
}

/**
 * @tc.number: GetObsoleteBundleTempPath_0100
 * @tc.name: GetObsoleteBundleTempPath
 * @tc.desc: Test whether GetObsoleteBundleTempPath and are called normally.
 */
HWTEST_F(ApplicationCleanerTest, GetObsoleteBundleTempPath_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "GetObsoleteBundleTempPath_0100 start";
    auto cleaner = ApplicationCleaner::GetInstance();
    std::string path = "/data/app/base";
    std::vector<std::string> rootPath {path};
    std::vector<std::string> tempPath;
    int res = cleaner->GetObsoleteBundleTempPath(rootPath, tempPath);
    EXPECT_EQ(res, 0);
    GTEST_LOG_(INFO) << "GetObsoleteBundleTempPath_0100 end";
}

/**
 * @tc.number: RemoveDir_0100
 * @tc.name: RemoveDir
 * @tc.desc: Test whether RemoveDir and are called normally.
 */
HWTEST_F(ApplicationCleanerTest, RemoveDir_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "RemoveDir_0100 start";
    auto cleaner = ApplicationCleaner::GetInstance();
    std::string currentPath = "/data/app/base";
    bool res = cleaner->RemoveDir(currentPath);
    EXPECT_EQ(res, false);
    GTEST_LOG_(INFO) << "RemoveDir_0100 end";
}

/**
 * @tc.number: RemoveDir_0200
 * @tc.name: RemoveDir
 * @tc.desc: Test RemoveDir with empty fileName.
 */
HWTEST_F(ApplicationCleanerTest, RemoveDir_0200, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::APPKIT, "RemoveDir_0200 start");

    std::string emptyPath;
    ApplicationCleaner cleaner;
    EXPECT_FALSE(cleaner.RemoveDir(emptyPath));

    TAG_LOGI(AAFwkTag::APPKIT, "RemoveDir_0200 end");
}

/**
 * @tc.number: RemoveDir_0300
 * @tc.name: RemoveDir
 * @tc.desc: Test RemoveDir with device fileName.
 */
HWTEST_F(ApplicationCleanerTest, RemoveDir_0300, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::APPKIT, "RemoveDir_0300 start");

    std::string deviceFile("/dev/null");
    ApplicationCleaner cleaner;
    EXPECT_FALSE(cleaner.RemoveDir(deviceFile));

    TAG_LOGI(AAFwkTag::APPKIT, "RemoveDir_0300 end");
}

/**
 * @tc.number: RemoveDir_0400
 * @tc.name: RemoveDir
 * @tc.desc: Test RemoveDir with regular file.
 */
HWTEST_F(ApplicationCleanerTest, RemoveDir_0400, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::APPKIT, "RemoveDir_0400 start");

    std::string fileName("testfile.txt");
    std::ofstream testFile(fileName);
    ApplicationCleaner cleaner;
    EXPECT_TRUE(cleaner.RemoveDir(fileName));

    TAG_LOGI(AAFwkTag::APPKIT, "RemoveDir_0400 end");
}

/**
 * @tc.number: RemoveDir_0500
 * @tc.name: RemoveDir
 * @tc.desc: Test RemoveDir with dir.
 */
HWTEST_F(ApplicationCleanerTest, RemoveDir_0500, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::APPKIT, "RemoveDir_0500 start");

    std::string fileName("testdir");
    std::filesystem::create_directory(fileName);
    ApplicationCleaner cleaner;
    EXPECT_TRUE(cleaner.RemoveDir(fileName));

    TAG_LOGI(AAFwkTag::APPKIT, "RemoveDir_0500 end");
}

/**
 * @tc.number: GetRootPath_0100
 * @tc.name: GetRootPath
 * @tc.desc: Test GetRootPath with null context_.
 */
HWTEST_F(ApplicationCleanerTest, GetRootPath_0100, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::APPKIT, "GetRootPath_0100 start");

    ApplicationCleaner cleaner;
    cleaner.context_ = nullptr;
    std::vector<std::string> rootPath;
    EXPECT_EQ(cleaner.GetRootPath(rootPath), RESULT_ERR);

    TAG_LOGI(AAFwkTag::APPKIT, "GetRootPath_0100 end");
}

/**
 * @tc.number: GetRootPath_0200
 * @tc.name: GetRootPath
 * @tc.desc: Test GetRootPath with null OsAccountManagerWrapper.
 */
HWTEST_F(ApplicationCleanerTest, GetRootPath_0200, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::APPKIT, "GetRootPath_0200 start");

    ApplicationCleaner cleaner;
    cleaner.context_ = AbilityRuntime::ApplicationContext::GetInstance();
    std::vector<std::string> rootPath;
    MyStatus::GetInstance().instanceStatus_ = false;
    EXPECT_EQ(cleaner.GetRootPath(rootPath), RESULT_ERR);
    MyStatus::GetInstance().instanceStatus_ = true;

    TAG_LOGI(AAFwkTag::APPKIT, "GetRootPath_0200 end");
}

/**
 * @tc.number: GetRootPath_0300
 * @tc.name: GetRootPath
 * @tc.desc: Test GetRootPath with GetOsAccountLocalIdFromProcess failing.
 */
HWTEST_F(ApplicationCleanerTest, GetRootPath_0300, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::APPKIT, "GetRootPath_0300 start");

    ApplicationCleaner cleaner;
    cleaner.context_ = AbilityRuntime::ApplicationContext::GetInstance();
    std::vector<std::string> rootPath;
    MyStatus::GetInstance().statusValue_ = RESULT_ERR;
    EXPECT_EQ(cleaner.GetRootPath(rootPath), RESULT_ERR);
    MyStatus::GetInstance().statusValue_ = 0;

    TAG_LOGI(AAFwkTag::APPKIT, "GetRootPath_0300 end");
}

/**
 * @tc.number: GetRootPath_0400
 * @tc.name: GetRootPath
 * @tc.desc: Test GetRootPath ok.
 */
HWTEST_F(ApplicationCleanerTest, GetRootPath_0400, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::APPKIT, "GetRootPath_0400 start");

    ApplicationCleaner cleaner;
    cleaner.context_ = AbilityRuntime::ApplicationContext::GetInstance();
    std::vector<std::string> rootPath;
    EXPECT_EQ(cleaner.GetRootPath(rootPath), 0);

    TAG_LOGI(AAFwkTag::APPKIT, "GetRootPath_0400 end");
}
}
}