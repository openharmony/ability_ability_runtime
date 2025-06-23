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

#include "native_lib_util.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class NativeLibUtilTest : public testing::Test {
public:
    NativeLibUtilTest()
    {}
    ~NativeLibUtilTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NativeLibUtilTest::SetUpTestCase(void)
{}

void NativeLibUtilTest::TearDownTestCase(void)
{}

void NativeLibUtilTest::SetUp(void)
{}

void NativeLibUtilTest::TearDown(void)
{}

/**
 * @tc.number: GetLibPath_0100
 * @tc.name: GetLibPath
 * @tc.desc: Test whether GetLibPath and are called normally.
 */
HWTEST_F(NativeLibUtilTest, GetLibPath_0100, TestSize.Level1)
{
    std::string hapPath = "/data/test/NativeLibUtilTest.hap";
    bool isPreInstallApp = true;
    std::string libpath = AppExecFwk::GetLibPath(hapPath, isPreInstallApp);
    EXPECT_NE(libpath, "");
}

/**
 * @tc.number: GetHapSoPath_0200
 * @tc.name: GetHapSoPath
 * @tc.desc: Test whether GetHapSoPath and are called normally.
 */
HWTEST_F(NativeLibUtilTest, GetHapSoPath_0200, TestSize.Level1)
{
    AppExecFwk::HapModuleInfo hapInfo;
    AppLibPathMap appLibPaths;
    bool isPreInstallApp = true;
    hapInfo.hapPath = "/data/test/NativeLibUtilTest.hap";
    hapInfo.nativeLibraryPath = "";
    AppExecFwk::GetHapSoPath(hapInfo, appLibPaths, isPreInstallApp);
    EXPECT_EQ(appLibPaths.empty(), true);

    hapInfo.nativeLibraryPath = "/data/test/nativeLibraryPath";
    hapInfo.compressNativeLibs = false;
    AppExecFwk::GetHapSoPath(hapInfo, appLibPaths, isPreInstallApp);
    EXPECT_EQ(appLibPaths.empty(), false);
}

/**
 * @tc.number: GetHspNativeLibPath_0300
 * @tc.name: GetHspNativeLibPath
 * @tc.desc: Test whether GetHspNativeLibPath and are called normally.
 */
HWTEST_F(NativeLibUtilTest, GetHspNativeLibPath_0300, TestSize.Level1)
{
    AppExecFwk::BaseSharedBundleInfo hspInfo;
    AppLibPathMap appLibPaths;
    AppLibPathMap appAbcLibPaths;
    bool isPreInstallApp = true;
    hspInfo.nativeLibraryPath = "";
    AppExecFwk::GetHspNativeLibPath(hspInfo, appLibPaths, isPreInstallApp, "", appAbcLibPaths);
    EXPECT_EQ(appLibPaths.empty(), true);
    
    hspInfo.nativeLibraryPath = "/data/test/nativeLibraryPath";
    hspInfo.bundleName = "nativeLibraryTest";
    hspInfo.moduleName = "library";

    hspInfo.compressNativeLibs = false;
    AppExecFwk::GetHspNativeLibPath(hspInfo, appLibPaths, isPreInstallApp, "", appAbcLibPaths);
    EXPECT_EQ(appLibPaths.empty(), false);

    appLibPaths.clear();
    isPreInstallApp = false;
    AppExecFwk::GetHspNativeLibPath(hspInfo, appLibPaths, isPreInstallApp, "", appAbcLibPaths);
    EXPECT_EQ(appLibPaths.empty(), false);
    
    appLibPaths.clear();
    hspInfo.compressNativeLibs = true;
    AppExecFwk::GetHspNativeLibPath(hspInfo, appLibPaths, isPreInstallApp, "", appAbcLibPaths);
    EXPECT_EQ(appLibPaths.empty(), false);
}

/**
 * @tc.number: GetPatchNativeLibPath_0400
 * @tc.name: GetPatchNativeLibPath
 * @tc.desc: Test whether GetPatchNativeLibPath and are called normally.
 */
HWTEST_F(NativeLibUtilTest, GetPatchNativeLibPath_0400, TestSize.Level1)
{
    AppExecFwk::HapModuleInfo hapInfo;
    std::string patchNativeLibraryPath = "";
    AppLibPathMap appLibPaths;
    AppLibPathMap appAbcLibPaths;
    
    hapInfo.hapPath = "/data/test/NativeLibUtilTest.hap";
    hapInfo.isLibIsolated = false;
    AppExecFwk::GetPatchNativeLibPath(hapInfo, patchNativeLibraryPath, appLibPaths, appAbcLibPaths);
    EXPECT_EQ(patchNativeLibraryPath, "");
     
    hapInfo.compressNativeLibs = true;
    patchNativeLibraryPath = "/data/test/patchNativeLibraryPath";
    AppExecFwk::GetPatchNativeLibPath(hapInfo, patchNativeLibraryPath, appLibPaths, appAbcLibPaths);
    EXPECT_EQ(appLibPaths.empty(), true);

    hapInfo.isLibIsolated = true;
    hapInfo.compressNativeLibs = false;
    hapInfo.bundleName = "nativeLibraryTest";
    hapInfo.moduleName = "library";
    hapInfo.hqfInfo.nativeLibraryPath = "/data/test/nativeLibraryPath";
    AppExecFwk::GetPatchNativeLibPath(hapInfo, patchNativeLibraryPath, appLibPaths, appAbcLibPaths);
    EXPECT_EQ(appLibPaths.empty(), false);
}
} // namespace AbilityRuntime
} // namespace OHOS
