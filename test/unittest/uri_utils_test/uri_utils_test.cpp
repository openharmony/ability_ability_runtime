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

#include "app_utils.h"
#include "array_wrapper.h"
#include "string_wrapper.h"

#include "uri_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
namespace {
const int32_t BEYOND_MAX_URI_COUNT = 501;
const int32_t MAX_URI_COUNT = 500;
}
class UriUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void UriUtilsTest::SetUpTestCase() {}

void UriUtilsTest::TearDownTestCase() {}

void UriUtilsTest::SetUp() {}

void UriUtilsTest::TearDown() {}

/*
 * Feature: UriUtils
 * Function: GetUriListFromWantDms
 * SubFunction: NA
 * FunctionPoints: UriUtils GetUriListFromWantDms
 */
HWTEST_F(UriUtilsTest, GetUriListFromWantDms_001, TestSize.Level1)
{
    Want want;
    auto uriList = UriUtils::GetInstance().GetUriListFromWantDms(want);
    EXPECT_EQ(uriList.size(), 0);

    WantParams params;
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(BEYOND_MAX_URI_COUNT, AAFwk::g_IID_IString);
    if (ao != nullptr) {
        for (size_t i = 0; i < BEYOND_MAX_URI_COUNT; i++) {
            ao->Set(i, String::Box("file"));
        }
        params.SetParam("ability.verify.uri", ao);
    }
    want.SetParams(params);
    auto uriList2 = UriUtils::GetInstance().GetUriListFromWantDms(want);
    EXPECT_EQ(uriList2.size(), 0);

    sptr<AAFwk::IArray> ao2 = new (std::nothrow) AAFwk::Array(1, AAFwk::g_IID_IString);
    if (ao2 != nullptr) {
        ao2->Set(0, String::Box("file://data/storage/el2/distributedfiles/test.txt"));
        params.SetParam("ability.verify.uri", ao2);
    }
    want.SetParams(params);
    auto uriList3 = UriUtils::GetInstance().GetUriListFromWantDms(want);
    EXPECT_EQ(uriList3.size(), 0);
}

/*
 * Feature: UriUtils
 * Function: CheckNonImplicitShareFileUri
 * SubFunction: NA
 * FunctionPoints: UriUtils CheckNonImplicitShareFileUri
 */
HWTEST_F(UriUtilsTest, CheckNonImplicitShareFileUri_001, TestSize.Level1)
{
    Want want;
    int32_t userId = 1;
    uint32_t specifyTokenId = 1001;
    int32_t errorCode0 = UriUtils::GetInstance().CheckNonImplicitShareFileUri(want, userId, specifyTokenId);
    EXPECT_EQ(errorCode0, ERR_OK);

    want.SetElementName("com.example.tsapplication", "EntryAbility");
    int32_t errorCode1 = UriUtils::GetInstance().CheckNonImplicitShareFileUri(want, userId, specifyTokenId);
    EXPECT_EQ(errorCode1, ERR_OK);
#ifdef SUPPORT_UPMS
    want.SetFlags(0x00000003);
    int32_t errorCode2 = UriUtils::GetInstance().CheckNonImplicitShareFileUri(want, userId, specifyTokenId);
    EXPECT_EQ(errorCode2, ERR_OK);

    want.SetFlags(0x00000001);
    int32_t errorCode3 = UriUtils::GetInstance().CheckNonImplicitShareFileUri(want, userId, specifyTokenId);
    EXPECT_EQ(errorCode3, ERR_OK);
#endif // SUPPORT_UPMS
    want.SetUri("file://data/storage/el2/distributedfiles/test.txt");
    int32_t errorCode4 = UriUtils::GetInstance().CheckNonImplicitShareFileUri(want, userId, specifyTokenId);
    EXPECT_EQ(errorCode4, ERR_OK);

    WantParams params;
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(1, AAFwk::g_IID_IString);
    if (ao != nullptr) {
        ao->Set(0, String::Box("file"));
        params.SetParam("ability.params.stream", ao);
    }
    want.SetParams(params);
    int32_t errorCode5 = UriUtils::GetInstance().CheckNonImplicitShareFileUri(want, userId, specifyTokenId);
    EXPECT_EQ(errorCode5, ERR_OK);
}

/*
 * Feature: UriUtils
 * Function: CheckNonImplicitShareFileUriInner
 * SubFunction: NA
 * FunctionPoints: UriUtils CheckNonImplicitShareFileUriInner
 */
HWTEST_F(UriUtilsTest, CheckNonImplicitShareFileUriInner_001, TestSize.Level1)
{
    uint32_t callerTokenId = 1001;
    std::string targetBundleName = "com.example.tsapplication";
    int32_t userId = 1;
    int32_t errorCode0 =
        UriUtils::GetInstance().CheckNonImplicitShareFileUriInner(callerTokenId, targetBundleName, userId);
    EXPECT_EQ(errorCode0, INNER_ERR);

    callerTokenId = 0;
    int32_t errorCode1 =
        UriUtils::GetInstance().CheckNonImplicitShareFileUriInner(callerTokenId, targetBundleName, userId);
    EXPECT_EQ(errorCode1, CHECK_PERMISSION_FAILED);
}

/*
 * Feature: UriUtils
 * Function: IsSystemApplication
 * SubFunction: NA
 * FunctionPoints: UriUtils IsSystemApplication
 */
HWTEST_F(UriUtilsTest, IsSystemApplication_001, TestSize.Level1)
{
    std::string targetBundleName = "com.example.tsapplication";
    int32_t userId = 1;
    bool result = UriUtils::GetInstance().IsSystemApplication(targetBundleName, userId);
    EXPECT_EQ(result, false);
}

/*
 * Feature: UriUtils
 * Function: GetPermissionedUriList
 * SubFunction: NA
 * FunctionPoints: UriUtils GetPermissionedUriList
 */
HWTEST_F(UriUtilsTest, GetPermissionedUriList_001, TestSize.Level1)
{
    std::vector<std::string> uriVec;
    std::vector<bool> checkResults = {true};
    Want want;
    std::vector<Uri> vec = UriUtils::GetInstance().GetPermissionedUriList(uriVec, checkResults, want);
    EXPECT_EQ(vec.size(), 0);

    want.SetUri("ability.verify.uri");
    uriVec.push_back("file://data/storage/el2/distributedfiles/test.txt");
    std::vector<Uri> vec2 = UriUtils::GetInstance().GetPermissionedUriList(uriVec, checkResults, want);
    EXPECT_EQ(vec2.size(), 1);

    checkResults[0] = false;
    std::vector<Uri> vec3 = UriUtils::GetInstance().GetPermissionedUriList(uriVec, checkResults, want);
    EXPECT_EQ(vec3.size(), 0);

    checkResults[0] = true;
    uriVec.push_back("https//test.openharmony.com");
    checkResults.push_back(true);
    std::vector<Uri> vec4 = UriUtils::GetInstance().GetPermissionedUriList(uriVec, checkResults, want);
    EXPECT_EQ(vec4.size(), 2);

    checkResults[1] = false;
    std::vector<Uri> vec5 = UriUtils::GetInstance().GetPermissionedUriList(uriVec, checkResults, want);
    EXPECT_EQ(vec5.size(), 1);
}

/*
 * Feature: UriUtils
 * Function: GetUriListFromWant
 * SubFunction: NA
 * FunctionPoints: UriUtils GetUriListFromWant
 */
HWTEST_F(UriUtilsTest, GetUriListFromWant_001, TestSize.Level1)
{
    Want want;
    WantParams params;
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(1, AAFwk::g_IID_IString);
    if (ao != nullptr) {
        ao->Set(0, String::Box("file"));
        params.SetParam("ability.params.stream", ao);
    }
    std::vector<std::string> uriVec;
    bool res0 = UriUtils::GetInstance().GetUriListFromWant(want, uriVec);
    EXPECT_EQ(res0, false);

    for (size_t i = 0; i < BEYOND_MAX_URI_COUNT; i++) {
        uriVec.push_back("https//test.openharmony.com");
    }
    want.SetUri("file://data/storage/el2/distributedfiles/test.txt");
    bool res1 = UriUtils::GetInstance().GetUriListFromWant(want, uriVec);
    EXPECT_EQ(res1, true);

    bool res2 = UriUtils::GetInstance().GetUriListFromWant(want, uriVec);
    EXPECT_EQ(res2, true);

    uriVec.clear();
    uriVec.push_back("https//test.openharmony.com");
    bool res3 = UriUtils::GetInstance().GetUriListFromWant(want, uriVec);
    EXPECT_EQ(res3, true);
}

/*
 * Feature: UriUtils
 * Function: IsDmsCall
 * SubFunction: NA
 * FunctionPoints: UriUtils IsDmsCall
 */
HWTEST_F(UriUtilsTest, IsDmsCall_001, TestSize.Level1)
{
    uint32_t fromTokenId = 1001;
    bool res1 = UriUtils::GetInstance().IsDmsCall(fromTokenId);
    EXPECT_EQ(res1, false);
}

#ifdef SUPPORT_UPMS
/*
 * Feature: UriUtils
 * Function: GrantDmsUriPermission
 * SubFunction: NA
 * FunctionPoints: UriUtils GrantDmsUriPermission
 */
HWTEST_F(UriUtilsTest, GrantDmsUriPermission_001, TestSize.Level1)
{
    Want want;
    uint32_t callerTokenId = 1;
    std::string targetBundleName = "com.example.tsapplication";
    int32_t appIndex = 101;
    WantParams params;
    sptr<AAFwk::IArray> ao2 = new (std::nothrow) AAFwk::Array(1, AAFwk::g_IID_IString);
    if (ao2 != nullptr) {
        ao2->Set(0, String::Box("file://data/storage/el2/distributedfiles/test.txt"));
        params.SetParam("ability.verify.uri", ao2);
    }
    want.SetParams(params);
    UriUtils::GetInstance().GrantDmsUriPermission(want, callerTokenId, targetBundleName, appIndex);
    bool res = want.GetParams().HasParam("ability.verify.uri");
    EXPECT_EQ(res, true);
}

/*
 * Feature: UriUtils
 * Function: GrantShellUriPermission
 * SubFunction: NA
 * FunctionPoints: UriUtils GrantShellUriPermission
 */
HWTEST_F(UriUtilsTest, GrantShellUriPermission_001, TestSize.Level1)
{
    std::vector<std::string> strUriVec = {"file://data/storage/el2/distributedfiles/test.txt"};
    uint32_t flag = 0;
    std::string targetPkg;
    int32_t appIndex = 101;
    bool res0 = UriUtils::GetInstance().GrantShellUriPermission(strUriVec, flag, targetPkg, appIndex);
    EXPECT_EQ(res0, false);

    strUriVec[0] = "content://data/storage/el2/distributedfiles/test.txt";
    bool res1 = UriUtils::GetInstance().GrantShellUriPermission(strUriVec, flag, targetPkg, appIndex);
    EXPECT_EQ(res1, true);
}

/*
 * Feature: UriUtils
 * Function: CheckUriPermission
 * SubFunction: NA
 * FunctionPoints: UriUtils CheckUriPermission
 */
HWTEST_F(UriUtilsTest, CheckUriPermission_001, TestSize.Level1)
{
    uint32_t callerTokenId = 1;
    Want want;
    want.SetFlags(0x00000003);

    WantParams params;
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(BEYOND_MAX_URI_COUNT, AAFwk::g_IID_IString);
    if (ao != nullptr) {
        for (size_t i = 0; i < BEYOND_MAX_URI_COUNT; i++) {
            ao->Set(i, String::Box("file"));
        }
        params.SetParam("ability.params.stream", ao);
    }
    want.SetParams(params);
    UriUtils::GetInstance().CheckUriPermission(callerTokenId, want);
    sptr<IInterface> value = want.GetParams().GetParam("ability.params.stream");
    IArray *arr = IArray::Query(value);
    long arrSize = 0;
    if (arr != nullptr && Array::IsStringArray(arr)) {
        arr->GetLength(arrSize);
    }
    EXPECT_EQ(arrSize, MAX_URI_COUNT);
}

/*
 * Feature: UriUtils
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: UriUtils GrantUriPermission
 */
HWTEST_F(UriUtilsTest, GrantUriPermission_001, TestSize.Level1)
{
    Want want;
    std::string targetBundleName = "";
    int32_t appIndex = 101;
    bool isSandboxApp = false;
    int32_t callerTokenId = 0;
    int32_t collaboratorType = 2;
    want.SetFlags(0x00000003);
    UriUtils::GetInstance().GrantUriPermission(want, targetBundleName, appIndex, isSandboxApp, callerTokenId,
        collaboratorType);

    want.SetFlags(0x00000001);
    UriUtils::GetInstance().GrantUriPermission(want, targetBundleName, appIndex, isSandboxApp, callerTokenId,
        collaboratorType);

    targetBundleName = "com.example.tsapplication";
    UriUtils::GetInstance().GrantUriPermission(want, targetBundleName, appIndex, isSandboxApp, callerTokenId,
        collaboratorType);

    callerTokenId = 1001;
    UriUtils::GetInstance().GrantUriPermission(want, targetBundleName, appIndex, isSandboxApp, callerTokenId,
        collaboratorType);

    WantParams params;
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(1, AAFwk::g_IID_IString);
    if (ao != nullptr) {
        ao->Set(0, String::Box("file"));
        params.SetParam("ability.params.stream", ao);
    }
    want.SetParams(params);
    UriUtils::GetInstance().GrantUriPermission(want, targetBundleName, appIndex, isSandboxApp, callerTokenId,
        collaboratorType);

    want.SetUri("file://data/storage/el2/distributedfiles/test.txt");
    UriUtils::GetInstance().GrantUriPermission(want, targetBundleName, appIndex, isSandboxApp, callerTokenId,
        collaboratorType);

    std::string bundleName = AppUtils::GetInstance().GetBrokerDelegateBundleName();
    EXPECT_EQ(bundleName.empty(), true);
}

/*
 * Feature: UriUtils
 * Function: GrantUriPermissionInner
 * SubFunction: NA
 * FunctionPoints: UriUtils GrantUriPermissionInner
 */
HWTEST_F(UriUtilsTest, GrantUriPermissionInner_001, TestSize.Level1)
{
    std::vector<std::string> uriVec = {"file://data/storage/el2/distributedfiles/test.txt"};
    uint32_t callerTokenId = 0;
    std::string targetBundleName = "com.example.tsapplication";
    int32_t appIndex = 0;
    Want want;
    bool res = UriUtils::GetInstance().GrantUriPermissionInner(uriVec, callerTokenId, targetBundleName, appIndex, want);
    EXPECT_EQ(res, false);
}
#endif // SUPPORT_UPMS

/*
 * Feature: UriUtils
 * Function: IsSandboxApp
 * SubFunction: NA
 * FunctionPoints: UriUtils IsSandboxApp
 */
HWTEST_F(UriUtilsTest, IsSandboxApp_001, TestSize.Level1)
{
    uint32_t tokenId = 0;
    bool res = UriUtils::GetInstance().IsSandboxApp(tokenId);
    EXPECT_EQ(res, false);

    tokenId = 1001;
    res = UriUtils::GetInstance().IsSandboxApp(tokenId);
    EXPECT_EQ(res, false);
}

/*
 * Feature: UriUtils
 * Function: GrantUriPermissionForServiceExtension
 * SubFunction: NA
 * FunctionPoints: UriUtils GrantUriPermissionForServiceExtension
 */
HWTEST_F(UriUtilsTest, GrantUriPermissionForServiceExtension_001, TestSize.Level1)
{
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::FORM;
    UriUtils::GetInstance().GrantUriPermissionForServiceExtension(abilityRequest);

    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SERVICE;
    UriUtils::GetInstance().GrantUriPermissionForServiceExtension(abilityRequest);
    EXPECT_EQ(abilityRequest.abilityInfo.extensionAbilityType, AppExecFwk::ExtensionAbilityType::SERVICE);
}

/*
 * Feature: UriUtils
 * Function: GrantUriPermissionForUIOrServiceExtension
 * SubFunction: NA
 * FunctionPoints: UriUtils GrantUriPermissionForUIOrServiceExtension
 */
HWTEST_F(UriUtilsTest, GrantUriPermissionForUIOrServiceExtension_001, TestSize.Level1)
{
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::FORM;
    UriUtils::GetInstance().GrantUriPermissionForUIOrServiceExtension(abilityRequest);

    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SERVICE;
    UriUtils::GetInstance().GrantUriPermissionForUIOrServiceExtension(abilityRequest);
    EXPECT_EQ(abilityRequest.abilityInfo.extensionAbilityType, AppExecFwk::ExtensionAbilityType::SERVICE);
}
}
}