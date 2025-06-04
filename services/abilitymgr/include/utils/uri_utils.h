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

#ifndef OHOS_ABILITY_RUNTIME_URI_UTILS_H
#define OHOS_ABILITY_RUNTIME_URI_UTILS_H

#include <string>
#include <vector>

#include "ability_record.h"
#include "nocopyable.h"
#include "uri.h"
#include "want.h"

namespace OHOS {
namespace AAFwk {
class UriUtils {
public:
    static UriUtils &GetInstance();

    int32_t CheckNonImplicitShareFileUri(const Want &want, int32_t userId, uint32_t specifyTokenId);

    std::vector<Uri> GetPermissionedUriList(const std::vector<std::string> &uriVec,
        const std::vector<bool> &checkResults, Want &want);

    bool GetUriListFromWant(Want &want, std::vector<std::string> &uriVec);

#ifdef SUPPORT_UPMS
    bool IsGrantUriPermissionFlag(const Want &want);
#endif // SUPPORT_UPMS

    bool IsServiceExtensionType(AppExecFwk::ExtensionAbilityType extensionAbilityType);

#ifdef SUPPORT_UPMS
    void GrantDmsUriPermission(Want &want, uint32_t callerTokenId, std::string targetBundleName, int32_t appIndex);

    void GrantUriPermissionForServiceExtension(const AbilityRequest &abilityRequest);

    void GrantUriPermissionForUIOrServiceExtension(const AbilityRequest &abilityRequest);

    void GrantUriPermission(Want &want, std::string targetBundleName, int32_t appIndex,
        bool isSandboxApp, uint32_t callerTokenId, int32_t collaboratorType);

    void CheckUriPermission(uint32_t callerTokenId, Want &want);

    void GrantUriPermission(const std::vector<std::string> &uriVec, int32_t flag,
        const std::string &targetBundleName, int32_t appIndex, uint32_t initiatorTokenId);
#endif // SUPPORT_UPMS
private:
    UriUtils();
    ~UriUtils();

#ifdef SUPPORT_UPMS
    bool GrantShellUriPermission(const std::vector<std::string> &strUriVec, uint32_t flag,
        const std::string &targetPkg, int32_t appIndex);
    
    bool GrantUriPermissionInner(std::vector<std::string> uriVec, uint32_t callerTokenId,
        const std::string &targetBundleName, int32_t appIndex, Want &want);
#endif // SUPPORT_UPMS

    bool IsDmsCall(uint32_t fromTokenId);

    bool IsSandboxApp(uint32_t tokenId);

    std::vector<Uri> GetUriListFromWantDms(Want &want);

    int32_t CheckNonImplicitShareFileUriInner(uint32_t callerTokenId, const std::string &targetBundleName,
        int32_t userId);

    bool IsSystemApplication(const std::string &bundleName, int32_t userId);

    void PublishFileOpenEvent(const Want &want);

    bool IsInAncoAppIdentifier(const std::string &bundleName);

    bool CheckIsInAncoAppIdentifier(const std::string &identifier, const std::string &bundleName);

    void ProcessUDMFKey(Want &want);

    DISALLOW_COPY_AND_MOVE(UriUtils);
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_URI_UTILS_H