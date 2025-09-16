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

    /**
     * @brief Get list of URIs with granted permissions
     * @param uriVec Input vector of URI strings
     * @param checkResults Vector indicating permission check results
     * @param callerTokenId Token ID of the caller
     * @param targetBundleName Bundle name of the target application
     * @param want The Want object containing URI information
     * @return Vector of Uri objects with granted permissions
     */
    std::vector<Uri> GetPermissionedUriList(const std::vector<std::string> &uriVec,
        const std::vector<bool> &checkResults, uint32_t callerTokenId,
        const std::string &targetBundleName, Want &want);

    /**
     * @brief Extract URI list from Want object
     * @param want The Want object containing URI information
     * @param uriVec Output vector to store extracted URIs
     * @return true if URIs were successfully extracted, false otherwise
     */
    bool GetUriListFromWant(Want &want, std::vector<std::string> &uriVec);

#ifdef SUPPORT_UPMS
    /**
     * @brief Check if URI permission flag is set in Want
     * @param want The Want object to check
     * @return true if URI permission flag is set, false otherwise
     */
    bool IsGrantUriPermissionFlag(const Want &want);
#endif // SUPPORT_UPMS

    /**
     * @brief Check if extension type is service extension
     * @param extensionAbilityType The extension ability type to check
     * @return true if the type is service extension, false otherwise
     */
    bool IsServiceExtensionType(AppExecFwk::ExtensionAbilityType extensionAbilityType);

#ifdef SUPPORT_UPMS
    /**
     * @brief Grant URI permission
     * @param want The Want object containing URI information
     * @param callerTokenId Token ID of the caller
     * @param targetBundleName Bundle name of the target application
     * @param appIndex Application index
     */
    void GrantDmsUriPermission(Want &want, uint32_t callerTokenId, std::string targetBundleName, int32_t appIndex);

    /**
     * @brief Grant URI permission for service extension ability
     * @param abilityRequest The ability request containing URI information
     * @return true if permission was successfully granted, false otherwise
     */
    bool GrantUriPermissionForServiceExtension(const AbilityRequest &abilityRequest);

    /**
     * @brief Grant URI permission for UI or service extension ability
     * @param abilityRequest The ability request containing URI information
     * @return true if permission was successfully granted, false otherwise
     */
    bool GrantUriPermissionForUIOrServiceExtension(const AbilityRequest &abilityRequest);

    /**
     * @brief Grant URI permission with detailed parameters
     * @param want The Want object containing URI information
     * @param targetBundleName Bundle name of the target application
     * @param appIndex Application index
     * @param isSandboxApp Whether the target is a sandbox application
     * @param callerTokenId Token ID of the caller
     * @param collaboratorType Type of collaborator
     */
    void GrantUriPermission(Want &want, std::string targetBundleName, int32_t appIndex,
        bool isSandboxApp, uint32_t callerTokenId, int32_t collaboratorType);

    /**
     * @brief Check URI permission for the caller
     * @param callerTokenId Token ID of the caller
     * @param want The Want object containing URI information
     */
    void CheckUriPermission(uint32_t callerTokenId, Want &want);

    /**
     * @brief Grant URI permission for a list of URIs
     * @param uriVec Vector of URI strings
     * @param flag Permission flag
     * @param targetBundleName Bundle name of the target application
     * @param appIndex Application index
     * @param initiatorTokenId Token ID of the initiator
     */
    void GrantUriPermission(const std::vector<std::string> &uriVec, int32_t flag,
        const std::string &targetBundleName, int32_t appIndex, uint32_t initiatorTokenId);
#endif // SUPPORT_UPMS
private:
    UriUtils();
    ~UriUtils();

#ifdef SUPPORT_UPMS
    /**
     * @brief Grant URI permission for shell process
     * @param strUriVec Vector of URI strings
     * @param flag Permission flag
     * @param targetPkg Package name of the target
     * @param appIndex Application index
     * @return true if permission was successfully granted, false otherwise
     */
    bool GrantShellUriPermission(const std::vector<std::string> &strUriVec, uint32_t flag,
        const std::string &targetPkg, int32_t appIndex);
    
    /**
     * @brief Internal implementation of URI permission granting
     * @param uriVec Vector of URI strings
     * @param callerTokenId Token ID of the caller
     * @param targetBundleName Bundle name of the target application
     * @param appIndex Application index
     * @param want The Want object containing URI information
     * @return true if permission was successfully granted, false otherwise
     */
    bool GrantUriPermissionInner(std::vector<std::string> uriVec, uint32_t callerTokenId,
        const std::string &targetBundleName, int32_t appIndex, Want &want);
#endif // SUPPORT_UPMS

    /**
     * @brief Check if the call is from DMS (Distributed Mission Service)
     * @param fromTokenId Token ID of the caller
     * @return true if the call is from DMS, false otherwise
     */
    bool IsDmsCall(uint32_t fromTokenId);

    /**
     * @brief Check if the application is a sandbox application
     * @param tokenId Token ID of the application
     * @return true if the application is a sandbox app, false otherwise
     */
    bool IsSandboxApp(uint32_t tokenId);

    /**
     * @brief Get URI list from Want for DMS
     * @param want The Want object containing URI information
     * @return Vector of Uri objects
     */
    std::vector<Uri> GetUriListFromWantDms(Want &want);

    /**
     * @brief Publish file open event
     * @param want The Want object containing file information
     */
    void PublishFileOpenEvent(const Want &want);

    /**
     * @brief Check if bundle is in Anco app identifier
     * @param bundleName Bundle name to check
     * @return true if the bundle is in Anco app identifier, false otherwise
     */
    bool IsInAncoAppIdentifier(const std::string &bundleName);

    /**
     * @brief Check if identifier matches bundle name in Anco context
     * @param identifier Identifier to check
     * @param bundleName Bundle name to match
     * @return true if identifier matches bundle name, false otherwise
     */
    bool CheckIsInAncoAppIdentifier(const std::string &identifier, const std::string &bundleName);

    /**
     * @brief Process UDMF key in Want object
     * @param want The Want object to process
     */
    void ProcessUDMFKey(Want &want);

    /**
     * @brief Process URI in Want object
     * @param checkResult Result of permission check
     * @param apiVersion API version of the caller
     * @param want The Want object to process
     * @param permissionedUris Output vector for processed URIs
     * @return true if processing was successful, false otherwise
     */
    bool ProcessWantUri(bool checkResult, int32_t apiVersion, Want &want, std::vector<Uri> &permissionedUris);

    /**
     * @brief Get caller name and API version
     * @param tokenId Token ID of the caller
     * @param callerName Output parameter for caller name
     * @param apiVersion Output parameter for API version
     * @return true if information was successfully retrieved, false otherwise
     */
    bool GetCallerNameAndApiVersion(uint32_t tokenId, std::string &callerName, int32_t &apiVersion);

    /**
     * @brief Send URI permission grant event
     * @param callerBundleName Bundle name of the caller
     * @param targetBundleName Bundle name of the target
     * @param oriUri Original URI string
     * @param apiVersion API version of the caller
     * @param eventType Type of the event
     * @return true if event was successfully sent, false otherwise
     */
    bool SendGrantUriPermissionEvent(const std::string &callerBundleName, const std::string &targetBundleName,
        const std::string &oriUri, int32_t apiVersion, const std::string &eventType);

    DISALLOW_COPY_AND_MOVE(UriUtils);
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_URI_UTILS_H