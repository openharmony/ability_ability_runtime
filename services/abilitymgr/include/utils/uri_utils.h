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

    void FilterUriWithPermissionDms(Want &want, uint32_t tokenId);

    int32_t CheckNonImplicitShareFileUri(const Want &want, int32_t userId, uint32_t specifyTokenId);

    std::vector<Uri> GetPermissionedUriList(const std::vector<std::string> &uriVec,
        const std::vector<bool> &checkResults, Want &want);

    bool GetUriListFromWant(Want &want, std::vector<std::string> &uriVec);

    bool IsGrantUriPermissionFlag(const Want &want);

    void CheckUriPermissionForServiceExtension(Want &want, AppExecFwk::ExtensionAbilityType extensionAbilityType);

    void CheckUriPermissionForUIExtension(Want &want, AppExecFwk::ExtensionAbilityType extensionAbilityType,
        uint32_t tokenId = 0);

    bool IsPermissionPreCheckedType(AppExecFwk::ExtensionAbilityType extensionAbilityType);
private:
    UriUtils();
    ~UriUtils();

    std::vector<std::string> GetUriListFromWantDms(const Want &want);

    void CheckUriPermissionForExtension(Want &want, uint32_t tokenId);

    int32_t CheckNonImplicitShareFileUriInner(uint32_t callerTokenId, const std::string &targetBundleName,
        int32_t userId);

    bool IsSystemApplication(const std::string &bundleName, int32_t userId);

    DISALLOW_COPY_AND_MOVE(UriUtils);
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_URI_UTILS_H