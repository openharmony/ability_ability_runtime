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

#ifndef ACCESSTOKEN_KIT_H
#define ACCESSTOKEN_KIT_H

#include "access_token.h"
#include "native_token_info.h"
#include "hap_token_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

class PermissionGrantInfo {
public:
    std::string grantBundleName;
    std::string grantServiceAbilityName;
};
class AccessTokenKit {
public:
    static ATokenTypeEnum GetTokenTypeFlag(AccessTokenID tokenID);

    static int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo &nativeTokenInfoRes);

    static int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo &hapInfo);

    static int VerifyAccessToken(AccessTokenID tokenID, const std::string &permissionName, bool crossIpc);

    static void GetPermissionManagerInfo(PermissionGrantInfo &info);
    static uint32_t GetHapTokenID(int32_t userId, const std::string &bundleName, int32_t appIndex);
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // MOCK_ACCESSTOKEN_KIT_H
