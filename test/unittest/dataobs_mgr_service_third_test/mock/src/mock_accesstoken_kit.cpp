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

#include "mock_accesstoken_kit.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
ATokenTypeEnum AccessTokenKit::tokenTypeFlag_ = ATokenTypeEnum::TOKEN_INVALID;
int AccessTokenKit::hapTokenInfo_ = 0;
int AccessTokenKit::hapTokenUserId_ = 0;

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID tokenID)
{
    return tokenTypeFlag_;
}

int AccessTokenKit::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo &hapInfo)
{
    hapInfo.userID =  hapTokenUserId_;
    return hapTokenInfo_;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS