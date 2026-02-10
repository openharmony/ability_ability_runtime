/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_TEST_DATA_TYPES_H
#define OHOS_ABILITY_RUNTIME_TEST_DATA_TYPES_H

#include <string>

namespace OHOS {
namespace TestMock {

/**
 * @struct PermissionInfo
 * @brief Permission information structure for testing
 *
 * This structure is used to test mock methods with custom struct types.
 */
struct PermissionInfo {
    int32_t tokenId;                  ///< Token identifier
    std::string permissionName;       ///< Permission name
};

/**
 * @struct UserInfo
 * @brief User information structure for testing
 *
 * This structure is used to test mock methods with output parameters
 * and custom struct types.
 */
struct UserInfo {
    int32_t userId;                   ///< User identifier
    std::string userName;             ///< User name
};

} // namespace TestMock
} // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_TEST_DATA_TYPES_H
