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

#ifndef OHOS_ABILITY_RUNTIME_TEST_CLASS_WITH_OUTPUT_H
#define OHOS_ABILITY_RUNTIME_TEST_CLASS_WITH_OUTPUT_H

#include <string>
#include <vector>
#include "oh_mock_utils.h"
#include "test_data_types.h"

namespace OHOS {
namespace TestMock {

/**
 * @class TestClassWithOutput
 * @brief Mock class for testing output parameter macros
 *
 * This class demonstrates the usage of:
 * - OH_MOCK_METHOD_WITH_OUTPUT_1 (scalar output)
 * - OH_MOCK_METHOD_WITH_OUTPUT_VECTOR (vector output)
 */
class TestClassWithOutput {
public:
    /**
     * @brief Mock method with scalar output parameter
     * @param inputValue Input integer value
     * @param inputString Input string
     * @param result [OUT] Output integer result
     * @return int32_t Return code (mocked)
     */
    OH_MOCK_METHOD_WITH_OUTPUT_1(int32_t, result, TestClassWithOutput, ProcessData,
        int32_t, const std::string&, int32_t& result);

    /**
     * @brief Mock method with struct output parameter
     * @param tokenId Token ID
     * @param userInfo [OUT] User information output
     * @return int32_t Return code (mocked)
     */
    OH_MOCK_METHOD_WITH_OUTPUT_1(int32_t, userInfo, TestClassWithOutput, GetUserInfo,
        uint32_t, UserInfo& userInfo);

    /**
     * @brief Mock method with vector output parameter (int32_t)
     * @param count Number of items to retrieve
     * @param items [OUT] Vector of retrieved items
     * @return int32_t Return code (mocked)
     */
    OH_MOCK_METHOD_WITH_OUTPUT_VECTOR(int32_t, items, TestClassWithOutput, GetItems,
        uint32_t, std::vector<int32_t>& items);

    /**
     * @brief Mock method with vector output parameter (bool) for permission checking
     * @param tokenId Token ID
     * @param uris Vector of URI strings to check
     * @param results [OUT] Vector of boolean results (true=granted, false=denied)
     * @param flags Vector of permission flags
     * @return int32_t Return code (mocked)
     */
    OH_MOCK_METHOD_WITH_OUTPUT_VECTOR(int32_t, results, TestClassWithOutput, CheckPermissions,
        uint32_t, const std::vector<std::string>&, std::vector<bool>& results, const std::vector<uint32_t>&);
};

} // namespace TestMock
} // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_TEST_CLASS_WITH_OUTPUT_H
