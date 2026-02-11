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

#ifndef OHOS_ABILITY_RUNTIME_TEST_CLASS_DECORATOR_H
#define OHOS_ABILITY_RUNTIME_TEST_CLASS_DECORATOR_H

#include <string>
#include <vector>
#include "oh_mock_utils.h"
#include "test_data_types.h"

namespace OHOS {
namespace TestMock {

/**
 * @class TestClassDecorator
 * @brief Mock class for testing static/virtual decorator macros
 *
 * This class demonstrates the usage of:
 * - OH_MOCK_METHOD_WITH_DECORATOR (static methods with return value)
 * - OH_MOCK_VOID_METHOD_WITH_DECORATOR (static void methods)
 * - OH_MOCK_METHOD_WITH_DECORATOR_AND_OUTPUT_1 (static + scalar output)
 * - OH_MOCK_METHOD_WITH_DECORATOR_AND_OUTPUT_VECTOR (static + vector output)
 */
class TestClassDecorator {
public:
    /**
     * @brief Static method with return value for testing OH_MOCK_METHOD_WITH_DECORATOR
     * @param a First integer parameter
     * @param b Second integer parameter
     * @return int Calculated result (mocked)
     */
    OH_MOCK_METHOD_WITH_DECORATOR(static, int, TestClassDecorator, StaticCalculate, int, int);

    /**
     * @brief Static void method for testing OH_MOCK_VOID_METHOD_WITH_DECORATOR
     * @param command Command string to execute
     */
    OH_MOCK_VOID_METHOD_WITH_DECORATOR(static, TestClassDecorator, StaticExecute, const std::string&);

    /**
     * @brief Static method with scalar output parameter
     * @param tokenId Token ID to query
     * @param userInfo [OUT] User information output
     * @return int32_t Return code (mocked)
     */
    OH_MOCK_METHOD_WITH_DECORATOR_AND_OUTPUT_1(static, int, userInfo, TestClassDecorator, GetUserInfo,
        uint32_t, UserInfo& userInfo);

    /**
     * @brief Static method with vector output parameter
     * @param tokenId Token ID to query
     * @param permissions [OUT] Vector of permission names
     * @return int32_t Return code (mocked)
     */
    OH_MOCK_METHOD_WITH_DECORATOR_AND_OUTPUT_VECTOR(static, int, permissions, TestClassDecorator, GetPermissions,
        uint32_t, std::vector<std::string>& permissions);
};

} // namespace TestMock
} // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_TEST_CLASS_DECORATOR_H
