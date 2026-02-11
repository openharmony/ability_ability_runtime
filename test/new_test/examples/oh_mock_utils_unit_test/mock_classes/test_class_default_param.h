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

#ifndef OHOS_ABILITY_RUNTIME_TEST_CLASS_DEFAULT_PARAM_H
#define OHOS_ABILITY_RUNTIME_TEST_CLASS_DEFAULT_PARAM_H

#include <string>
#include "oh_mock_utils.h"

namespace OHOS {
namespace TestMock {

/**
 * @class TestClassDefaultParam
 * @brief Mock class for testing OH_MOCK_FUNCTION_WITH_DEFAULT_PARAM_BODY
 *
 * This class demonstrates the usage of OH_MOCK_FUNCTION_WITH_DEFAULT_PARAM_BODY
 * for mocking methods with default parameters.
 */
class TestClassDefaultParam {
public:
    /**
     * @brief Method with default parameter
     * @param data Input data string
     * @param timeout Timeout in milliseconds (default: 5000)
     * @return int Return code (mocked)
     *
     * Note: This method demonstrates manual implementation with
     * OH_MOCK_FUNCTION_WITH_DEFAULT_PARAM_BODY because C++ preprocessor
     * cannot handle default parameters in macros directly.
     */
    int ProcessData(const std::string& data, int timeout = 5000)
    {
        OH_MOCK_FUNCTION_WITH_DEFAULT_PARAM_BODY(int, TestClassDefaultParam,
            ProcessData, "const std::string&, int");
    }
};

} // namespace TestMock
} // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_TEST_CLASS_DEFAULT_PARAM_H
