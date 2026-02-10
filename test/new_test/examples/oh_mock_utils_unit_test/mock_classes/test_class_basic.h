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

#ifndef OHOS_ABILITY_RUNTIME_TEST_CLASS_BASIC_H
#define OHOS_ABILITY_RUNTIME_TEST_CLASS_BASIC_H

#include <string>
#include <vector>
#include "oh_mock_utils.h"

namespace OHOS {
namespace TestMock {

/**
 * @class TestClassBasic
 * @brief Basic mock class for testing OH_MOCK_METHOD and OH_MOCK_VOID_METHOD macros
 *
 * This class demonstrates the usage of basic mock macros for member functions
 * with return values and void member functions.
 */
class TestClassBasic {
public:
    /**
     * @brief Mock method for testing OH_MOCK_METHOD with int return type
     * @param a First integer parameter
     * @param b Second integer parameter
     * @return int Calculated result (mocked)
     */
    OH_MOCK_METHOD(int, TestClassBasic, Calculate, int, int);

    /**
     * @brief Mock method for testing OH_MOCK_METHOD with string return type
     * @param message Input message string
     * @return std::string Processed message (mocked)
     */
    OH_MOCK_METHOD(std::string, TestClassBasic, GetMessage, const std::string&);

    /**
     * @brief Mock void method for testing OH_MOCK_VOID_METHOD
     * @param command Command string
     * @param priority Priority level
     */
    OH_MOCK_VOID_METHOD(TestClassBasic, Execute, const std::string&, int);
};

} // namespace TestMock
} // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_TEST_CLASS_BASIC_H
