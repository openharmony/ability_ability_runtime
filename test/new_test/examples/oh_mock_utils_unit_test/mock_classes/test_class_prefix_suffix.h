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

#ifndef OHOS_ABILITY_RUNTIME_TEST_CLASS_PREFIX_SUFFIX_H
#define OHOS_ABILITY_RUNTIME_TEST_CLASS_PREFIX_SUFFIX_H

#include <string>
#include "oh_mock_utils.h"

namespace OHOS {
namespace TestMock {

/**
 * @class ITestClassInterface
 * @brief Base interface for testing override specifier
 */
class ITestClassInterface {
public:
    virtual ~ITestClassInterface() = default;
    virtual int VirtualMethod(int value) = 0;
};

/**
 * @class TestClassPrefixSuffix
 * @brief Mock class for testing OH_MOCK_METHOD_WITH_PREFIX_AMD_SUFFIX macro
 *
 * This class demonstrates the usage of prefix and suffix decorators for
 * mocking methods with virtual, override, noexcept, and other specifiers.
 */
class TestClassPrefixSuffix : public ITestClassInterface {
public:
    /**
     * @brief Virtual method with override specifier
     * @param value Input value
     * @return int Calculated result (mocked)
     */
    OH_MOCK_METHOD_WITH_PREFIX_AMD_SUFFIX(virtual, override, int, TestClassPrefixSuffix, VirtualMethod, int);

    /**
     * @brief Noexcept method
     * @param message Input message
     * @return std::string Processed message (mocked)
     */
    OH_MOCK_METHOD_WITH_PREFIX_AMD_SUFFIX(, noexcept, std::string, TestClassPrefixSuffix, NoexceptMethod,
        const std::string&);
};

} // namespace TestMock
} // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_TEST_CLASS_PREFIX_SUFFIX_H
