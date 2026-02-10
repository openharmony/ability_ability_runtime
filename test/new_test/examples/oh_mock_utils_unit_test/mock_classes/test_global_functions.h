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

#ifndef OHOS_ABILITY_RUNTIME_TEST_GLOBAL_FUNCTIONS_H
#define OHOS_ABILITY_RUNTIME_TEST_GLOBAL_FUNCTIONS_H

#include <string>
#include "oh_mock_utils.h"

namespace OHOS {
namespace TestMock {

/**
 * @brief Mock global function for testing OH_MOCK_GLOBAL_METHOD
 * @param a First integer parameter
 * @param b Second integer parameter
 * @return int Calculation result (mocked)
 */
OH_MOCK_GLOBAL_METHOD(int, GlobalCalculate, int, int);

/**
 * @brief Mock global void function for testing OH_MOCK_GLOBAL_VOID_METHOD
 * @param command Command string
 * @param value Integer value
 */
OH_MOCK_GLOBAL_VOID_METHOD(GlobalExecute, const std::string&, int);

} // namespace TestMock
} // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_TEST_GLOBAL_FUNCTIONS_H
