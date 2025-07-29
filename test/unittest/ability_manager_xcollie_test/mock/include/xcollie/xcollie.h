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

#ifndef OHOS_ABILITY_RUNTIME_XCOLLIE_H
#define OHOS_ABILITY_RUNTIME_XCOLLIE_H

#include <cinttypes>
#include <memory>
#include <string>
#include <gmock/gmock.h>

namespace HiviewDFX {
constexpr int32_t XCOLLIE_FLAG_LOG = 0;
class XCollie {
public:
    static XCollie &GetInstance();
    MOCK_METHOD(int32_t, SetTimer, (std::string, uint32_t, nullptr_t, nullptr_t, int32_t), ());
    MOCK_METHOD(void, CancelTimer, (uint32_t), ());

    static std::shared_ptr<XCollie> instance;
};
} // namespace HiviewDFX
#endif // OHOS_ABILITY_RUNTIME_XCOLLIE_H