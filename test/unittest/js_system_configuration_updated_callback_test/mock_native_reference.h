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

#ifndef MOCK_NATIVE_REFERENCE_H
#define MOCK_NATIVE_REFERENCE_H

#include "native_reference.h"

namespace OHOS {
namespace AbilityRuntime {

class MockNativeReference : public NativeReference {
public:
    MockNativeReference()
    {}
    ~MockNativeReference() override = default;

    napi_value GetNapiValue() override
    {
        return reinterpret_cast<napi_value>(0x2);
    }
    uint32_t Ref() override
    {
        return 0;
    }
    uint32_t Unref() override
    {
        return 0;
    }
    napi_value Get() override
    {
        return nullptr;
    }

    operator napi_value() override
    {
        return 0;
    }
    void SetDeleteSelf() override
    {}

    uint32_t GetRefCount() override
    {
        return 0;
    }
    bool GetFinalRun() override
    {
        return true;
    }
};

}  // namespace AbilityRuntime
}  // namespace OHOS

#endif  // MOCK_NATIVE_REFERENCE_H
