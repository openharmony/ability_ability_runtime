/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <memory>

#include "jsnapi.h"
#include "mock_jsnapi.h"

namespace panda {
std::shared_ptr<MockJSNApi> MockJSNApi::instance_ = nullptr;

void JSNApi::SetRequestAotCallback(EcmaVM *vm, const RequestAotCallback &cb)
{
    if (MockJSNApi::GetInstance() == nullptr) {
        return;
    }
    MockJSNApi::GetInstance()->SetRequestAotCallback(cb);
}
} // namespace panda
