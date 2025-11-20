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

#ifndef OHOS_ABILITY_RUNTIME_ETS_INTEROP_OBJECT_H
#define OHOS_ABILITY_RUNTIME_ETS_INTEROP_OBJECT_H

#include <memory>
#include <node_api.h>

#include "ani.h"
#include "interop_object.h"

typedef struct __hybridgref *hybridgref;
class NativeReference;

namespace OHOS {
namespace AbilityRuntime {
class EtsInteropObject : public InteropObject {
public:
    EtsInteropObject(napi_env env, std::shared_ptr<NativeReference> ref);
    ~EtsInteropObject() override;

    bool IsFromNapi() override;
    ani_object GetAniValue(ani_env *env);

private:
    hybridgref ref_ = nullptr;
    napi_env env_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_INTEROP_OBJECT_H
