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

#ifndef OHOS_ABILITY_RUNTIME_CONTEXT_TRANSFER_H
#define OHOS_ABILITY_RUNTIME_CONTEXT_TRANSFER_H

#include <memory>
#include "context.h"
#include "ani.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace AbilityRuntime {
using CreateStaticObject = std::function<ani_object (ani_env *aniEnv, std::shared_ptr<Context> context)>;
using CreateDynamicObject = std::function<napi_value (napi_env napiEnv, std::shared_ptr<Context> context)>;
class ContextTransfer {
public:
    static ContextTransfer &GetInstance();
    ContextTransfer() = default;
    ~ContextTransfer() = default;

    void RegisterStaticObjectCreator(const std::string &contextType, const CreateStaticObject &createFunc);
    ani_object GetStaticObject(const std::string &contextType, ani_env *aniEnv, std::shared_ptr<Context> context);

    void RegisterDynamicObjectCreator(const std::string &contextType, const CreateDynamicObject &createFunc);
    napi_value GetDynamicObject(const std::string &contextType, napi_env napiEnv, std::shared_ptr<Context> context);

    bool IsStaticCreatorExist(const std::string &contextType);
    bool IsDynamicCreatorExist(const std::string &contextType);

private:
    ContextTransfer(const ContextTransfer&) = delete;
    ContextTransfer(ContextTransfer&&) = delete;
    ContextTransfer& operator=(const ContextTransfer&) = delete;
    ContextTransfer& operator=(ContextTransfer&&) = delete;

    std::mutex creatorMutex_;
    std::unordered_map<std::string, CreateStaticObject> staticCreators_;
    std::unordered_map<std::string, CreateDynamicObject> dynamicCreators_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_CONTEXT_TRANSFER_H
