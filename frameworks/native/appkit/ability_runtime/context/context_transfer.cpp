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

#include "context_transfer.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
ContextTransfer &ContextTransfer::GetInstance()
{
    static ContextTransfer contextTransfer;
    return contextTransfer;
}

void ContextTransfer::RegisterStaticObjectCreator(const std::string &contextType, const CreateStaticObject &createFunc)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "Reg static creator for %{public}s", contextType.c_str());
    std::lock_guard<std::mutex> lock(creatorMutex_);
    staticCreators_.emplace(contextType, createFunc);
}

ani_object ContextTransfer::GetStaticObject(const std::string &contextType, ani_env *aniEnv,
    std::shared_ptr<Context> context)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "Get static creator for %{public}s", contextType.c_str());
    std::lock_guard<std::mutex> lock(creatorMutex_);
    auto it = staticCreators_.find(contextType);
    if (it != staticCreators_.end()) {
        return it->second(aniEnv, context);
    }
    return nullptr;
}

void ContextTransfer::RegisterDynamicObjectCreator(const std::string &contextType,
    const CreateDynamicObject &createFunc)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "Reg dynamic creator for %{public}s", contextType.c_str());
    std::lock_guard<std::mutex> lock(creatorMutex_);
    dynamicCreators_.emplace(contextType, createFunc);
}

napi_value ContextTransfer::GetDynamicObject(const std::string &contextType, napi_env napiEnv,
    std::shared_ptr<Context> context)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "Get dynamic creator for %{public}s", contextType.c_str());
    std::lock_guard<std::mutex> lock(creatorMutex_);
    auto it = dynamicCreators_.find(contextType);
    if (it != dynamicCreators_.end()) {
        return it->second(napiEnv, context);
    }
    return nullptr;
}

bool ContextTransfer::IsStaticCreatorExist(const std::string &contextType)
{
    std::lock_guard<std::mutex> lock(creatorMutex_);
    auto it = staticCreators_.find(contextType);
    return it != staticCreators_.end();
}

bool ContextTransfer::IsDynamicCreatorExist(const std::string &contextType)
{
    std::lock_guard<std::mutex> lock(creatorMutex_);
    auto it = dynamicCreators_.find(contextType);
    return it != dynamicCreators_.end();
}
} // namespace AbilityRuntime
} // namespace OHOS
