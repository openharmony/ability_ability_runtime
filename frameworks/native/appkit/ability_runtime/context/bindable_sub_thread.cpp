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

#include "bindable_sub_thread.h"

#include "hilog_tag_wrapper.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace AbilityRuntime {
struct HookData {
    BindableSubThread* instance;
    napi_env env;
};

void BindableSubThread::BindSubThreadObject(void* napiEnv, void* object)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "bind sub thread object");
    std::lock_guard guard(objectsMutex_);
    auto it = objects_.find(napiEnv);
    if (it != objects_.end()) {
        return;
    }

    napi_env acutalEnv = static_cast<napi_env>(napiEnv);
    HookData* data = new HookData { this, acutalEnv };
    if (data == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "data err");
        return;
    }

    napi_status ret = napi_add_env_cleanup_hook(acutalEnv,
        StaticRemoveSubThreadObject, data);
    if (ret != napi_status::napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "add hook err");
        delete data;
        return;
    }

    std::unique_ptr<void, void (*)(void*)> obj(object, nullptr);
    objects_.emplace(napiEnv, std::move(obj));
}

void* BindableSubThread::GetSubThreadObject(void* napiEnv)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "get sub thread object");
    std::lock_guard guard(objectsMutex_);
    const auto& iter = objects_.find(napiEnv);
    if (iter == objects_.end()) {
        return nullptr;
    }
    return static_cast<void*>(iter->second.get());
}

void BindableSubThread::RemoveSubThreadObject(void* napiEnv)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "remove sub thread object");
    std::lock_guard guard(objectsMutex_);
    objects_.erase(napiEnv);
}

void BindableSubThread::StaticRemoveSubThreadObject(void* arg)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "remove sub thread object");
    HookData* data = static_cast<HookData*>(arg);
    if (data) {
        data->instance->RemoveSubThreadObject(data->env);
        delete data;
    }
}
} // namespace AbilityRuntime
} // namespace OHOS
