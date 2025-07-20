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
namespace {
struct HookData {
    std::weak_ptr<BindableSubThread> instance;
    napi_env env = nullptr;
};
} // namespace

BindableSubThread::~BindableSubThread()
{
    TAG_LOGD(AAFwkTag::CONTEXT, "destructor");
}

void BindableSubThread::BindSubThreadObject(void* napiEnv, void* object)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "bind sub thread object");
    uintptr_t key = reinterpret_cast<uintptr_t>(napiEnv);
    std::lock_guard guard(objectsMutex_);
    auto it = objects_.find(key);
    if (it != objects_.end()) {
        TAG_LOGD(AAFwkTag::CONTEXT, "object has bound");
        return;
    }

    napi_env acutalEnv = static_cast<napi_env>(napiEnv);
    HookData* data = new (std::nothrow) HookData { weak_from_this(), acutalEnv };
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

    std::unique_ptr<void, void (*)(void*)> obj(object,
        [](void* ptr) {
            TAG_LOGD(AAFwkTag::CONTEXT, "delete sub thread ptr");
            delete static_cast<NativeReference*>(ptr);
        });
    objects_.emplace(key, std::move(obj));
}

void* BindableSubThread::GetSubThreadObject(void* napiEnv)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "get sub thread object");
    uintptr_t key = reinterpret_cast<uintptr_t>(napiEnv);
    std::lock_guard guard(objectsMutex_);
    const auto& iter = objects_.find(key);
    if (iter == objects_.end()) {
        TAG_LOGD(AAFwkTag::CONTEXT, "not found target object");
        return nullptr;
    }
    return static_cast<void*>(iter->second.get());
}

void BindableSubThread::RemoveSubThreadObject(void* napiEnv)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "remove sub thread object");
    uintptr_t key = reinterpret_cast<uintptr_t>(napiEnv);
    std::lock_guard guard(objectsMutex_);
    const auto& iter = objects_.find(key);
    if (iter == objects_.end()) {
        TAG_LOGW(AAFwkTag::CONTEXT, "not found target object");
        return;
    }
    objects_.erase(key);
}

void BindableSubThread::RemoveAllObject()
{
    TAG_LOGD(AAFwkTag::CONTEXT, "remove all object");
    std::lock_guard guard(objectsMutex_);
    objects_.clear();
}

void BindableSubThread::StaticRemoveSubThreadObject(void* arg)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "remove sub thread object");
    HookData* data = static_cast<HookData*>(arg);
    if (data == nullptr) {
        return;
    }

    std::shared_ptr<BindableSubThread> instance = data->instance.lock();
    if (instance == nullptr) {
        TAG_LOGW(AAFwkTag::CONTEXT, "instance nullptr");
        delete data;
        return;
    }

    instance->RemoveSubThreadObject(data->env);
    delete data;
}
} // namespace AbilityRuntime
} // namespace OHOS
