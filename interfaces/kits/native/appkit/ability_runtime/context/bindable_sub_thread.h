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

#ifndef OHOS_ABILITY_RUNTIME_BINDABLE_SUB_THREAD_H
#define OHOS_ABILITY_RUNTIME_BINDABLE_SUB_THREAD_H

#include <map>
#include <mutex>
#include <string>

namespace OHOS {
namespace AbilityRuntime {
class BindableSubThread {
public:
    BindableSubThread() = default;
    virtual ~BindableSubThread() = default;

    void BindSubThreadObject(void* napiEnv, void* object);

    void* GetSubThreadObject(void* napiEnv);

    void RemoveSubThreadObject(void* napiEnv);

    static void StaticRemoveSubThreadObject(void* arg);

private:
    BindableSubThread(const BindableSubThread&) = delete;
    BindableSubThread(BindableSubThread&&) = delete;
    BindableSubThread& operator=(const BindableSubThread&) = delete;
    BindableSubThread& operator=(BindableSubThread&&) = delete;

    std::mutex objectsMutex_;
    std::map<void*, std::unique_ptr<void, void (*)(void*)>> objects_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_BINDABLE_SUB_THREAD_H
