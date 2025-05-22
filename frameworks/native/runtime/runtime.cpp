/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "runtime.h"

#ifdef CJ_FRONTEND
#include "cj_runtime.h"
#endif
#include "js_runtime.h"
#include "sts_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
std::map<Runtime::Language, std::unique_ptr<Runtime>> g_preloadedInstances;
}

std::vector<std::unique_ptr<Runtime>> Runtime::CreateRuntimes(Runtime::Options& options)
{
    std::vector<std::unique_ptr<Runtime>> runtimes;
    for (auto lang : options.langs) {
        switch (lang.first) {
            case Runtime::Language::JS:
                options.lang = Runtime::Language::JS;
                runtimes.push_back(JsRuntime::Create(options));
                break;
#ifdef CJ_FRONTEND
            case Runtime::Language::CJ:
                options.lang = Runtime::Language::CJ;
                runtimes.push_back(CJRuntime::Create(options));
                break;
#endif
            case Runtime::Language::STS:
                options.lang = Runtime::Language::JS;
                runtimes.push_back(JsRuntime::Create(options));
                options.lang = Runtime::Language::STS;
                runtimes.push_back(STSRuntime::Create(options, &static_cast<AbilityRuntime::JsRuntime&>(*runtimes[0])));
                break;
            default:
                runtimes.push_back(std::unique_ptr<Runtime>());
                break;
        }
    }
    return runtimes;
}

std::unique_ptr<Runtime> Runtime::Create(Runtime::Options& options)
{
    switch (options.lang) {
        case Runtime::Language::JS:
            return JsRuntime::Create(options);
#ifdef CJ_FRONTEND
        case Runtime::Language::CJ:
            return CJRuntime::Create(options);
#endif
        case Runtime::Language::STS:
            return STSRuntime::PreFork(options);
        default:
            return std::unique_ptr<Runtime>();
    }
}

void Runtime::SavePreloaded(std::unique_ptr<Runtime>&& instance, Language key)
{
    if (instance) {
        instance->FinishPreload();
    }

    auto it = g_preloadedInstances.find(key);
    if (it != g_preloadedInstances.end()) {
        g_preloadedInstances.erase(it);
    }
    g_preloadedInstances.emplace(key, std::move(instance));
}

std::unique_ptr<Runtime> Runtime::GetPreloaded(Language key)
{
    auto it = g_preloadedInstances.find(key);
    if (it == g_preloadedInstances.end()) {
        return nullptr;
    }
    auto instance = std::move(it->second);
    return instance;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
