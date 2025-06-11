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
#include "ets_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
std::unique_ptr<Runtime> g_preloadedInstance;
}

std::vector<std::unique_ptr<Runtime>> Runtime::CreateRuntimes(Runtime::Options &options)
{
    std::vector<std::unique_ptr<Runtime>> runtimes;
    for (auto lang : options.langs) {
        switch (lang.first) {
            case Runtime::Language::JS:
                options.lang = Runtime::Language::JS;
                runtimes.emplace_back(JsRuntime::Create(options));
                break;
#ifdef CJ_FRONTEND
            case Runtime::Language::CJ:
                options.lang = Runtime::Language::CJ;
                runtimes.emplace_back(CJRuntime::Create(options));
                break;
#endif
            case Runtime::Language::ETS: {
                options.lang = Runtime::Language::JS;
                auto &jsRuntime = runtimes.emplace_back(JsRuntime::Create(options));
                options.lang = Runtime::Language::ETS;
                runtimes.emplace_back(ETSRuntime::Create(options,
                    static_cast<AbilityRuntime::JsRuntime*>(jsRuntime.get())));
                break;
            }
            default:
                runtimes.emplace_back(std::unique_ptr<Runtime>());
                break;
        }
    }
    return runtimes;
}

std::unique_ptr<Runtime> Runtime::Create(Runtime::Options &options)
{
    std::unique_ptr<JsRuntime> jsRuntime;
    if (options.lang == Runtime::Language::ETS) {
        options.lang = Runtime::Language::JS;
        jsRuntime = JsRuntime::Create(options);
        options.lang = Runtime::Language::ETS;
    }
    switch (options.lang) {
        case Runtime::Language::JS:
            return JsRuntime::Create(options);
#ifdef CJ_FRONTEND
        case Runtime::Language::CJ:
            return CJRuntime::Create(options);
#endif
        case Runtime::Language::ETS:
            return ETSRuntime::Create(options, jsRuntime.get());
        default:
            return std::unique_ptr<Runtime>();
    }
}

void Runtime::SavePreloaded(std::unique_ptr<Runtime>&& instance)
{
    if (instance) {
        instance->FinishPreload();
    }
    g_preloadedInstance = std::move(instance);
}

std::unique_ptr<Runtime> Runtime::GetPreloaded()
{
    return std::move(g_preloadedInstance);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
