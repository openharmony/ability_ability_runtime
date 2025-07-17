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

std::unique_ptr<Runtime> Runtime::Create(Runtime::Options &options)
{
    switch (options.lang) {
        case Runtime::Language::JS:
            return JsRuntime::Create(options);
#ifdef CJ_FRONTEND
        case Runtime::Language::CJ:
            return CJRuntime::Create(options);
#endif
        case Runtime::Language::ETS: {
            std::unique_ptr<JsRuntime> jsRuntime;
            if (options.lang == Runtime::Language::ETS) {
                options.lang = Runtime::Language::JS;
                jsRuntime = JsRuntime::Create(options);
                options.lang = Runtime::Language::ETS;
            }
            return ETSRuntime::Create(options, jsRuntime);
        }
        default:
            return std::unique_ptr<Runtime>();
    }
}

void Runtime::SavePreloaded(std::unique_ptr<Runtime> &&instance)
{
    if (instance) {
        instance->FinishPreload();
    }
    g_preloadedInstance = std::move(instance);
}

std::unique_ptr<Runtime> Runtime::GetPreloaded(Language key)
{
    if (g_preloadedInstance &&
        g_preloadedInstance->GetLanguage() == Language::ETS &&
        key == Language::JS) {
        return static_cast<ETSRuntime *>(g_preloadedInstance.get())->MoveJsRuntime();
    }
    return std::move(g_preloadedInstance);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
