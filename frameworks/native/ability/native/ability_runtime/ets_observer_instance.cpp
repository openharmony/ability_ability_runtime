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

#include "ets_observer_instance.h"

#include <cstddef>
#include <dlfcn.h>

#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "string_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
const char *ETS_ANI_LIBNAME = "libani_observer.z.so";
const char *ETS_STARTABILITIESOBSERVER_HANDLE_FINISH_FUNC = "OHOS_ETS_START_ABILITIES_OBSERVER_HANDLE_FINISH";
using EtsStartAbilitiesObserverHandleFinishFunc = void(*)(const std::string &requestKey, int32_t resultCode);
EtsStartAbilitiesObserverHandleFinishFunc g_etsStartAbiliesObserverHandleFinishFunc = nullptr;
}

void ETSStartAbilitiesHandleFinished(const std::string &requestKey, int32_t resultCode)
{
    if (g_etsStartAbiliesObserverHandleFinishFunc != nullptr) {
        return g_etsStartAbiliesObserverHandleFinishFunc(requestKey, resultCode);
    }
    auto handle = dlopen(ETS_ANI_LIBNAME, RTLD_LAZY);
    if (handle == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "dlopen failed %{public}s, %{public}s", ETS_ANI_LIBNAME, dlerror());
        return;
    }
    auto symbol = dlsym(handle, ETS_STARTABILITIESOBSERVER_HANDLE_FINISH_FUNC);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "dlsym failed %{public}s, %{public}s",
            ETS_STARTABILITIESOBSERVER_HANDLE_FINISH_FUNC, dlerror());
        dlclose(handle);
        return;
    }
    g_etsStartAbiliesObserverHandleFinishFunc = reinterpret_cast<EtsStartAbilitiesObserverHandleFinishFunc>(symbol);
    return g_etsStartAbiliesObserverHandleFinishFunc(requestKey, resultCode);
}

} // namespace AbilityRuntime
} // namespace OHOS