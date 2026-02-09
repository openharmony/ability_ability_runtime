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

#ifndef OHOS_ABILITY_RUNTIME_TEST_NATIVE_ENGINE_H
#define OHOS_ABILITY_RUNTIME_TEST_NATIVE_ENGINE_H

#include <cstdint>

class NativeReference {
public:
    static inline int32_t destructCount = 0;
    virtual ~NativeReference() { destructCount++; }
    static void ResetCount() { destructCount = 0; }
};

using napi_env = void*;
using napi_env_cleanup_hook = void (*)(void*);

enum napi_status {
    napi_ok = 0,
    napi_generic_failure = 1,
};

inline napi_status g_mockHookResult = napi_ok;
inline napi_env_cleanup_hook g_lastHook = nullptr;
inline void* g_lastHookData = nullptr;

inline void SetMockHookResult(napi_status status)
{
    g_mockHookResult = status;
}

inline void TriggerCleanupHook()
{
    if (g_lastHook != nullptr) {
        g_lastHook(g_lastHookData);
    }
}

inline napi_status napi_add_env_cleanup_hook(napi_env env, napi_env_cleanup_hook hook, void* data)
{
    g_lastHook = hook;
    g_lastHookData = data;
    return g_mockHookResult;
}

#endif // OHOS_ABILITY_RUNTIME_TEST_NATIVE_ENGINE_H
