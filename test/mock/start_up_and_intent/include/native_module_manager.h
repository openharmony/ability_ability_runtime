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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_NATIVE_MODULE_MANAGER_H
#define MOCK_OHOS_ABILITY_RUNTIME_NATIVE_MODULE_MANAGER_H

#include <cstdint>
#include <map>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <pthread.h>

struct NativeModule {
};
 
class NativeModuleManager {
public:
    static NativeModuleManager* GetInstance();
    NativeModule* LoadNativeModule(const char* moduleName, const char* path, bool isAppModule,
        std::string& errInfo, bool internal = false, const char* relativePath = "");
};

#endif
 