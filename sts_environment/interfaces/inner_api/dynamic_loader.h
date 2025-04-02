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

#ifndef OHOS_ABILITY_RUNTIME_DYNAMIC_LOADER_H
#define OHOS_ABILITY_RUNTIME_DYNAMIC_LOADER_H

#include <dlfcn.h>

extern "C" {
void* DynamicLoadLibrary(Dl_namespace *ns, const char* dlPath, unsigned int mode);
void* DynamicFindSymbol(void* so, const char* symbol);
const char* DynamicGetError();
void DynamicFreeLibrary(void* so);
void DynamicInitNamespace(Dl_namespace* ns, void* parent, const char* entries, const char* name);
};

#endif //OHOS_ABILITY_RUNTIME_DYNAMIC_LOADER_H
