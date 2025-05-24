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

#ifndef ABILITY_RUNTIME_CHILD_PROCESS_CONFIGS_H
#define ABILITY_RUNTIME_CHILD_PROCESS_CONFIGS_H

#include <string>
#include "native_child_process.h"

struct Ability_ChildProcessConfigs {
    /** the custom process name. */
    std::string processName;

    /** the isolation modes used by the native child process module */
    NativeChildProcess_IsolationMode isolationMode = NCP_ISOLATION_MODE_NORMAL;
};

#endif // ABILITY_RUNTIME_CHILD_PROCESS_CONFIGS_H