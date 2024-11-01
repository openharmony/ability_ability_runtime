/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_WINDOW_MANAGER_H
#define OHOS_ABILITY_RUNTIME_WINDOW_MANAGER_H

#include <string>
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class WindowManager
 * Record app process info.
 */
class WindowManager {
public:
    static WindowManager &GetInstance();
    static int retCodeSetProcessWatermark;
    static int retCodeSkipSnapshotForAppProcess;

    virtual ~WindowManager() = default;

    int SetProcessWatermark(int pid, const std::string& watermarkBusinessName, bool isWatermarkEnabled);
    int SkipSnapshotForAppProcess(int pid, bool isWatermarkEnabled);

private:
    WindowManager();

    DISALLOW_COPY_AND_MOVE(WindowManager);
};

}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_WINDOW_MANAGER_H
