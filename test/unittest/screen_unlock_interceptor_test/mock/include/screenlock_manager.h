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

#ifndef SERVICE_SCREENLOCK_MANAGER_H
#define SERVICE_SCREENLOCK_MANAGER_H

#include <mutex>
#include "refbase.h"

namespace OHOS {
namespace ScreenLock {
class ScreenLockManager : public RefBase {
public:
    static sptr<ScreenLockManager> GetInstance();

    bool IsScreenLocked()
    {
        return screenLocked_;
    }
    void SetScreenLockedState(bool screenLockedState)
    {
        screenLocked_ = screenLockedState;
    }
private:
    ScreenLockManager();
    ~ScreenLockManager() override;
    static std::mutex instanceLock_;
    static sptr<ScreenLockManager> instance_;
    bool screenLocked_ = true;
};
}
}

#endif // SERVICE_SCREENLOCK_MANAGER_H