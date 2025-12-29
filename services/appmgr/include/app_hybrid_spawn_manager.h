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

#ifndef OHOS_APP_HYBRID_SPAWN_MANAGER_H
#define OHOS_APP_HYBRID_SPAWN_MANAGER_H

#include <memory>

#include "app_mgr_service_inner.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @class AppHybridSpawnManager
 * provides hybrid spawn exit.
 */
class AppHybridSpawnManager {
public:
    /**
     * GetInstance, get an instance of AppHybridSpawnManager.
     *
     * @return An instance of AppHybridSpawnManager.
     */
    static AppHybridSpawnManager &GetInstance();

    /**
     * AppHybridSpawnManager, destructor.
     *
     */
    ~AppHybridSpawnManager();

    void InitHybridSpawnMsgPipe(std::weak_ptr<AppMgrServiceInner> appMgrServiceInner);

    int GetHRfd() const
    {
        return hrFd_;
    }

    int GetHWfd() const
    {
        return hwFd_;
    }

    void RecordAppExitSignalReason(int32_t pid, int32_t uid, int32_t signal, std::string &bundleName);
private:
    AppHybridSpawnManager();

    //hybrid spawn use
    int hrFd_ = -1;
    int hwFd_ = -1;
    std::weak_ptr<AppMgrServiceInner> appMgrServiceInner_;
    DISALLOW_COPY_AND_MOVE(AppHybridSpawnManager);
};
}
}
#endif  // OHOS_APP_HYBRID_SPAWN_MANAGER_H