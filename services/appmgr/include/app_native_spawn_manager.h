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

#ifndef OHOS_APP_NATIVE_SPAWN_MANAGER_H
#define OHOS_APP_NATIVE_SPAWN_MANAGER_H

#include <mutex>
#include <string>
#include "nocopyable.h"
#include "app_running_manager.h"
#include "native_child_notify_interface.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @class AppNativeSpawnManager
 * provides native spawn exit.
 */
class AppNativeSpawnManager {
public:
    /**
     * GetInstance, get an instance of AppNativeSpawnManager.
     *
     * @return An instance of AppNativeSpawnManager.
     */
    static AppNativeSpawnManager &GetInstance();

    /**
     * AppNativeSpawnManager, destructor.
     *
     */
    ~AppNativeSpawnManager();

    int32_t RegisterNativeChildExitNotify(const sptr<INativeChildNotify> &callback);

    int32_t UnregisterNativeChildExitNotify(const sptr<INativeChildNotify> &callback);

    // pid is parent pid
    sptr<INativeChildNotify> GetNativeChildCallbackByPid(int32_t pid);

    // pid is parent pid
    void RemoveNativeChildCallbackByPid(int32_t pid);

    void InitNativeSpawnMsgPipe(std::shared_ptr<AppRunningManager> appRunningManager);

    int GetNRfd() const
    {
        return nrFd_;
    }

    int GetNWfd() const
    {
        return nwFd_;
    }

    void NotifyChildProcessExitTask(int32_t pid, int32_t signal, const std::string &bundleName);

    int32_t GetChildRelation(int32_t childPid);

    void AddChildRelation(int32_t childPid, int32_t parentPid);

    void RemoveChildRelation(int32_t childPid);
private:
    /**
     * AppUtils, private constructor.
     *
     */
    AppNativeSpawnManager();

    //native spawn use
    int nrFd_ = -1;
    int nwFd_ = -1;
    std::mutex nativeChildCallbackLock_;
    std::map<int32_t, sptr<INativeChildNotify>> nativeChildCallbackMap_;

    // child pid -> parent pid
    std::mutex childRelationLock_;
    std::map<int32_t, int32_t> childRelationMap_;
    std::shared_ptr<AppRunningManager> appRunningManager_ = nullptr;
    DISALLOW_COPY_AND_MOVE(AppNativeSpawnManager);
};
}
}
#endif  // OHOS_APP_NATIVE_SPAWN_MANAGER_H