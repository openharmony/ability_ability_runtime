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

#ifndef OHOS_ABILITY_RUNTIME_RENDER_RECORD_H
#define OHOS_ABILITY_RUNTIME_RENDER_RECORD_H

#include "irender_scheduler.h"
#include "app_death_recipient.h"
#include "fd_guard.h"

namespace OHOS {
namespace AppExecFwk {
using AAFwk::FdGuard;
class AppRunningRecord;

/**
 * @class RenderRecord
 * Record nweb render process info.
 */
class RenderRecord {
public:
    RenderRecord(pid_t hostPid, const std::string &renderParam,
                 FdGuard &&ipcFd, FdGuard &&sharedFd, FdGuard &&crashFd,
                 const std::shared_ptr<AppRunningRecord> &host);

    virtual ~RenderRecord();

    static std::shared_ptr<RenderRecord>
    CreateRenderRecord(pid_t hostPid, const std::string &renderParam,
                       FdGuard &&ipcFd, FdGuard &&sharedFd, FdGuard &&crashFd,
                       const std::shared_ptr<AppRunningRecord> &host);

    void SetPid(pid_t pid);
    pid_t GetPid() const ;
    pid_t GetHostPid() const;
    void SetUid(int32_t uid);
    int32_t GetUid() const;
    int32_t GetHostUid() const;
    std::string GetHostBundleName() const;
    std::string GetRenderParam() const;
    std::string GetProcessName() const;
    int32_t GetIpcFd() const;
    int32_t GetSharedFd() const;
    int32_t GetCrashFd() const;
    ProcessType GetProcessType() const;
    std::shared_ptr<AppRunningRecord> GetHostRecord() const;
    sptr<IRenderScheduler> GetScheduler() const;
    void SetScheduler(const sptr<IRenderScheduler> &scheduler);
    void SetDeathRecipient(const sptr<AppDeathRecipient> recipient);
    void RegisterDeathRecipient();
    void SetState(int32_t state);
    int32_t GetState() const;
    void SetProcessType(ProcessType type);
    void SetProcessName(const std::string &processName);

private:
    void SetHostUid(const int32_t hostUid);
    void SetHostBundleName(const std::string &hostBundleName);

    pid_t pid_ = 0;
    pid_t hostPid_ = 0;
    int32_t uid_ = 0;
    int32_t hostUid_ = 0;
    std::string hostBundleName_;
    std::string renderParam_;
    std::string processName_;
    FdGuard ipcFd_;
    FdGuard sharedFd_;
    FdGuard crashFd_;
    int32_t state_ = 0;
    ProcessType processType_ = ProcessType::RENDER;
    std::weak_ptr<AppRunningRecord> host_; // nweb host
    sptr<IRenderScheduler> renderScheduler_ = nullptr;
    sptr<AppDeathRecipient> deathRecipient_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_RENDER_RECORD_H