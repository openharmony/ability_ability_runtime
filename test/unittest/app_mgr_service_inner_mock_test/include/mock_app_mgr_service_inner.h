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

#ifndef OHOS_ABILITY_RUNTIME_APP_MGR_SERVICE_INNER_H
#define OHOS_ABILITY_RUNTIME_APP_MGR_SERVICE_INNER_H

#include "app_running_manager.h"
#include "app_running_record.h"
#include "kia_interceptor_interface.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class AppMgrServiceInner
 * AppMgrServiceInner provides a facility for managing ability life cycle.
 */
class AppMgrServiceInner : public std::enable_shared_from_this<AppMgrServiceInner> {
public:
    AppMgrServiceInner() = default;
    virtual ~AppMgrServiceInner() = default;

    int32_t MakeKiaProcess(std::shared_ptr<AAFwk::Want> want, bool &isKia, std::string &watermarkBusinessName,
        bool &isWatermarkEnabled, bool &isFileUri, std::string &processName);
    int32_t ProcessKia(bool isKia, std::shared_ptr<AppRunningRecord> appRecord,
        const std::string& watermarkBusinessName, bool isWatermarkEnabled);

    /**
     * Register KIA interceptor.
     * @param interceptor KIA interceptor.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RegisterKiaInterceptor(const sptr<IKiaInterceptor> &interceptor);

    /**
     * Check if the given pid is a KIA process.
     * @param pid process id.
     * @return Returns true if it is a KIA process, false otherwise.
     */
    virtual int32_t CheckIsKiaProcess(pid_t pid, bool &isKia);

public:
    sptr<IKiaInterceptor> kiaInterceptor_ = nullptr;
    std::shared_ptr<AppRunningManager> appRunningManager_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APP_MGR_SERVICE_INNER_H
