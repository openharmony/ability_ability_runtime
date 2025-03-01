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

#ifndef OHOS_ABILITY_RUNTIME_STS_SERVICE_EXTENSION_H
#define OHOS_ABILITY_RUNTIME_STS_SERVICE_EXTENSION_H

#include "configuration.h"
#ifdef SUPPORT_GRAPHICS
#include "display_manager.h"
#include "system_ability_status_change_stub.h"
#include "window_manager.h"
#endif
#include "service_extension.h"
#include "sts_runtime.h"

class STSNativeReference;

namespace OHOS {
namespace AbilityRuntime {
class ServiceExtension;
class STSRuntime;
 /**
  * @brief Basic service components.
  */
class StsServiceExtension {
public:
    explicit StsServiceExtension(STSRuntime &stsRuntime);
    virtual ~StsServiceExtension();

    static void TestServiceExtension(const std::unique_ptr<Runtime>& runtime);
    static StsServiceExtension *Create(const std::unique_ptr<Runtime> &runtime);
    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
               const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
               std::shared_ptr<AppExecFwk::AbilityHandler> &handler,
               const sptr<IRemoteObject> &token);
    void OnStart(const AAFwk::Want &want);
    sptr<IRemoteObject> OnConnect(const AAFwk::Want &want);
    void OnDisconnect(const AAFwk::Want &want);
    void OnCommand(const AAFwk::Want &want, bool restart, int startId);
    void OnStop();
private:
    ani_ref CallObjectMethod(bool withResult, const char* name, const char* signature, ...);
    void SetAbilityContext(std::shared_ptr<AbilityInfo> abilityInfo,
        std::shared_ptr<AAFwk::Want> want, const std::string &moduleName, const std::string &srcPath);
    STSRuntime& stsRuntime_;
    std::shared_ptr<STSNativeReference> stsAbilityObj_;
    std::weak_ptr<StsServiceExtension> stsServiceExtension_;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_STS_SERVICE_EXTENSION_H
 