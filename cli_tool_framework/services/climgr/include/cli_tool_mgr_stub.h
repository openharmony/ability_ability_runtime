/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_CLI_TOOL_MGR_STUB_H
#define OHOS_ABILITY_RUNTIME_CLI_TOOL_MGR_STUB_H

#include <string>

#include "cli_tool_interface.h"
#include "iremote_stub.h"
#include "iremote_object.h"

namespace OHOS {
namespace CliTool {

/**
 * @brief Implementation of ICliSa IPC stub.
 * Handles incoming IPC requests from clients.
 */
class CliToolMGRStub : public IRemoteStub<ICliToolInterface> {
public:
    /**
     * @brief Handle IPC request.
     * @param data Input data parcel.
     * @param reply Output data parcel.
     * @param option IPC option flags.
     * @return ERR_OK on success, error code on failure.
     */
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;
};

} // namespace CliTool
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_CLI_TOOL_MGR_STUB_H
