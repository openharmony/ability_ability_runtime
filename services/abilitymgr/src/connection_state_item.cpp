/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "connection_state_item.h"

#include "hilog_wrapper.h"

namespace OHOS {
namespace AAFwk {
/**
 * @class ConnectedExtension
 * ConnectedExtension,This class is used to record a connected extension.
 */
class ConnectedExtension : public std::enable_shared_from_this<ConnectedExtension>{
public:
    static std::shared_ptr<ConnectedExtension> CreateConnectedExtension(const std::shared_ptr<ConnectionRecord> &record)
    {
        if (!record) {
            return nullptr;
        }

        auto targetExtension = record->GetAbilityRecord();
        auto targetToken = record->GetTargetToken();
        if (!targetExtension || !targetToken) {
            return nullptr;
        }

        return std::make_shared<ConnectedExtension>(targetExtension, targetToken);
    }

    ConnectedExtension() {}

    ConnectedExtension(const std::shared_ptr<AbilityRecord> &target, const sptr<IRemoteObject> &targetToken)
    {
        if (!target || !targetToken) {
            return;
        }
        extensionPid_ = target->GetPid();
        extensionUid_ = target->GetUid();
        extensionBundleName_ = target->GetAbilityInfo().bundleName;
        extensionModuleName_ = target->GetAbilityInfo().moduleName;
        extensionName_ = target->GetAbilityInfo().name;
        extensionType_ = target->GetAbilityInfo().extensionAbilityType;
        extensionToken_ = targetToken;
    }

    virtual ~ConnectedExtension() = default;

    bool AddConnection(const sptr<IRemoteObject> &connection)
    {
        if (!connection) {
            return false;
        }

        bool needNotify = connections_.empty();
        connections_.emplace(connection);

        return needNotify;
    }

    bool RemoveConnection(const sptr<IRemoteObject> &connection)
    {
        if (!connection) {
            return false;
        }

        connections_.erase(connection);
        return connections_.empty();
    }

    void GenerateExtensionInfo(AbilityRuntime::ConnectionData &data)
    {
        data.extensionPid = extensionPid_;
        data.extensionUid = extensionUid_;
        data.extensionBundleName = extensionBundleName_;
        data.extensionModuleName = extensionModuleName_;
        data.extensionName = extensionName_;
        data.extensionType = extensionType_;
    }

private:
    int32_t extensionPid_ = 0;
    int32_t extensionUid_ = 0;
    std::string extensionBundleName_;
    std::string extensionModuleName_;
    std::string extensionName_;
    AppExecFwk::ExtensionAbilityType extensionType_;
    sptr<IRemoteObject> extensionToken_; // ability token of this extension.
    std::set<sptr<IRemoteObject>> connections_; // remote object of IAbilityConnection
};

ConnectionStateItem::ConnectionStateItem(int32_t callerUid, int32_t callerPid, const std::string &callerName)
    : callerUid_(callerUid), callerPid_(callerPid), callerName_(callerName)
{
}

ConnectionStateItem::~ConnectionStateItem()
{}

std::shared_ptr<ConnectionStateItem> ConnectionStateItem::CreateConnectionStateItem(
    const std::shared_ptr<ConnectionRecord> &record)
{
    if (!record) {
        return nullptr;
    }

    return std::make_shared<ConnectionStateItem>(record->GetCallerUid(),
        record->GetCallerPid(), record->GetCallerName());
}

bool ConnectionStateItem::AddConnection(const std::shared_ptr<ConnectionRecord> &record,
    AbilityRuntime::ConnectionData &data)
{
    if (!record) {
        HILOG_ERROR("invalid connection record.");
        return false;
    }

    auto token = record->GetTargetToken();
    if (!token) {
        HILOG_ERROR("invalid token.");
        return false;
    }

    sptr<IRemoteObject> connectionObj = record->GetConnection();
    if (!connectionObj) {
        HILOG_ERROR("no connection callback for this connect.");
        return false;
    }

    std::shared_ptr<ConnectedExtension> connectedExtension = nullptr;
    auto it = connectionMap_.find(token);
    if (it == connectionMap_.end()) {
        connectedExtension = ConnectedExtension::CreateConnectedExtension(record);
        if (connectedExtension) {
            connectionMap_[token] = connectedExtension;
        }
    } else {
        connectedExtension = it->second;
    }

    if (!connectedExtension) {
        HILOG_ERROR("connectedExtension is invalid");
        return false;
    }

    bool needNotify = connectedExtension->AddConnection(connectionObj);
    if (needNotify) {
        GenerateConnectionData(connectedExtension, data);
    }

    return needNotify;
}

bool ConnectionStateItem::RemoveConnection(const std::shared_ptr<ConnectionRecord> &record,
    AbilityRuntime::ConnectionData &data)
{
    if (!record) {
        HILOG_ERROR("invalid connection record.");
        return false;
    }

    auto token = record->GetTargetToken();
    if (!token) {
        HILOG_ERROR("invalid token.");
        return false;
    }

    sptr<IRemoteObject> connectionObj = record->GetConnection();
    if (!connectionObj) {
        HILOG_ERROR("no connection callback for this connect.");
        return false;
    }

    auto it = connectionMap_.find(token);
    if (it == connectionMap_.end()) {
        HILOG_ERROR("no such connectedExtension.");
        return false;
    }

    auto connectedExtension = it->second;
    if (!connectedExtension) {
        HILOG_ERROR("can not find such connectedExtension");
        return false;
    }

    bool needNotify = connectedExtension->RemoveConnection(connectionObj);
    if (needNotify) {
        connectionMap_.erase(it);
        GenerateConnectionData(connectedExtension, data);
    }

    return needNotify;
}

void ConnectionStateItem::GenerateAllConnectionData(std::vector<AbilityRuntime::ConnectionData> &datas)
{
    AbilityRuntime::ConnectionData data;
    for (auto it = connectionMap_.begin(); it != connectionMap_.end(); ++it) {
        GenerateConnectionData(it->second, data);
        datas.emplace_back(data);
    }
}

void ConnectionStateItem::GenerateConnectionData(
    const std::shared_ptr<ConnectedExtension> &connectedExtension, AbilityRuntime::ConnectionData &data)
{
    if (connectedExtension) {
        connectedExtension->GenerateExtensionInfo(data);
    }
    data.callerUid = callerUid_;
    data.callerPid = callerPid_;
    data.callerName = callerName_;
}
}  // namespace AAFwk
}  // namespace OHOS
