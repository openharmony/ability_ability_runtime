/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "deeplink_reserve/deeplink_reserve_config.h"

#include <fstream>
#include <unistd.h>
#include <regex>

#include "config_policy_utils.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {
namespace {
const std::string CONFIG_PATH = "/etc/ability_runtime/deeplink_reserve_config.json";
const std::string DEFAULT_RESERVE_CONFIG_PATH = "/system/etc/deeplink_reserve_config.json";
const std::string DEEPLINK_RESERVED_URI_NAME = "deepLinkReservedUri";
const std::string BUNDLE_NAME = "bundleName";
const std::string URIS_NAME = "uris";
const std::string SCHEME_NAME = "scheme";
const std::string HOST_NAME = "host";
const std::string PORT_NAME = "port";
const std::string PATH_NAME = "path";
const std::string PATH_START_WITH_NAME = "pathStartWith";
const std::string PATH_REGEX_NAME = "pathRegex";
const std::string TYPE_NAME = "type";
const std::string UTD_NAME = "utd";
const std::string PORT_SEPARATOR = ":";
const std::string SCHEME_SEPARATOR = "://";
const std::string PATH_SEPARATOR = "/";
const std::string PARAM_SEPARATOR = "?";
}

std::string DeepLinkReserveConfig::GetConfigPath()
{
    char buf[MAX_PATH_LEN] = { 0 };
    char *configPath = GetOneCfgFile(CONFIG_PATH.c_str(), buf, MAX_PATH_LEN);
    if (configPath == nullptr || configPath[0] == '\0' || strlen(configPath) > MAX_PATH_LEN) {
        return DEFAULT_RESERVE_CONFIG_PATH;
    }
    return configPath;
}

bool DeepLinkReserveConfig::LoadConfiguration()
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    std::string configPath = GetConfigPath();
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Deeplink reserve config path is: %{public}s", configPath.c_str());
    cJSON *jsonBuf = nullptr;
    if (!ReadFileInfoJson(configPath, jsonBuf)) {
        return false;
    }
    if (jsonBuf == nullptr) {
        return false;
    }
    if (!LoadReservedUriList(jsonBuf)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "load fail");
        cJSON_Delete(jsonBuf);
        return false;
    }
    cJSON_Delete(jsonBuf);
    return true;
}

bool DeepLinkReserveConfig::IsLinkReserved(const std::string &linkString, std::string &bundleName)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    for (auto it = deepLinkReserveUris_.begin(); it != deepLinkReserveUris_.end(); ++it) {
        for (auto &itemUri : it->second) {
            if (IsUriMatched(itemUri, linkString)) {
                TAG_LOGI(AAFwkTag::ABILITYMGR, "link:%{public}s, linkReserved:%{public}s, matched",
                    linkString.c_str(), itemUri.scheme.c_str());
                bundleName = it->first;
                return true;
            }
        }
    }

    return false;
}

static std::string GetOptParamUri(const std::string &linkString)
{
    std::size_t pos = linkString.rfind(PARAM_SEPARATOR);
    if (pos == std::string::npos) {
        return linkString;
    }
    return linkString.substr(0, pos);
}

static bool StartsWith(const std::string &sourceString, const std::string &targetPrefix)
{
    return sourceString.rfind(targetPrefix, 0) == 0;
}


bool DeepLinkReserveConfig::IsUriMatched(const ReserveUri &reservedUri, const std::string &link)
{
    if (reservedUri.scheme.empty()) {
        return false;
    }
    if (reservedUri.host.empty()) {
        // config uri is : scheme
        // belows are param uri matched conditions:
        // 1.scheme
        // 2.scheme:
        // 3.scheme:/
        // 4.scheme://
        return link == reservedUri.scheme || StartsWith(link, reservedUri.scheme + PORT_SEPARATOR);
    }
    std::string optParamUri = GetOptParamUri(link);
    std::string reservedUriString;
    reservedUriString.append(reservedUri.scheme).append(SCHEME_SEPARATOR).append(reservedUri.host);
    if (!reservedUri.port.empty()) {
        reservedUriString.append(PORT_SEPARATOR).append(reservedUri.port);
    }
    if (reservedUri.path.empty() && reservedUri.pathStartWith.empty() && reservedUri.pathRegex.empty()) {
        // with port, config uri is : scheme://host:port
        // belows are param uri matched conditions:
        // 1.scheme://host:port
        // 2.scheme://host:port/path

        // without port, config uri is : scheme://host
        // belows are param uri matched conditions:
        // 1.scheme://host
        // 2.scheme://host/path
        // 3.scheme://host:port     scheme://host:port/path
        bool ret = (optParamUri == reservedUriString || StartsWith(optParamUri, reservedUriString + PATH_SEPARATOR));
        if (reservedUri.port.empty()) {
            ret = ret || StartsWith(optParamUri, reservedUriString + PORT_SEPARATOR);
        }
        return ret;
    }
    reservedUriString.append(PATH_SEPARATOR);
    // if one of path, pathStartWith, pathRegex match, then match
    if (!reservedUri.path.empty()) {
        // path match
        std::string pathUri(reservedUriString);
        pathUri.append(reservedUri.path);
        if (optParamUri == pathUri) {
            return true;
        }
    }
    if (!reservedUri.pathStartWith.empty()) {
        // pathStartWith match
        std::string pathStartWithUri(reservedUriString);
        pathStartWithUri.append(reservedUri.pathStartWith);
        if (StartsWith(optParamUri, pathStartWithUri)) {
            return true;
        }
    }
    if (!reservedUri.pathRegex.empty()) {
        // pathRegex match
        std::string pathRegexUri(reservedUriString);
        pathRegexUri.append(reservedUri.pathRegex);
        try {
            std::regex regex(pathRegexUri);
            if (regex_match(optParamUri, regex)) {
                return true;
            }
        } catch(...) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "regex error");
        }
    }
    return false;
}

void DeepLinkReserveConfig::LoadReservedUrilItem(const cJSON *jsonUriObject, std::vector<ReserveUri> &uriList)
{
    ReserveUri reserveUri;
    cJSON *schemeNameItem = cJSON_GetObjectItem(jsonUriObject, SCHEME_NAME.c_str());
    if (schemeNameItem != nullptr && cJSON_IsString(schemeNameItem)) {
        std::string schemeName = schemeNameItem->valuestring;
        reserveUri.scheme = schemeName;
        TAG_LOGD(AAFwkTag::ABILITYMGR, "scheme:%{public}s", reserveUri.scheme.c_str());
    }
    cJSON *hostNameItem = cJSON_GetObjectItem(jsonUriObject, HOST_NAME.c_str());
    if (hostNameItem != nullptr && cJSON_IsString(hostNameItem)) {
        std::string hostName = hostNameItem->valuestring;
        reserveUri.host = hostName;
        TAG_LOGD(AAFwkTag::ABILITYMGR, "host:%{public}s", reserveUri.host.c_str());
    }
    cJSON *portNameItem = cJSON_GetObjectItem(jsonUriObject, PORT_NAME.c_str());
    if (portNameItem != nullptr && cJSON_IsString(portNameItem)) {
        std::string portName = portNameItem->valuestring;
        reserveUri.port = portName;
        TAG_LOGD(AAFwkTag::ABILITYMGR, "port:%{public}s", reserveUri.port.c_str());
    }
    cJSON *pathNameItem = cJSON_GetObjectItem(jsonUriObject, PATH_NAME.c_str());
    if (pathNameItem != nullptr && cJSON_IsString(pathNameItem)) {
        std::string pathName = pathNameItem->valuestring;
        reserveUri.path = PATH_NAME;
        TAG_LOGD(AAFwkTag::ABILITYMGR, "path:%{public}s", reserveUri.path.c_str());
    }
    cJSON *pathStartWithItem = cJSON_GetObjectItem(jsonUriObject, PATH_START_WITH_NAME.c_str());
    if (pathStartWithItem != nullptr && cJSON_IsString(pathStartWithItem)) {
        std::string pathStartWith = pathStartWithItem->valuestring;
        reserveUri.pathStartWith = pathStartWith;
        TAG_LOGD(AAFwkTag::ABILITYMGR, "pathStartWith:%{public}s", reserveUri.pathStartWith.c_str());
    }
    cJSON *pathRegexNameItem = cJSON_GetObjectItem(jsonUriObject, PATH_REGEX_NAME.c_str());
    if (pathRegexNameItem != nullptr && cJSON_IsString(pathRegexNameItem)) {
        std::string pathRegexName = pathRegexNameItem->valuestring;
        reserveUri.pathRegex = pathRegexName;
        TAG_LOGD(AAFwkTag::ABILITYMGR, "pathRegex:%{public}s", reserveUri.pathRegex.c_str());
    }
    cJSON *typeNameItem = cJSON_GetObjectItem(jsonUriObject, TYPE_NAME.c_str());
    if (typeNameItem != nullptr && cJSON_IsString(typeNameItem)) {
        std::string typeName = typeNameItem->valuestring;
        reserveUri.type = typeName;
        TAG_LOGD(AAFwkTag::ABILITYMGR, "type:%{public}s", reserveUri.type.c_str());
    }
    cJSON *utdNameItem = cJSON_GetObjectItem(jsonUriObject, UTD_NAME.c_str());
    if (utdNameItem != nullptr && cJSON_IsString(utdNameItem)) {
        std::string utdName = utdNameItem->valuestring;
        reserveUri.utd = utdName;
        TAG_LOGD(AAFwkTag::ABILITYMGR, "utd:%{public}s", reserveUri.utd.c_str());
    }

    uriList.emplace_back(reserveUri);
}

bool DeepLinkReserveConfig::LoadReservedUriList(const cJSON *object)
{
    cJSON *uriNameItems = cJSON_GetObjectItem(object, DEEPLINK_RESERVED_URI_NAME.c_str());
    if (uriNameItems == nullptr || !cJSON_IsArray(uriNameItems)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "uri config absent");
        return false;
    }
    int size = cJSON_GetArraySize(uriNameItems);
    for (int i = 0; i < size; i++) {
        cJSON *uriNameItem = cJSON_GetArrayItem(uriNameItems, i);
        if (uriNameItem == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "item is null");
            return false;
        }
        cJSON *bundleNameItem = cJSON_GetObjectItem(uriNameItem, BUNDLE_NAME.c_str());
        if (bundleNameItem == nullptr || !cJSON_IsString(bundleNameItem)) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "reserve bundleName fail");
            return false;
        }
        cJSON *urisNameItems = cJSON_GetObjectItem(uriNameItem, URIS_NAME.c_str());
        if (urisNameItems == nullptr || !cJSON_IsArray(urisNameItems)) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "reserve uris fail");
            return false;
        }
        std::string bundleName = bundleNameItem->valuestring;
        std::vector<ReserveUri> uriList;
        int uriSize = cJSON_GetArraySize(urisNameItems);
        for (int j = 0; j < uriSize; j++) {
            cJSON *urisNameItem = cJSON_GetArrayItem(urisNameItems, j);
            LoadReservedUrilItem(urisNameItem, uriList);
        }
        deepLinkReserveUris_.insert(std::make_pair(bundleName, uriList));
    }
    return true;
}

bool DeepLinkReserveConfig::ReadFileInfoJson(const std::string &filePath, cJSON *&jsonBuf)
{
    if (access(filePath.c_str(), F_OK) != 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "reserve config absent");
        return false;
    }

    if (filePath.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "file path empty");
        return false;
    }

    char path[PATH_MAX] = {0};
    if (realpath(filePath.c_str(), path) == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "realpath error:%{public}d", errno);
        return false;
    }

    std::fstream in;
    char errBuf[256];
    errBuf[0] = '\0';
    in.open(path, std::ios_base::in);
    if (!in.is_open()) {
        strerror_r(errno, errBuf, sizeof(errBuf));
        TAG_LOGE(AAFwkTag::ABILITYMGR, "open error:%{public}s", errBuf);
        return false;
    }

    in.seekg(0, std::ios::end);
    int64_t size = in.tellg();
    if (size <= 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "file empty");
        in.close();
        return false;
    }

    in.seekg(0, std::ios::beg);
    std::string fileContent((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    jsonBuf = cJSON_Parse(fileContent.c_str());
    if (jsonBuf == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "bad profile file");
        return false;
    }

    return true;
}
}
}