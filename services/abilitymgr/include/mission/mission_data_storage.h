/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_MISSION_DATA_STORAGE_H
#define OHOS_ABILITY_RUNTIME_MISSION_DATA_STORAGE_H

#include <list>
#include <mutex>
#include <queue>
#include "cpp/mutex.h"

#include "inner_mission_info.h"
#include "mission_snapshot.h"

namespace OHOS {
namespace AAFwk {
constexpr const char* TASK_DATA_FILE_BASE_PATH = "/data/service/el1/public/AbilityManagerService";
constexpr const char* MISSION_DATA_FILE_PATH = "MissionInfo";
constexpr const char* MISSION_JSON_FILE_PREFIX = "mission";
constexpr const char* LOW_RESOLUTION_FLAG = "little";
constexpr const char* JSON_FILE_SUFFIX = ".json";
constexpr const char* JPEG_FILE_SUFFIX = ".jpg";
constexpr const char* FILE_SEPARATOR = "/";
constexpr const char* UNDERLINE_SEPARATOR = "_";
const int32_t SCALE = 2;

class MissionDataStorage : public std::enable_shared_from_this<MissionDataStorage> {
public:
    MissionDataStorage() = default;
    explicit MissionDataStorage(int userId);
    virtual ~MissionDataStorage();

    /**
     * @brief GeT all mission info.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool LoadAllMissionInfo(std::list<InnerMissionInfo> &missionInfoList);

    /**
     * @brief Save the mission data.
     * @param missionInfo Indicates the missionInfo object to be save.
     */
    void SaveMissionInfo(const InnerMissionInfo &missionInfo);

    /**
     * @brief Delete the bundle data corresponding to the mission Id.
     * @param missionId Indicates this mission id.
     */
    void DeleteMissionInfo(int missionId);

    /**
     * @brief Save mission snapshot
     * @param missionId Indicates this mission id.
     * @param missionSnapshot the mission snapshot to save
     */
    void SaveMissionSnapshot(int32_t missionId, const MissionSnapshot& missionSnapshot);

    /**
     * @brief Delete mission snapshot
     * @param missionId Indicates this mission id.
     */
    void DeleteMissionSnapshot(int32_t missionId);

    /**
     * @brief Get the Mission Snapshot object
     * @param missionId id of mission.
     * @param missionSnapshot snapshot of target mission id.
     * @param isLowResolution low resolution.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetMissionSnapshot(int32_t missionId, MissionSnapshot& missionSnapshot, bool isLowResolution);

#ifdef SUPPORT_SCREEN
    /**
     * Get low resoultion pixelmap of source.
     *
     * @param source source pixelmap.
     * @return return reduced pixel map.
     */
    static std::shared_ptr<OHOS::Media::PixelMap> GetReducedPixelMap(
        const std::shared_ptr<OHOS::Media::PixelMap>& source);

    /**
     * @brief Get the Snapshot object
     * @param missionId Indicates this mission id.
     * @return Returns PixelMap of snapshot.
     */
    std::shared_ptr<Media::PixelMap> GetSnapshot(int missionId, bool isLowResolution = false) const;

    /**
     * @brief Get pixel map for specified mission
     * @param missionId The ID of target mission
     * @param isLowResolution Whether to get low resolution version
     * @return Unique pointer to PixelMap object, nullptr if failed
     * @note This is an internal helper function for screen support scenarios
     */
    std::unique_ptr<Media::PixelMap> GetPixelMap(int missionId, bool isLowResolution) const;

    /**
     * @brief Read file content into memory buffer
     * @param filePath Path to the file to be read
     * @param bufferSize Output parameter for buffer size
     * @return Unique pointer to buffer containing file data, nullptr if failed
     * @note Caller is responsible for managing the returned buffer memory
     */
    std::unique_ptr<uint8_t[]> ReadFileToBuffer(const std::string &filePath, size_t &bufferSize) const;
#endif

private:
    /**
     * @brief Get the base directory path for mission data storage
     * @return Full path to the mission data directory
     */
    std::string GetMissionDataDirPath() const;

    /**
     * @brief Get the file path for storing mission data
     * @param missionId The ID of the mission
     * @return Full path to the mission data file
     */
    std::string GetMissionDataFilePath(int missionId);

    /**
     * @brief Get the path for storing mission snapshot
     * @param missionId The ID of the mission
     * @param isLowResolution Whether to get path for low resolution snapshot
     * @return Full path to the snapshot file
     */
    std::string GetMissionSnapshotPath(int32_t missionId, bool isLowResolution) const;

    /**
     * @brief Validate the given file name
     * @param fileName The file name to validate
     * @return true if the file name is valid, false otherwise
     */
    bool CheckFileNameValid(const std::string &fileName);

#ifdef SUPPORT_SCREEN
    template<typename T>
    void WriteToJpeg(const std::string &filePath, T &snapshot) const;

    bool GetCachedSnapshot(int32_t missionId, MissionSnapshot& missionSnapshot);

    bool SaveCachedSnapshot(int32_t missionId, const MissionSnapshot& missionSnapshot);

    bool DeleteCachedSnapshot(int32_t missionId);
    void DeleteMissionSnapshot(int32_t missionId, bool isLowResolution);

    void SaveSnapshotFile(int32_t missionId, const MissionSnapshot& missionSnapshot);

    void SaveSnapshotFile(int32_t missionId, const std::shared_ptr<OHOS::Media::PixelMap>& snapshot,
        bool isPrivate, bool isLowResolution);

    std::map<int32_t, std::shared_ptr<Media::PixelMap>> cachedPixelMap_;
#endif

    int userId_ = 0;
    ffrt::mutex cachedPixelMapMutex_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_MISSION_DATA_STORAGE_H
