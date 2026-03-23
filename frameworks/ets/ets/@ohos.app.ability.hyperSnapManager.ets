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

export default namespace hyperSnapManager {
loadLibraryWithPermissionCheck("hyper_snap_manager_ani.z", "@ohos.app.ability.hyperSnapManager")

export native function nativeSetHyperSnapEnabled(enableFlag: boolean): void;
export function setHyperSnapEnabled(enableFlag: boolean): void {
    hyperSnapManager.nativeSetHyperSnapEnabled(enableFlag);
}

export native function nativeRequestRebuildHyperSnap(): void;
export function requestRebuildHyperSnap(): void {
    hyperSnapManager.nativeRequestRebuildHyperSnap();
}
} // namespace hyperSnapManager