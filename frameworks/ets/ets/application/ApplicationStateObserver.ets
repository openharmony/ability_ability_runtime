/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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
import AppStateData from 'application.AppStateData';
import AbilityStateData from 'application.AbilityStateData';
import processData from 'application.ProcessData';

interface ApplicationStateObserver {

  onForegroundApplicationChanged(appStateData: AppStateData): void;

  onAbilityStateChanged(abilityStateData: AbilityStateData): void;

  onProcessCreated(processData: ProcessData): void;

  onProcessDied(processData: ProcessData): void;

  onProcessStateChanged(processData: ProcessData): void;

  onAppStarted(appStateData: AppStateData): void;

  onAppStopped(appStateData: AppStateData): void;
}

class ApplicationStateObserverImpl implements ApplicationStateObserver {
  onForegroundApplicationChanged(appStateData: AppStateData): void {}

  onAbilityStateChanged(abilityStateData: AbilityStateData): void {}

  onProcessCreated(processData: ProcessData): void {}

  onProcessDied(processData: ProcessData): void {}

  onProcessStateChanged(processData: ProcessData): void {}

  onAppStarted(appStateData: AppStateData): void {}

  onAppStopped(appStateData: AppStateData): void {}
}

export type ProcessData = processData;

export default ApplicationStateObserver;