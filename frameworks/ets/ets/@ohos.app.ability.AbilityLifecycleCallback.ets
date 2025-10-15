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

import UIAbility from '@ohos.app.ability.UIAbility';
import window from '@ohos.window';

export type OnNewWantFn = (ability: UIAbility) => void;
export type OnAbilityWillBackgroundFn = (ability: UIAbility) => void;
export type OnAbilityWillForegroundFn = (ability: UIAbility) => void;
export type OnAbilityWillCreateFn = (ability: UIAbility) => void;
export type OnWindowStageWillDestroyFn = (ability: UIAbility, windowStage: window.WindowStage) => void;
export type OnAbilityWillDestroyFn = (ability: UIAbility) => void;
export type OnWindowStageRestoreFn = (ability: UIAbility, windowStage: window.WindowStage) => void;
export type OnAbilitySaveStateFn = (ability: UIAbility) => void;
export type OnAbilityWillContinueFn = (ability: UIAbility) => void;
export type OnAbilityWillSaveStateFn = (ability: UIAbility) => void;
export type OnWillNewWantFn = (ability: UIAbility) => void;
export type OnWindowStageWillCreateFn = (ability: UIAbility, windowStage: window.WindowStage) => void;
export type OnWindowStageWillRestoreFn = (ability: UIAbility, windowStage: window.WindowStage) => void;


export default class AbilityLifecycleCallback {
  onAbilityCreate(ability: UIAbility): void {}
  onAbilityForeground(ability: UIAbility): void {}
  onAbilityBackground(ability: UIAbility): void {}
  onAbilityDestroy(ability: UIAbility): void {}
  onWindowStageCreate(ability: UIAbility, windowStage: window.WindowStage): void {}
  onWindowStageDestroy(ability: UIAbility, windowStage: window.WindowStage): void {}
  onAbilityContinue(ability: UIAbility): void {}
  onWindowStageInactive(ability: UIAbility, windowStage: window.WindowStage): void {}
  onWindowStageActive(ability: UIAbility, windowStage: window.WindowStage): void {}

  onNewWant?: OnNewWantFn;
  onAbilityWillBackground?: OnAbilityWillBackgroundFn;
  onAbilityWillForeground?: OnAbilityWillForegroundFn;
  onAbilityWillCreate?: OnAbilityWillCreateFn;
  onWindowStageWillDestroy?: OnWindowStageWillDestroyFn;
  onAbilityWillDestroy?: OnAbilityWillDestroyFn;
  onWindowStageRestore?: OnWindowStageRestoreFn;
  onAbilitySaveState?: OnAbilitySaveStateFn;
  onAbilityWillContinue?: OnAbilityWillContinueFn;
  onAbilityWillSaveState?: OnAbilityWillSaveStateFn;
  onWillNewWant?: OnWillNewWantFn;
  onWindowStageWillCreate?: OnWindowStageWillCreateFn;
  onWindowStageWillRestore?: OnWindowStageWillRestoreFn;
}